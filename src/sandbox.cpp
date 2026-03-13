/*
 * sandbox.cpp — Cgroup, namespace, landlock, rootfs, and seccomp primitives.
 *
 * Cgroup v2:  writes to /sys/fs/cgroup/executor/{name}/ for limits and stats.
 * Namespaces: clone(2) with NEWPID|NEWNS|NEWUSER|NEWUTS|NEWIPC; optionally
 *             NEWNET. uid/gid maps let the child see itself as root while the
 *             host sees an unprivileged UID.
 * Landlock:   raw syscalls (no glibc wrapper in older toolchains). ABI v1.
 * Rootfs:     overlay over a pre-built read-only rootfs + tmpfs upper layer,
 *             then pivot_root so the host filesystem becomes inaccessible.
 * Seccomp:    libseccomp with ALLOW default; hard-kills dangerous syscalls;
 *             denies network calls when env.network is false.
 */
#include "sandbox.h"
#include "logger.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <seccomp.h>

/* ── Landlock syscall wrappers (ABI v1) ─────────────────────────────────── */

#ifndef __NR_landlock_create_ruleset
#  define __NR_landlock_create_ruleset 444
#  define __NR_landlock_add_rule       445
#  define __NR_landlock_restrict_self  446
#endif

/* Inline structs in case kernel headers are older than 5.13. */
struct ll_ruleset_attr { uint64_t handled_access_fs; };
struct ll_path_beneath { uint64_t allowed_access; int32_t parent_fd; };

#define LANDLOCK_ACCESS_FS_EXECUTE      (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE   (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR     (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR   (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE  (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR    (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR     (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG     (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SYM     (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK    (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO    (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK   (1ULL << 12)
#define LANDLOCK_ACCESS_FS_MAKE_IPC     (1ULL << 13)

static inline int ll_create_ruleset(const ll_ruleset_attr* attr, size_t sz) {
    return static_cast<int>(syscall(__NR_landlock_create_ruleset, attr, sz, 0));
}
static inline int ll_add_rule(int fd, uint32_t type, const void* attr, size_t sz) {
    return static_cast<int>(syscall(__NR_landlock_add_rule, fd, type, attr, sz, 0));
}
static inline int ll_restrict_self(int fd) {
    return static_cast<int>(syscall(__NR_landlock_restrict_self, fd, 0));
}

/* ── Internal file helpers ──────────────────────────────────────────────── */

static bool write_file(const std::string& path, const std::string& content) {
    int fd = open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t written = write(fd, content.data(), content.size());
    close(fd);
    return written == static_cast<ssize_t>(content.size());
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    return f ? std::string(std::istreambuf_iterator<char>(f),
                            std::istreambuf_iterator<char>())
             : std::string{};
}

/* ── CgroupGuard ────────────────────────────────────────────────────────── */

std::expected<CgroupGuard, int> CgroupGuard::create(const std::string& name,
                                                      const ResourceLimits& limits) {
    std::string path = std::string(CGROUP_ROOT) + "/" + name;

    if (mkdir(path.c_str(), 0755) < 0 && errno != EEXIST)
        return std::unexpected(errno);

    /* memory.max in bytes */
    if (!write_file(path + "/memory.max",
                    std::to_string(limits.memory_mb * 1024 * 1024)))
        return std::unexpected(errno);

    /* Disable swap. */
    write_file(path + "/memory.swap.max", "0");

    /* cpu.max: quota microseconds per 1-second period */
    if (!write_file(path + "/cpu.max",
                    std::to_string(limits.cpu_time_ms * 1000) + " 1000000"))
        return std::unexpected(errno);

    /* pids.max */
    if (!write_file(path + "/pids.max", std::to_string(limits.max_pids)))
        return std::unexpected(errno);

    return CgroupGuard{path};
}

std::expected<void, int> CgroupGuard::attach(pid_t pid) const {
    if (!write_file(path_ + "/cgroup.procs", std::to_string(pid)))
        return std::unexpected(errno);
    return {};
}

uint64_t CgroupGuard::peak_memory_bytes() const {
    std::string val = read_file(path_ + "/memory.peak");
    if (val.empty()) return 0;
    return std::stoull(val);
}

uint64_t CgroupGuard::cpu_usage_us() const {
    /* cpu.stat has "usage_usec NNN\n..." among other lines. */
    std::string content = read_file(path_ + "/cpu.stat");
    std::istringstream ss(content);
    std::string key;
    uint64_t val = 0;
    while (ss >> key >> val) {
        if (key == "usage_usec") return val;
    }
    return 0;
}

CgroupGuard::~CgroupGuard() {
    if (!path_.empty()) rmdir(path_.c_str());
}

CgroupGuard::CgroupGuard(CgroupGuard&& o) noexcept
    : NonCopyable(std::move(o))
    , path_(std::exchange(o.path_, {}))
{}

CgroupGuard& CgroupGuard::operator=(CgroupGuard&& o) noexcept {
    if (this != &o) {
        if (!path_.empty()) rmdir(path_.c_str());
        path_ = std::exchange(o.path_, {});
    }
    return *this;
}

/* ── NamespaceGuard ─────────────────────────────────────────────────────── */

/* Thread-local stack for clone(2). One child runs per thread at a time. */
static thread_local char clone_stack[CLONE_STACK_SIZE];

std::expected<NamespaceGuard, int> NamespaceGuard::create(
        int (*child_fn)(void*), void* arg, int clone_flags)
{
    /* clone() needs the top of the stack. */
    char* stack_top = clone_stack + CLONE_STACK_SIZE;

    pid_t pid = clone(child_fn, stack_top, clone_flags, arg);
    if (pid < 0) return std::unexpected(errno);

    return NamespaceGuard{pid};
}

std::expected<void, int> NamespaceGuard::write_uid_gid_mappings() const {
    /* Deny setgroups first (required before writing gid_map in user namespaces). */
    std::string base = "/proc/" + std::to_string(pid_);

    if (!write_file(base + "/setgroups", "deny"))
        return std::unexpected(errno);

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (!write_file(base + "/uid_map", "0 " + std::to_string(uid) + " 1"))
        return std::unexpected(errno);

    if (!write_file(base + "/gid_map", "0 " + std::to_string(gid) + " 1"))
        return std::unexpected(errno);

    return {};
}

std::expected<int, int> NamespaceGuard::wait() {
    int wstatus = 0;
    if (waitpid(pid_, &wstatus, 0) < 0) return std::unexpected(errno);
    reaped_ = true;
    return wstatus;
}

void NamespaceGuard::kill() {
    if (!reaped_ && pid_ > 0) {
        ::kill(pid_, SIGKILL);
        waitpid(pid_, nullptr, 0);
        reaped_ = true;
    }
}

NamespaceGuard::~NamespaceGuard() {
    kill();
}

/* ── LandlockGuard ──────────────────────────────────────────────────────── */

std::expected<LandlockGuard, int> LandlockGuard::create(
        const std::vector<LandlockRule>& rules)
{
    /* Claim the full ABI v1 access set. */
    uint64_t all_access =
        LANDLOCK_ACCESS_FS_EXECUTE     |
        LANDLOCK_ACCESS_FS_WRITE_FILE  |
        LANDLOCK_ACCESS_FS_READ_FILE   |
        LANDLOCK_ACCESS_FS_READ_DIR    |
        LANDLOCK_ACCESS_FS_REMOVE_DIR  |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR   |
        LANDLOCK_ACCESS_FS_MAKE_DIR    |
        LANDLOCK_ACCESS_FS_MAKE_REG    |
        LANDLOCK_ACCESS_FS_MAKE_SYM    |
        LANDLOCK_ACCESS_FS_MAKE_SOCK   |
        LANDLOCK_ACCESS_FS_MAKE_FIFO   |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK  |
        LANDLOCK_ACCESS_FS_MAKE_IPC;

    ll_ruleset_attr attr{ .handled_access_fs = all_access };
    int ruleset_fd = ll_create_ruleset(&attr, sizeof(attr));
    if (ruleset_fd < 0) return std::unexpected(errno);

    for (const auto& rule : rules) {
        int path_fd = open(rule.path.c_str(), O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            close(ruleset_fd);
            return std::unexpected(errno);
        }

        uint64_t allowed = 0;
        if (rule.read)    allowed |= LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
        if (rule.write)   allowed |= LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_FILE
                                   | LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_MAKE_REG
                                   | LANDLOCK_ACCESS_FS_MAKE_DIR;
        if (rule.execute) allowed |= LANDLOCK_ACCESS_FS_EXECUTE;

        ll_path_beneath beneath{ .allowed_access = allowed, .parent_fd = path_fd };
        int rc = ll_add_rule(ruleset_fd, 1 /* LANDLOCK_RULE_PATH_BENEATH */,
                             &beneath, sizeof(beneath));
        close(path_fd);
        if (rc < 0) {
            close(ruleset_fd);
            return std::unexpected(errno);
        }
    }

    return LandlockGuard{ruleset_fd};
}

std::expected<void, int> LandlockGuard::enforce() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return std::unexpected(errno);

    if (ll_restrict_self(fd_) < 0)
        return std::unexpected(errno);

    close(fd_);
    fd_ = -1;
    return {};
}

LandlockGuard::~LandlockGuard() {
    if (fd_ >= 0) close(fd_);
}

LandlockGuard::LandlockGuard(LandlockGuard&& o) noexcept
    : NonCopyable(std::move(o))
    , fd_(std::exchange(o.fd_, -1))
{}

LandlockGuard& LandlockGuard::operator=(LandlockGuard&& o) noexcept {
    if (this != &o) {
        if (fd_ >= 0) close(fd_);
        fd_ = std::exchange(o.fd_, -1);
    }
    return *this;
}

/* ── clone_flags_for ────────────────────────────────────────────────────── */

int clone_flags_for(const Environment& env) {
    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER |
                CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD;
    if (!env.network) flags |= CLONE_NEWNET;
    return flags;
}

/* ── build_landlock_rules ───────────────────────────────────────────────── */

std::vector<LandlockRule> build_landlock_rules(const Environment& env,
                                                const std::string& work_dir) {
    std::vector<LandlockRule> rules;

    auto add = [&](const char* path, bool r, bool w, bool x) {
        rules.push_back(LandlockRule{path, r, w, x});
    };

    add(work_dir.c_str(), true,  true,  true);
    add("/tmp",           true,  true,  false);
    add("/usr/lib",       true,  false, true);
    add("/lib",           true,  false, true);
    add("/lib64",         true,  false, true);
    add("/usr/lib64",     true,  false, true);
    add("/dev",           true,  true,  false);
    add("/proc",          true,  false, false);
    add("/etc/ld.so.cache", true, false, false);
    add("/usr/share/zoneinfo", true, false, false);

    if (env.gpu) {
        add("/usr/local/cuda", true, false, true);
    }

    return rules;
}

/* ── setup_child_rootfs ─────────────────────────────────────────────────── */

int setup_child_rootfs(const Environment& env, const std::string& work_dir) {
    /* Make everything private so our mounts don't propagate to the host. */
    if (mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0)
        return -1;

    /* Create per-sandbox directories: upper (writable layer) and
     * overlay_work (kernel bookkeeping) under a tmpfs. */
    std::string sandbox_dir = std::string(SANDBOX_ROOT) + "/rootfs_" +
                               std::to_string(getpid());
    mkdir(sandbox_dir.c_str(), 0755);

    std::string upper   = sandbox_dir + "/upper";
    std::string ovlwork = sandbox_dir + "/ovlwork";
    std::string merged  = sandbox_dir + "/merged";

    mkdir(upper.c_str(),   0755);
    mkdir(ovlwork.c_str(), 0755);
    mkdir(merged.c_str(),  0755);

    /* Mount a tmpfs so upper/ovlwork are in-memory. */
    if (mount("tmpfs", sandbox_dir.c_str(), "tmpfs", 0, "size=64m") < 0)
        return -1;

    /* Re-create dirs inside the tmpfs. */
    mkdir(upper.c_str(),   0755);
    mkdir(ovlwork.c_str(), 0755);
    mkdir(merged.c_str(),  0755);

    /* Overlay: lowerdir is the read-only pre-built rootfs. */
    std::string opts = "lowerdir=" + env.rootfs_path +
                       ",upperdir=" + upper +
                       ",workdir="  + ovlwork;

    if (mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()) < 0)
        return -1;

    /* Bind-mount work_dir into the overlay so the binary is accessible. */
    std::string mnt_work = merged + "/work";
    mkdir(mnt_work.c_str(), 0755);
    if (mount(work_dir.c_str(), mnt_work.c_str(), nullptr,
              MS_BIND | MS_REC, nullptr) < 0)
        return -1;

    /* Standard mounts inside the new root. */
    std::string proc_dir = merged + "/proc";
    std::string tmp_dir  = merged + "/tmp";
    mkdir(proc_dir.c_str(), 0755);
    mkdir(tmp_dir.c_str(),  0755);

    if (mount("proc", proc_dir.c_str(), "proc", 0, nullptr) < 0)
        return -1;

    if (mount("tmpfs", tmp_dir.c_str(), "tmpfs", 0, "size=64m") < 0)
        return -1;

    /* Bind /dev/null and /dev/urandom. */
    auto bind_dev = [&](const char* dev) {
        std::string dst = merged + dev;
        /* Create the target file if it doesn't exist in the rootfs. */
        int fd = open(dst.c_str(), O_CREAT | O_WRONLY, 0666);
        if (fd >= 0) close(fd);
        mount(dev, dst.c_str(), nullptr, MS_BIND, nullptr);
    };
    bind_dev("/dev/null");
    bind_dev("/dev/urandom");
    bind_dev("/dev/zero");

    if (env.gpu) {
        bind_dev("/dev/nvidia0");
        bind_dev("/dev/nvidiactl");
        bind_dev("/dev/nvidia-uvm");
    }

    /* pivot_root: swap the root to merged, stash old root at merged/old_root. */
    std::string old_root = merged + "/old_root";
    mkdir(old_root.c_str(), 0755);

    if (syscall(SYS_pivot_root, merged.c_str(), old_root.c_str()) < 0)
        return -1;

    if (chdir("/") < 0) return -1;

    /* Unmount the old root so the host filesystem is completely gone. */
    if (umount2("/old_root", MNT_DETACH) < 0) return -1;
    rmdir("/old_root");

    return 0;
}

/* ── install_seccomp ────────────────────────────────────────────────────── */

std::expected<void, int> install_seccomp(const Environment& env) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return std::unexpected(errno);

    /* Helper: add a rule, return error on failure. */
    auto deny_kill = [&](int syscall_nr) {
        seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_nr, 0);
    };
    auto deny_eperm = [&](int syscall_nr) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_nr, 0);
    };

    /* Always kill these — they modify global kernel state. */
    deny_kill(SCMP_SYS(ptrace));
    deny_kill(SCMP_SYS(mount));
    deny_kill(SCMP_SYS(umount2));
    deny_kill(SCMP_SYS(reboot));
    deny_kill(SCMP_SYS(kexec_load));
    deny_kill(SCMP_SYS(init_module));
    deny_kill(SCMP_SYS(finit_module));
    deny_kill(SCMP_SYS(swapon));
    deny_kill(SCMP_SYS(swapoff));
    deny_kill(SCMP_SYS(settimeofday));
    deny_kill(SCMP_SYS(clock_settime));

    if (!env.network) {
        deny_eperm(SCMP_SYS(socket));
        deny_eperm(SCMP_SYS(connect));
        deny_eperm(SCMP_SYS(bind));
        deny_eperm(SCMP_SYS(listen));
        deny_eperm(SCMP_SYS(accept));
        deny_eperm(SCMP_SYS(accept4));
        deny_eperm(SCMP_SYS(sendto));
        deny_eperm(SCMP_SYS(recvfrom));
        deny_eperm(SCMP_SYS(sendmsg));
        deny_eperm(SCMP_SYS(recvmsg));
    }

    /* GPU environments need ioctl for the nvidia driver; others don't strictly
     * need it blocked but it's safe to leave allowed (ptrace handles abuse). */

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);

    if (rc < 0) return std::unexpected(-rc);
    return {};
}
