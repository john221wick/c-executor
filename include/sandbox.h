/*
 * sandbox.h — All sandbox primitives: RAII guards and child-side setup.
 *
 * Guards:
 *   CgroupGuard    — creates a cgroup v2 subtree, writes limits, cleans up.
 *                    Movable (factory returns by value; path via std::exchange).
 *   NamespaceGuard — wraps the child PID produced by clone(2). NonMovable
 *                    because the PID is under active ptrace.
 *   LandlockGuard  — builds a Landlock ruleset fd and enforces it.
 *                    Movable (fd via std::exchange).
 *
 * Free functions (called INSIDE the child after clone, before execve):
 *   clone_flags_for()     — compute clone(2) flags from environment config.
 *   build_landlock_rules()— produce the filesystem whitelist for an environment.
 *   setup_child_rootfs()  — overlay mount + pivot_root; host fs disappears.
 *   install_seccomp()     — load BPF filter via libseccomp.
 */
#pragma once

#include "common.h"
#include "environment.h"
#include <expected>
#include <string>
#include <vector>
#include <sys/types.h>

/* ── Landlock rule ──────────────────────────────────────────────────────── */

struct LandlockRule {
    std::string path;
    bool        read    = false;
    bool        write   = false;
    bool        execute = false;
};

/* ── CgroupGuard ────────────────────────────────────────────────────────────
 *
 * Creates /sys/fs/cgroup/executor/{name}, writes memory/cpu/pid limits,
 * and rmdir's the cgroup in the destructor.
 */
class CgroupGuard : public NonCopyable {
public:
    static std::expected<CgroupGuard, int> create(const std::string&    name,
                                                   const ResourceLimits& limits);

    /* Write pid to cgroup.procs, attaching the process to this cgroup. */
    std::expected<void, int> attach(pid_t pid) const;

    uint64_t peak_memory_bytes() const; /* reads memory.peak */
    uint64_t cpu_usage_us() const;      /* reads cpu.stat → usage_usec */

    ~CgroupGuard();
    CgroupGuard(CgroupGuard&& o) noexcept;
    CgroupGuard& operator=(CgroupGuard&& o) noexcept;

private:
    explicit CgroupGuard(std::string path) : path_(std::move(path)) {}
    std::string path_; /* empty = moved-from or not yet created */
};

/* ── NamespaceGuard ─────────────────────────────────────────────────────────
 *
 * Wraps the child PID created by clone(2). Kills and reaps in the destructor
 * if wait() was never called. NonMovable: the PID is under active ptrace and
 * cannot be handed off to another owner.
 */
class NamespaceGuard : public NonCopyable, public NonMovable {
public:
    /* child_fn: int fn(void* arg). Clone stack is thread_local inside create(). */
    static std::expected<NamespaceGuard, int> create(int (*child_fn)(void*),
                                                      void* arg,
                                                      int   clone_flags);

    pid_t child_pid() const { return pid_; }

    /* Write uid_map + gid_map so the child's UID 0 maps to the caller's UID.
     * Must be called from the parent after clone() and before SIGCONT. */
    std::expected<void, int> write_uid_gid_mappings() const;

    /* Blocking waitpid. Returns wstatus. */
    std::expected<int, int> wait();

    /* SIGKILL + waitpid. Safe to call multiple times. */
    void kill();

    ~NamespaceGuard();

private:
    explicit NamespaceGuard(pid_t pid) : pid_(pid) {}
    pid_t pid_    = -1;
    bool  reaped_ = false;
};

/* ── LandlockGuard ──────────────────────────────────────────────────────────
 *
 * Creates a Landlock ruleset fd, adds one rule per path, then enforces it
 * on the calling thread via landlock_restrict_self. After enforce() the fd
 * is closed and the guard is inert.
 */
class LandlockGuard : public NonCopyable {
public:
    static std::expected<LandlockGuard, int> create(
        const std::vector<LandlockRule>& rules);

    /* prctl(PR_SET_NO_NEW_PRIVS) then landlock_restrict_self. Closes fd. */
    std::expected<void, int> enforce();

    ~LandlockGuard();
    LandlockGuard(LandlockGuard&& o) noexcept;
    LandlockGuard& operator=(LandlockGuard&& o) noexcept;

private:
    explicit LandlockGuard(int fd) : fd_(fd) {}
    int fd_ = -1; /* -1 = moved-from or already enforced */
};

/* ── Free functions ─────────────────────────────────────────────────────── */

/* Always includes CLONE_NEWPID|NEWNS|NEWUSER|NEWUTS|NEWIPC|SIGCHLD.
 * Adds CLONE_NEWNET when env.network is false. */
int clone_flags_for(const Environment& env);

/* Build the Landlock whitelist for this environment + work directory.
 * Always allows access to work_dir, /tmp, standard lib paths, /dev, /proc.
 * Adds /usr/local/cuda when env.gpu is true. */
std::vector<LandlockRule> build_landlock_rules(const Environment& env,
                                                const std::string& work_dir);

/* Called INSIDE the child after clone(CLONE_NEWNS), before execve.
 * Mounts an overlay over env.rootfs_path with a tmpfs upper layer,
 * bind-mounts work_dir into the overlay, then pivot_root's into it.
 * Returns 0 on success, -1 on error (errno set). */
int setup_child_rootfs(const Environment& env, const std::string& work_dir);

/* Load seccomp-BPF filter via libseccomp. Always kills ptrace/mount/reboot.
 * Denies network syscalls when env.network is false.
 * Called inside child before execve. */
std::expected<void, int> install_seccomp(const Environment& env);
