/*
 * tracer.cpp — Syscall name table, trace loop, and policy implementation.
 *
 * Syscall table: a flat array of 512 const char* indexed by syscall number.
 * Populated with the standard x86_64 Linux ABI; unmapped slots are "unknown".
 *
 * Trace loop (PtraceTracer::run):
 *   Waits for the child's initial SIGSTOP, sets PTRACE options, then
 *   enters a wait loop. On each syscall stop it alternates entry/exit state.
 *   On entry: builds a SyscallEvent, consults TracerPolicy.
 *     ALLOW      → continue
 *     DENY_EPERM → overwrite orig_rax with -1 so the kernel treats it as
 *                  an invalid syscall, then inject EPERM on exit
 *     KILL       → SIGKILL child, break loop
 *   On exit: completes the event, adds to record.
 */
#include "tracer.h"
#include "logger.h"
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <signal.h>

/* ── Clock ──────────────────────────────────────────────────────────────── */

uint64_t Clock::now_ns() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL
           + static_cast<uint64_t>(ts.tv_nsec);
}

namespace {

constexpr long kPtraceOptions =
    PTRACE_O_TRACESYSGOOD |
    PTRACE_O_EXITKILL     |
    PTRACE_O_TRACECLONE   |
    PTRACE_O_TRACEFORK    |
    PTRACE_O_TRACEVFORK;

struct ThreadTraceState {
    bool         in_syscall = false;
    SyscallEvent pending_event{};
};

} // namespace

/* ── Syscall name table ─────────────────────────────────────────────────── */

static const char* const SYSCALL_NAMES[512] = {
    /* 0-9 */
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    "lseek", "mmap",
    /* 10-19 */
    "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv",
    /* 20-29 */
    "writev", "access", "pipe", "select", "sched_yield", "mremap",
    "msync", "mincore", "madvise", "shmget",
    /* 30-39 */
    "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer",
    "alarm", "setitimer", "getpid",
    /* 40-49 */
    "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "shutdown", "bind",
    /* 50-59 */
    "listen", "getsockname", "getpeername", "socketpair", "setsockopt",
    "getsockopt", "clone", "fork", "vfork", "execve",
    /* 60-69 */
    "exit", "wait4", "kill", "uname", "semget", "semop", "semctl",
    "shmdt", "msgget", "msgsnd",
    /* 70-79 */
    "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
    "truncate", "ftruncate", "getdents", "getcwd",
    /* 80-89 */
    "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link",
    "unlink", "symlink", "readlink",
    /* 90-99 */
    "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
    "gettimeofday", "getrlimit", "getrusage", "sysinfo",
    /* 100-109 */
    "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid",
    "geteuid", "getegid", "setpgid",
    /* 110-119 */
    "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups",
    "setgroups", "setresuid", "getresuid", "setresgid",
    /* 120-129 */
    "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget",
    "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
    /* 130-139 */
    "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib",
    "personality", "ustat", "statfs", "fstatfs", "sysfs",
    /* 140-149 */
    "getpriority", "setpriority", "sched_setparam", "sched_getparam",
    "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
    "sched_get_priority_min", "sched_rr_get_interval", "mlock",
    /* 150-159 */
    "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
    "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
    /* 160-169 */
    "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount",
    "umount2", "swapon", "swapoff", "reboot",
    /* 170-179 */
    "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
    "init_module", "delete_module", "get_kernel_syms", "query_module",
    "quotactl",
    /* 180-189 */
    "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall",
    "security", "gettid", "readahead", "setxattr", "lsetxattr",
    /* 190-199 */
    "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
    "llistxattr", "flistxattr", "removexattr", "lremovexattr",
    "fremovexattr",
    /* 200-209 */
    "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity",
    "set_thread_area", "io_setup", "io_destroy", "io_getevents",
    "io_submit",
    /* 210-219 */
    "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
    "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64",
    "set_tid_address", "restart_syscall",
    /* 220-229 */
    "semtimedop", "fadvise64", "timer_create", "timer_settime",
    "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
    "clock_gettime", "clock_getres",
    /* 230-239 */
    "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl",
    "tgkill", "utimes", "vserver", "mbind", "set_mempolicy",
    "get_mempolicy",
    /* 240-249 */
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
    "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key",
    "request_key",
    /* 250-259 */
    "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
    "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
    /* 260-269 */
    "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
    "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
    /* 270-279 */
    "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list",
    "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
    /* 280-289 */
    "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd",
    "fallocate", "timerfd_settime", "timerfd_gettime", "accept4",
    "signalfd4",
    /* 290-299 */
    "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1",
    "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
    "recvmmsg",
    /* 300-309 */
    "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at",
    "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg",
    "setns", "getcpu",
    /* 310-319 */
    "process_vm_readv", "process_vm_writev", "kcmp", "finit_module",
    "sched_setattr", "sched_getattr", "renameat2", "seccomp",
    "getrandom", "memfd_create",
    /* 320-329 */
    "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier",
    "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect",
    /* 330-339 */
    "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq",
    nullptr, nullptr, nullptr, nullptr, nullptr,
    /* 340-349 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 350-359 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 360-369 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 370-379 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 380-389 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 390-399 */
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr,
    /* 400-409 */
    "pidfd_send_signal", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig",
    "fsmount", "fspick",
    /* 410-419 */
    "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd",
    "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr",
    "quotactl_fd",
    /* 420-429 */
    "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
    "memfd_secret", "process_mrelease", "futex_waitv", "set_mempolicy_home_node",
    "cachestat", "fchmodat2", "map_shadow_stack",
    /* 430-431 */
    "futex_wake", "futex_requeue",
    /* pad rest to 512 */
};

std::string_view syscall_name(long nr) {
    if (nr < 0 || nr >= 512) return "unknown";
    const char* n = SYSCALL_NAMES[nr];
    return n ? std::string_view{n} : std::string_view{"unknown"};
}

/* ── SyscallArgs ────────────────────────────────────────────────────────── */

SyscallArgs SyscallArgs::from_entry(const user_regs_struct& r) {
    return SyscallArgs{
        .number       = static_cast<long>(r.orig_rax),
        .args         = { static_cast<long>(r.rdi), static_cast<long>(r.rsi),
                          static_cast<long>(r.rdx), static_cast<long>(r.r10),
                          static_cast<long>(r.r8),  static_cast<long>(r.r9) },
        .return_value = 0,
    };
}

long SyscallArgs::ret_from_regs(const user_regs_struct& r) {
    return static_cast<long>(r.rax);
}

/* ── read_child_string ──────────────────────────────────────────────────── */

std::string read_child_string(pid_t pid, unsigned long addr, size_t max_len) {
    std::string result;
    result.reserve(64);

    for (size_t i = 0; i < max_len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, nullptr);
        if (errno) break;

        /* Copy bytes from word until null terminator. */
        const char* bytes = reinterpret_cast<const char*>(&word);
        for (size_t b = 0; b < sizeof(long); ++b) {
            if (bytes[b] == '\0') return result;
            result.push_back(bytes[b]);
            if (result.size() >= max_len) return result;
        }
    }
    return result;
}

/* ── SyscallEvent ───────────────────────────────────────────────────────── */

/* Syscalls that take a pathname as their first argument. */
static bool syscall_has_path_arg(long nr) {
    switch (nr) {
        case SYS_open: case SYS_stat: case SYS_lstat: case SYS_access:
        case SYS_execve: case SYS_chdir: case SYS_mkdir: case SYS_rmdir:
        case SYS_unlink: case SYS_rename: case SYS_link: case SYS_symlink:
        case SYS_readlink: case SYS_chmod: case SYS_chown: case SYS_lchown:
        case SYS_openat: case SYS_openat2:
            return true;
        default:
            return false;
    }
}

SyscallEvent SyscallEvent::begin(uint64_t seq, const SyscallArgs& args,
                                  uint64_t ts_ns, pid_t child_pid) {
    SyscallEvent ev;
    ev.sequence       = seq;
    ev.syscall_nr     = args.number;
    ev.syscall_name_sv = syscall_name(args.number);
    ev.entry_args     = args;
    ev.entry_ts_ns    = ts_ns;

    if (syscall_has_path_arg(args.number)) {
        /* For openat/openat2 the path is in arg[1], for others in arg[0]. */
        unsigned long path_addr = (args.number == SYS_openat || args.number == SYS_openat2)
            ? static_cast<unsigned long>(args.args[1])
            : static_cast<unsigned long>(args.args[0]);
        ev.resolved_path = read_child_string(child_pid, path_addr);
    }

    return ev;
}

void SyscallEvent::complete(long ret_val, uint64_t ts_ns) {
    return_value = ret_val;
    exit_ts_ns   = ts_ns;
    completed    = true;
}

/* ── ExecutionRecord ────────────────────────────────────────────────────── */

uint64_t ExecutionRecord::total_syscall_ns() const {
    uint64_t total = 0;
    for (const auto& ev : events)
        if (ev.completed) total += ev.duration_ns();
    return total;
}

/* ── TracerPolicy ───────────────────────────────────────────────────────── */

TracerPolicy::TracerPolicy(const Environment& env)
    : allow_network_(env.network)
    , allow_threads_(env.limits.max_pids > 4)
{}

PolicyDecision TracerPolicy::on_entry(const SyscallEvent& ev) {
    const long nr = ev.syscall_nr;

    /* ptrace is always KILL — no escape hatches. */
    if (nr == SYS_ptrace) return PolicyDecision::KILL;

    /* Only allow the initial execve (the binary we launch). */
    if (nr == SYS_execve || nr == SYS_execveat) {
        if (!first_execve_done_) {
            first_execve_done_ = true;
            return PolicyDecision::ALLOW;
        }
        return PolicyDecision::DENY_EPERM;
    }

    /* Thread/process creation. */
    if (nr == SYS_fork || nr == SYS_vfork || nr == SYS_clone || nr == SYS_clone3) {
        return allow_threads_ ? PolicyDecision::ALLOW : PolicyDecision::DENY_EPERM;
    }

    /* Network syscalls. */
    if (nr == SYS_socket || nr == SYS_connect || nr == SYS_bind   ||
        nr == SYS_listen  || nr == SYS_accept  || nr == SYS_accept4 ||
        nr == SYS_sendto  || nr == SYS_recvfrom || nr == SYS_sendmsg ||
        nr == SYS_recvmsg) {
        return allow_network_ ? PolicyDecision::ALLOW : PolicyDecision::DENY_EPERM;
    }

    return PolicyDecision::ALLOW;
}

void TracerPolicy::on_exit(const SyscallEvent& ev) {
    /* Log denied calls for post-mortem analysis. */
    if (ev.denied) {
        Logger::instance().debug(
            std::string("denied: ") + std::string(ev.syscall_name_sv));
    }
}

/* ── PtraceTracer ───────────────────────────────────────────────────────── */

PtraceTracer::PtraceTracer(pid_t child, TracerPolicy* policy,
                            uint64_t wall_timeout_ns)
    : child_(child)
    , policy_(policy)
    , wall_timeout_ns_(wall_timeout_ns)
{}

std::expected<ExecutionRecord, int> PtraceTracer::run() {
    ExecutionRecord record;
    record.set_start(Clock::now_ns());
    tracees_.clear();
    tracees_.insert(child_);
    std::unordered_map<pid_t, ThreadTraceState> thread_states;
    thread_states.try_emplace(child_);

    auto cleanup_tracees = [&]() {
        std::vector<pid_t> pending(tracees_.begin(), tracees_.end());
        for (pid_t pid : pending) {
            if (pid > 0) kill(pid, SIGKILL);
        }

        while (!tracees_.empty()) {
            int status = 0;
            pid_t reaped = waitpid(-1, &status, __WALL);
            if (reaped < 0) {
                if (errno == EINTR) continue;
                break;
            }
            tracees_.erase(reaped);
        }

        thread_states.clear();
        tracees_.clear();
        attached_ = false;
    };

    /* Wait for the child's initial SIGSTOP (raised after PTRACE_TRACEME). */
    int wstatus = 0;
    if (waitpid(child_, &wstatus, 0) < 0) return std::unexpected(errno);
    if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGSTOP) {
        return std::unexpected(ECHILD);
    }

    /* Enable syscall tracking, clone/fork tracing, and the EXITKILL failsafe. */
    if (ptrace(PTRACE_SETOPTIONS, child_, 0, kPtraceOptions) < 0)
        return std::unexpected(errno);

    if (ptrace(PTRACE_SYSCALL, child_, 0, 0) < 0)
        return std::unexpected(errno);

    uint64_t seq       = 0;
    int leader_exit_code = -1;
    int leader_exit_signal = 0;
    bool leader_exited = false;

    while (true) {
        uint64_t now = Clock::now_ns();
        if (now - record.wall_start_ns > wall_timeout_ns_) {
            cleanup_tracees();
            record.set_end(Clock::now_ns());
            record.set_exit_status(-1, SIGKILL);
            return record;
        }

        pid_t stopped_pid = waitpid(-1, &wstatus, __WALL | WNOHANG);
        if (stopped_pid < 0) {
            if (errno == EINTR) continue;

            record.set_end(Clock::now_ns());
            if (leader_exited) {
                record.set_exit_status(leader_exit_code, leader_exit_signal);
            } else {
                record.set_exit_status(-1, SIGKILL);
            }
            tracees_.clear();
            thread_states.clear();
            attached_ = false;
            return record;
        }

        if (stopped_pid == 0) {
            usleep(1000);
            continue;
        }

        if (WIFEXITED(wstatus)) {
            tracees_.erase(stopped_pid);
            thread_states.erase(stopped_pid);

            if (stopped_pid == child_) {
                leader_exit_code = WEXITSTATUS(wstatus);
                leader_exit_signal = 0;
                leader_exited = true;
            }

            if (tracees_.empty()) {
                record.set_end(now);
                record.set_exit_status(leader_exited ? leader_exit_code : WEXITSTATUS(wstatus),
                                       leader_exited ? leader_exit_signal : 0);
                attached_ = false;
                return record;
            }

            continue;
        }

        if (WIFSIGNALED(wstatus)) {
            tracees_.erase(stopped_pid);
            thread_states.erase(stopped_pid);

            if (stopped_pid == child_) {
                leader_exit_code = -1;
                leader_exit_signal = WTERMSIG(wstatus);
                leader_exited = true;
            }

            if (tracees_.empty()) {
                record.set_end(now);
                record.set_exit_status(leader_exited ? leader_exit_code : -1,
                                       leader_exited ? leader_exit_signal : WTERMSIG(wstatus));
                attached_ = false;
                return record;
            }

            continue;
        }

        if (!WIFSTOPPED(wstatus)) {
            ptrace(PTRACE_SYSCALL, stopped_pid, 0, 0);
            continue;
        }

        int sig = WSTOPSIG(wstatus);
        auto& state = thread_states.try_emplace(stopped_pid).first->second;

        /* Syscall entry or exit: SIGTRAP | 0x80 (from TRACESYSGOOD). */
        if (sig == (SIGTRAP | 0x80)) {
            user_regs_struct regs{};
            ptrace(PTRACE_GETREGS, stopped_pid, 0, &regs);

            if (!state.in_syscall) {
                /* Entry */
                auto args = SyscallArgs::from_entry(regs);
                state.pending_event = SyscallEvent::begin(seq++, args, now, stopped_pid);

                PolicyDecision decision = policy_->on_entry(state.pending_event);

                if (decision == PolicyDecision::KILL) {
                    cleanup_tracees();
                    record.set_end(Clock::now_ns());
                    record.set_exit_status(-1, SIGKILL);
                    return record;
                }

                if (decision == PolicyDecision::DENY_EPERM) {
                    /* Overwrite orig_rax with -1 so the kernel returns ENOSYS,
                     * then we'll inject -EPERM on the exit stop. */
                    regs.orig_rax = static_cast<unsigned long long>(-1);
                    ptrace(PTRACE_SETREGS, stopped_pid, 0, &regs);
                    state.pending_event.denied = true;
                }

                state.in_syscall = true;
            } else {
                /* Exit */
                long ret = SyscallArgs::ret_from_regs(regs);

                if (state.pending_event.denied) {
                    /* Inject -EPERM as the return value. */
                    regs.rax = static_cast<unsigned long long>(-EPERM);
                    ptrace(PTRACE_SETREGS, stopped_pid, 0, &regs);
                    ret = -EPERM;
                }

                state.pending_event.complete(ret, now);
                policy_->on_exit(state.pending_event);
                record.add_event(std::move(state.pending_event));
                state.in_syscall = false;
            }
        } else if (sig == SIGTRAP) {
            int event = wstatus >> 16;
            if (event == PTRACE_EVENT_CLONE ||
                    event == PTRACE_EVENT_FORK ||
                    event == PTRACE_EVENT_VFORK) {
                unsigned long new_pid_raw = 0;
                if (ptrace(PTRACE_GETEVENTMSG, stopped_pid, 0, &new_pid_raw) == 0) {
                    pid_t new_pid = static_cast<pid_t>(new_pid_raw);
                    if (new_pid > 0) {
                        tracees_.insert(new_pid);
                        thread_states.try_emplace(new_pid);
                        ptrace(PTRACE_SETOPTIONS, new_pid, 0, kPtraceOptions);
                        ptrace(PTRACE_SYSCALL, new_pid, 0, 0);
                    }
                }
            }
        } else {
            /* Non-syscall stop: re-inject the signal to the child. */
            int inject = (sig == SIGTRAP) ? 0 : sig;
            ptrace(PTRACE_SYSCALL, stopped_pid, 0, inject);
            continue;
        }

        ptrace(PTRACE_SYSCALL, stopped_pid, 0, 0);
    }
}

PtraceTracer::~PtraceTracer() {
    if (attached_) {
        for (pid_t pid : tracees_) {
            ptrace(PTRACE_DETACH, pid, 0, 0);
        }
    }
}
