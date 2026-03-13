/*
 * worker.cpp — Orchestrates one test case end-to-end.
 *
 * Worker::run() is called from the engine's thread pool, one call per test
 * case. It:
 *   1. Creates a working directory and writes input.
 *   2. Creates the cgroup.
 *   3. Clones the child with all namespace flags.
 *   4. Writes uid/gid maps so the child sees itself as root.
 *   5. Attaches the child to the cgroup.
 *   6. Runs the ptrace loop.
 *   7. Reads cgroup stats and actual stdout.
 *   8. Determines the verdict.
 *   RAII guards clean everything up automatically in reverse order.
 *
 * child_fn() runs inside the cloned child. It executes: PTRACE_TRACEME →
 * SIGSTOP → rootfs setup → landlock → seccomp → drop caps → dup2 I/O → execve.
 */
#include "sandbox.h"
#include "tracer.h"
#include "io.h"
#include "logger.h"
#include "common.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/capability.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <expected>

/* ── ChildContext — passed through the clone void* arg ─────────────────── */

struct ChildContext {
    const Environment* env;
    std::string        work_dir;
    std::string        binary_path; /* resolved {output} or {source} */
    std::vector<std::string> argv;  /* run_cmd after substitution */
    int                input_fd;
    int                output_fd;
    int                stderr_fd;
};

/* Drop all capabilities. Called in the child before execve. */
static void drop_capabilities() {
    /* cap_clear_flag on all caps, then set. Ignore errors — we're in a
     * user namespace so we may already have no real capabilities. */
    cap_t caps = cap_get_proc();
    if (caps) {
        cap_clear(caps);
        cap_set_proc(caps);
        cap_free(caps);
    }
}

/* Build a null-terminated argv array from a vector<string>. */
static std::vector<char*> make_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& s : args)
        argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);
    return argv;
}

/* ── Child function ─────────────────────────────────────────────────────── */

static int child_fn(void* arg) {
    auto* ctx = static_cast<ChildContext*>(arg);

    /* Signal the tracer that we are ready for PTRACE_SETOPTIONS. */
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    raise(SIGSTOP);

    /* Set up overlay rootfs + pivot_root. */
    if (setup_child_rootfs(*ctx->env, ctx->work_dir) < 0) {
        Logger::instance().error("setup_child_rootfs failed");
        _exit(127);
    }

    /* Landlock: whitelist-only filesystem access. */
    auto ll_rules = build_landlock_rules(*ctx->env, "/work");
    auto ll_guard = LandlockGuard::create(ll_rules);
    if (ll_guard) {
        if (!ll_guard->enforce()) {
            /* Non-fatal: log and continue — seccomp + ptrace still active. */
            Logger::instance().warn("landlock enforce failed");
        }
    }

    /* Seccomp BPF filter. */
    if (auto r = install_seccomp(*ctx->env); !r) {
        Logger::instance().error("seccomp failed: " + std::to_string(r.error()));
        _exit(127);
    }

    drop_capabilities();

    /* Wire up stdin/stdout/stderr to the files prepared by the parent. */
    dup2(ctx->input_fd,  STDIN_FILENO);
    dup2(ctx->output_fd, STDOUT_FILENO);
    dup2(ctx->stderr_fd, STDERR_FILENO);

    /* Close everything above stderr. */
    for (int fd = 3; fd < 1024; ++fd) close(fd);

    auto argv = make_argv(ctx->argv);
    execve(argv[0], argv.data(), nullptr);

    /* execve only returns on failure. */
    _exit(127);
}

/* ── Worker ─────────────────────────────────────────────────────────────── */

class Worker : public NonCopyable, public NonMovable {
public:
    Worker(const Environment& env, std::string compiled_exe)
        : env_(env), compiled_exe_(std::move(compiled_exe))
    {}

    std::expected<TestCaseVerdict, int> run(const TestCase& tc) {
        namespace fs = std::filesystem;

        /* 1. Work directory */
        std::string work_dir = std::string(SANDBOX_ROOT) + "/task_"
                               + std::to_string(tc.id) + "_"
                               + std::to_string(getpid());
        fs::create_directories(work_dir);

        /* Write test input. */
        std::string input_path  = work_dir + "/stdin.txt";
        std::string output_path = work_dir + "/stdout.txt";
        std::string stderr_path = work_dir + "/stderr.txt";

        {
            int fd = open(input_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) return std::unexpected(errno);
            write(fd, tc.input.data(), tc.input.size());
            close(fd);
        }

        /* Create output/stderr files. */
        int out_fd = open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int err_fd = open(stderr_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int in_fd  = open(input_path.c_str(),  O_RDONLY);

        if (out_fd < 0 || err_fd < 0 || in_fd < 0) {
            if (out_fd >= 0) close(out_fd);
            if (err_fd >= 0) close(err_fd);
            if (in_fd  >= 0) close(in_fd);
            return std::unexpected(errno);
        }

        /* 2. Cgroup */
        auto cgroup = CgroupGuard::create("task_" + std::to_string(tc.id), env_.limits);
        if (!cgroup) { cleanup(work_dir, out_fd, err_fd, in_fd); return std::unexpected(cgroup.error()); }

        /* Resolve binary path and argv. */
        std::string binary_in_sandbox = "/work/" + fs::path(compiled_exe_).filename().string();
        auto argv_vec = env_.resolved_run_cmd(binary_in_sandbox, binary_in_sandbox);
        if (argv_vec.empty()) { cleanup(work_dir, out_fd, err_fd, in_fd); return std::unexpected(EINVAL); }

        /* Copy binary into work dir so it's accessible inside the sandbox. */
        fs::copy_file(compiled_exe_, work_dir + "/" + fs::path(compiled_exe_).filename().string(),
                      fs::copy_options::overwrite_existing);
        fs::permissions(work_dir + "/" + fs::path(compiled_exe_).filename().string(),
                        fs::perms::owner_exec | fs::perms::owner_read | fs::perms::group_read,
                        fs::perm_options::add);

        /* 3. Clone */
        ChildContext ctx{
            .env         = &env_,
            .work_dir    = work_dir,
            .binary_path = binary_in_sandbox,
            .argv        = argv_vec,
            .input_fd    = in_fd,
            .output_fd   = out_fd,
            .stderr_fd   = err_fd,
        };

        int flags = clone_flags_for(env_);
        auto ns   = NamespaceGuard::create(child_fn, &ctx, flags);
        if (!ns) { cleanup(work_dir, out_fd, err_fd, in_fd); return std::unexpected(ns.error()); }

        /* 4. uid/gid maps */
        if (auto r = ns->write_uid_gid_mappings(); !r) {
            ns->kill();
            cleanup(work_dir, out_fd, err_fd, in_fd);
            return std::unexpected(r.error());
        }

        /* 5. Attach to cgroup */
        if (auto r = cgroup->attach(ns->child_pid()); !r) {
            ns->kill();
            cleanup(work_dir, out_fd, err_fd, in_fd);
            return std::unexpected(r.error());
        }

        /* Close parent-side fds — child has its own copies via dup2. */
        close(in_fd); close(out_fd); close(err_fd);

        /* 6. Trace */
        uint64_t timeout_ns = env_.limits.wall_time_ms * 1'000'000ULL;
        TracerPolicy   policy(env_);
        PtraceTracer   tracer(ns->child_pid(), &policy, timeout_ns);

        auto record_result = tracer.run();
        if (!record_result) {
            ns->kill();
            fs::remove_all(work_dir);
            return std::unexpected(record_result.error());
        }
        const auto& record = *record_result;

        /* Reap the child. */
        ns->wait();

        /* 7. Cgroup stats */
        uint64_t mem_peak_kb  = cgroup->peak_memory_bytes() / 1024;
        uint64_t cpu_time_us  = cgroup->cpu_usage_us();

        /* 8. Read actual stdout */
        std::string actual_output;
        {
            int fd = open(output_path.c_str(), O_RDONLY);
            if (fd >= 0) {
                char buf[4096];
                ssize_t n;
                while ((n = read(fd, buf, sizeof(buf))) > 0)
                    actual_output.append(buf, static_cast<size_t>(n));
                close(fd);
            }
        }

        /* Read stderr snippet */
        std::string stderr_snippet;
        {
            int fd = open(stderr_path.c_str(), O_RDONLY);
            if (fd >= 0) {
                char buf[MAX_STDERR_CAPTURE];
                ssize_t n = read(fd, buf, sizeof(buf));
                if (n > 0) stderr_snippet.assign(buf, static_cast<size_t>(n));
                close(fd);
            }
        }

        /* 9. Verdict */
        uint64_t wall_us = Clock::ns_to_us(record.wall_time_ns());
        bool     timed_out = (wall_us * 1000 >= env_.limits.wall_time_ms * 1'000'000ULL);
        bool     oom       = (mem_peak_kb * 1024 >= env_.limits.memory_mb * 1024 * 1024);

        VerdictType verdict;
        std::string diff_snippet;

        if (record.exit_signal == SIGKILL && timed_out) {
            verdict = VerdictType::TLE;
        } else if (record.exit_signal == SIGKILL && oom) {
            verdict = VerdictType::MLE;
        } else if (record.exit_signal != 0 || record.exit_code != 0) {
            /* Check if a denied syscall triggered the crash. */
            bool any_denied = false;
            for (const auto& ev : record.events) if (ev.denied) { any_denied = true; break; }
            verdict = any_denied ? VerdictType::SANDBOX_VIOLATION : VerdictType::RE;
        } else {
            verdict = compare(actual_output, tc.expected_output, diff_snippet);
        }

        ExecResult exec_result{
            .verdict        = verdict,
            .exit_code      = record.exit_code,
            .exit_signal    = record.exit_signal,
            .wall_time_us   = wall_us,
            .cpu_time_us    = cpu_time_us,
            .memory_peak_kb = mem_peak_kb,
            .stderr_snippet = std::move(stderr_snippet),
        };

        /* 10. Cleanup (cgroup and ns guards clean up in their destructors). */
        fs::remove_all(work_dir);

        return TestCaseVerdict{
            .test_id      = tc.id,
            .verdict      = verdict,
            .exec_result  = std::move(exec_result),
            .diff_snippet = std::move(diff_snippet),
        };
    }

private:
    const Environment& env_;
    std::string        compiled_exe_;

    static void cleanup(const std::string& work_dir, int a, int b, int c) {
        if (a >= 0) close(a);
        if (b >= 0) close(b);
        if (c >= 0) close(c);
        std::filesystem::remove_all(work_dir);
    }
};
