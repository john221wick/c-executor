/*
 * engine.cpp — Thread pool + compilation step.
 *
 * ExecutorEngine::run():
 *   1. If the environment needs compilation, forks a child, exec's the
 *      compiler with a 30-second hard timeout. On failure, returns CE for
 *      all test cases without running any.
 *   2. Dispatches all test cases to a fixed-size thread pool. Each thread
 *      picks the next test case from a shared queue and calls Worker::run().
 *   3. Collects all TestCaseVerdicts, sorts by test_id, and returns.
 *
 * Compilation runs in a simple lightweight fork (no full namespace sandbox)
 * because the compiler binary is trusted. Only the source file and a temp
 * output directory are involved.
 */
#include "sandbox.h"
#include "logger.h"
#include "common.h"
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

/* Include worker implementation directly (no separate header needed). */
#include "worker.cpp"

/* ── ExecutorEngine ─────────────────────────────────────────────────────── */

class ExecutorEngine : public NonCopyable, public NonMovable {
public:
    ExecutorEngine(const Environment& env, int thread_count)
        : env_(env), thread_count_(thread_count)
    {}

    std::vector<TestCaseVerdict> run(const std::vector<TestCase>& test_cases) {
        namespace fs = std::filesystem;

        /* 1. Compilation */
        std::string exe_path;

        if (env_.needs_compilation()) {
            /* We expect test_cases to carry the source path via a side channel.
             * Convention: source_path_ is set by the caller before run(). */
            fs::create_directories(SANDBOX_ROOT);
            std::string out_binary = std::string(SANDBOX_ROOT) + "/compiled_"
                                     + std::to_string(getpid());

            auto argv_vec = env_.resolved_compile_cmd(source_path_, out_binary);
            if (argv_vec.empty()) {
                return make_ce_verdicts(test_cases, "empty compile command");
            }

            auto result = compile(argv_vec);
            if (!result) {
                return make_ce_verdicts(test_cases, result.error());
            }
            exe_path = out_binary;
        } else {
            /* Interpreted: source is the "binary". */
            exe_path = source_path_;
        }

        /* 2. Thread pool dispatch */
        std::vector<TestCaseVerdict>    verdicts;
        std::mutex                      verdicts_mu;
        std::queue<const TestCase*>     queue;
        std::mutex                      queue_mu;
        std::condition_variable         queue_cv;
        std::atomic<bool>               done{false};

        for (const auto& tc : test_cases) queue.push(&tc);

        auto worker_fn = [&]() {
            while (true) {
                const TestCase* tc = nullptr;
                {
                    std::unique_lock lock(queue_mu);
                    if (queue.empty()) return;
                    tc = queue.front();
                    queue.pop();
                }

                Worker w(env_, exe_path);
                auto result = w.run(*tc);

                std::lock_guard lock(verdicts_mu);
                if (result) {
                    verdicts.push_back(std::move(*result));
                } else {
                    Logger::instance().error(
                        "worker failed for test " + std::to_string(tc->id) +
                        ": " + std::strerror(result.error())
                    );
                    verdicts.push_back(TestCaseVerdict{
                        .test_id     = tc->id,
                        .verdict     = VerdictType::INTERNAL_ERROR,
                        .exec_result = {},
                        .diff_snippet = {},
                    });
                }
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(thread_count_);
        for (int i = 0; i < thread_count_; ++i)
            threads.emplace_back(worker_fn);

        for (auto& t : threads) t.join();

        /* 3. Sort by test_id before returning. */
        std::sort(verdicts.begin(), verdicts.end(),
                  [](const TestCaseVerdict& a, const TestCaseVerdict& b) {
                      return a.test_id < b.test_id;
                  });

        return verdicts;
    }

    void set_source(const std::string& source_path) {
        source_path_ = source_path;
    }

    ~ExecutorEngine() = default;

private:
    const Environment& env_;
    int                thread_count_;
    std::string        source_path_;

    /* Fork + exec the compiler. Returns empty string on success,
     * error message on failure. Times out after 30 seconds. */
    std::expected<void, std::string> compile(const std::vector<std::string>& argv_vec) {
        pid_t pid = fork();
        if (pid < 0) return std::unexpected(std::string("fork: ") + strerror(errno));

        if (pid == 0) {
            /* Child: exec the compiler. */
            auto argv = make_argv(argv_vec);
            execve(argv[0], argv.data(), environ);
            _exit(127);
        }

        /* Parent: wait up to 30 seconds. */
        for (int waited = 0; waited < 30; ++waited) {
            int wstatus = 0;
            pid_t r = waitpid(pid, &wstatus, WNOHANG);
            if (r == pid) {
                if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) return {};
                return std::unexpected("compiler exited with status "
                                       + std::to_string(WEXITSTATUS(wstatus)));
            }
            sleep(1);
        }

        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        return std::unexpected("compiler timed out");
    }

    static std::vector<char*> make_argv(const std::vector<std::string>& args) {
        std::vector<char*> v;
        v.reserve(args.size() + 1);
        for (const auto& s : args) v.push_back(const_cast<char*>(s.c_str()));
        v.push_back(nullptr);
        return v;
    }

    static std::vector<TestCaseVerdict> make_ce_verdicts(
            const std::vector<TestCase>& cases, const std::string& msg) {
        Logger::instance().error("CE: " + msg);
        std::vector<TestCaseVerdict> out;
        out.reserve(cases.size());
        for (const auto& tc : cases)
            out.push_back(TestCaseVerdict{.test_id = tc.id,
                                          .verdict = VerdictType::CE,
                                          .exec_result = {},
                                          .diff_snippet = {}});
        return out;
    }
};
