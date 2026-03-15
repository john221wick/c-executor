/*
 * main.cpp — CLI entry point.
 *
 * Parses arguments, loads environments, splits test cases, runs the engine,
 * and prints results. Exit code 0 if all test cases passed, 1 otherwise.
 *
 * Arguments:
 *   --env          environment name (e.g. "cpp", "python-ml")
 *   --source       path to the source file
 *   --input        path to the concatenated input file
 *   --output       path to the concatenated expected output file
 *   --env-dir      directory containing *.json environment configs
 *   --threads      number of worker threads (default: 4)
 *   --verbose      enable DEBUG logging
 */
#include "environment.h"
#include "io.h"
#include "logger.h"
#include "common.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

/* Include engine (which includes worker) — no separate headers needed. */
#include "engine.cpp"

/* ── CLI helpers ────────────────────────────────────────────────────────── */

static std::unordered_map<std::string, std::string>
parse_args(int argc, char** argv) {
    std::unordered_map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        if (!key.starts_with("--")) continue;

        if (key == "--verbose") {
            args["verbose"] = "1";
        } else if (i + 1 < argc) {
            args[key.substr(2)] = argv[i + 1];
            ++i;
        }
    }
    return args;
}

static bool enable_cgroup_controllers(const std::filesystem::path& root_path,
                                      std::string& error) {
    std::ifstream controllers_file(root_path / "cgroup.controllers");
    if (!controllers_file) {
        error = "cannot read " + (root_path / "cgroup.controllers").string();
        return false;
    }

    std::string controller;
    std::string value;
    while (controllers_file >> controller) {
        if (!value.empty()) value += ' ';
        value += '+' + controller;
    }

    if (value.empty()) return true;

    std::ofstream subtree_file(root_path / "cgroup.subtree_control");
    if (!subtree_file) {
        error = "cannot open " + (root_path / "cgroup.subtree_control").string();
        return false;
    }

    subtree_file << value;
    if (!subtree_file) {
        error = "cannot write " + (root_path / "cgroup.subtree_control").string();
        return false;
    }

    return true;
}

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << "\n"
              << "  --env        <name>          environment (e.g. cpp, python-ml)\n"
              << "  --source     <path>          source file\n"
              << "  --input      <path>          concatenated input file\n"
              << "  --output     <path>          concatenated expected output file\n"
              << "  --env-dir    <path>          directory containing *.json env configs\n"
              << "  --threads    <N>             worker threads (default: 4)\n"
              << "  --verbose                    enable debug logging\n";
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);

    if (args.count("verbose"))
        Logger::instance().set_level(LogLevel::DEBUG);

    /* Validate required arguments. */
    for (const char* key : {"env", "source", "input", "output", "env-dir"}) {
        if (!args.count(key)) {
            std::cerr << "missing --" << key << "\n";
            usage(argv[0]);
            return 2;
        }
    }

    /* Load environment registry. */
    auto& registry = EnvironmentRegistry::instance();
    if (auto r = registry.load_from(args["env-dir"]); !r) {
        std::cerr << "failed to load environments from " << args["env-dir"]
                  << ": " << strerror(r.error()) << "\n";
        return 2;
    }

    const Environment* env = registry.get(args["env"]);
    if (!env) {
        std::cerr << "unknown environment: " << args["env"] << "\n";
        return 2;
    }

    /* Split test cases from input/output files. */
    auto cases_result = split(args["input"], args["output"]);
    if (!cases_result) {
        std::cerr << "failed to split test cases: "
                  << strerror(cases_result.error()) << "\n";
        return 2;
    }
    const auto& test_cases = *cases_result;

    /* Ensure sandbox root exists. */
    const auto cgroup_root_path = cgroup_root();
    std::error_code ec;
    std::filesystem::create_directories(SANDBOX_ROOT, ec);
    if (ec) {
        std::cerr << "failed to create sandbox root " << SANDBOX_ROOT
                  << ": " << ec.message() << "\n";
        return 2;
    }

    ec.clear();
    std::filesystem::create_directories(cgroup_root_path, ec);
    if (ec) {
        std::cerr << "failed to create cgroup root " << cgroup_root_path
                  << ": " << ec.message() << "\n"
                  << "create it manually after build and before running "
                     "c-executor, or set EXECUTOR_CGROUP_ROOT to a writable "
                     "delegated cgroup path\n";
        return 2;
    }

    std::string cgroup_error;
    if (!enable_cgroup_controllers(cgroup_root_path, cgroup_error)) {
        std::cerr << "failed to enable cgroup controllers in "
                  << cgroup_root_path << ": " << cgroup_error << "\n";
        return 2;
    }

    /* Run. */
    int threads = args.count("threads") ? std::stoi(args["threads"])
                                        : DEFAULT_THREADS;
    ExecutorEngine engine(*env, threads);
    engine.set_source(args["source"]);

    auto verdicts = engine.run(test_cases);

    /* Print results. */
    bool all_ac = true;
    for (const auto& v : verdicts) {
        const auto& r = v.exec_result;
        std::cout << "Test " << v.test_id
                  << ": " << verdict_to_string(v.verdict)
                  << " | " << (r.wall_time_us / 1000) << "ms"
                  << " | " << r.memory_peak_kb << "KB"
                  << "\n";

        if (v.verdict == VerdictType::WA && !v.diff_snippet.empty())
            std::cout << "  diff: " << v.diff_snippet << "\n";

        if (v.verdict != VerdictType::AC) all_ac = false;
    }

    return all_ac ? 0 : 1;
}
