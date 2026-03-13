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
 *   --in-offsets   comma-separated byte offsets for input test cases
 *   --out-offsets  comma-separated byte offsets for output test cases
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
    for (int i = 1; i < argc - 1; i += 2) {
        std::string key = argv[i];
        if (key.starts_with("--")) {
            args[key.substr(2)] = argv[i + 1];
        }
    }
    /* Boolean flags (no value). */
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        if (key == "--verbose") args["verbose"] = "1";
    }
    return args;
}

static std::vector<size_t> parse_offsets(const std::string& s) {
    std::vector<size_t> offsets;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (!token.empty())
            offsets.push_back(std::stoull(token));
    }
    return offsets;
}

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << "\n"
              << "  --env        <name>          environment (e.g. cpp, python-ml)\n"
              << "  --source     <path>          source file\n"
              << "  --input      <path>          concatenated input file\n"
              << "  --output     <path>          concatenated expected output file\n"
              << "  --in-offsets <0,N,...>       byte offsets for input test cases\n"
              << "  --out-offsets <0,N,...>      byte offsets for output test cases\n"
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
    for (const char* key : {"env", "source", "input", "output",
                             "in-offsets", "out-offsets", "env-dir"}) {
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

    /* Split test cases from mmap'd files. */
    auto in_offsets  = parse_offsets(args["in-offsets"]);
    auto out_offsets = parse_offsets(args["out-offsets"]);

    auto cases_result = split(args["input"], args["output"],
                               in_offsets, out_offsets);
    if (!cases_result) {
        std::cerr << "failed to split test cases: "
                  << strerror(cases_result.error()) << "\n";
        return 2;
    }
    const auto& test_cases = *cases_result;

    /* Ensure sandbox root exists. */
    std::filesystem::create_directories(SANDBOX_ROOT);
    std::filesystem::create_directories(CGROUP_ROOT);

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
