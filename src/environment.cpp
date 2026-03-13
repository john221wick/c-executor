/*
 * environment.cpp — JSON parsing and registry population.
 *
 * Uses nlohmann/json (pulled in via CMake FetchContent).
 * Each JSON file maps 1-to-1 with one Environment struct.
 *
 * Placeholder substitution: {source} and {output} are replaced with real
 * paths at exec time; the raw command vectors are stored verbatim.
 */
#include "environment.h"
#include "logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cerrno>

using json = nlohmann::json;

/* Replace all occurrences of `token` in each element of `vec` with `value`. */
static std::vector<std::string> substitute(std::vector<std::string> vec,
                                            const std::string&       token,
                                            const std::string&       value) {
    for (auto& s : vec) {
        size_t pos = 0;
        while ((pos = s.find(token, pos)) != std::string::npos) {
            s.replace(pos, token.size(), value);
            pos += value.size();
        }
    }
    return vec;
}

std::vector<std::string> Environment::resolved_compile_cmd(
        const std::string& source, const std::string& output) const {
    auto v = substitute(compile_cmd, "{source}", source);
    return substitute(std::move(v), "{output}", output);
}

std::vector<std::string> Environment::resolved_run_cmd(
        const std::string& source, const std::string& output) const {
    auto v = substitute(run_cmd, "{source}", source);
    return substitute(std::move(v), "{output}", output);
}

/* Parse one JSON file into an Environment. Returns false on any error. */
static bool parse_environment(const std::filesystem::path& path,
                               Environment& out) {
    std::ifstream f(path);
    if (!f) {
        Logger::instance().error("cannot open: " + path.string());
        return false;
    }

    json j;
    try {
        f >> j;
    } catch (const json::exception& e) {
        Logger::instance().error("JSON parse error in " + path.string()
                                  + ": " + e.what());
        return false;
    }

    try {
        out.name        = j.at("name").get<std::string>();
        out.rootfs_path = j.at("rootfs").get<std::string>();
        out.extension   = j.at("extension").get<std::string>();
        out.network     = j.value("network", false);
        out.gpu         = j.value("gpu", false);

        /* compile is nullable */
        if (!j.at("compile").is_null())
            out.compile_cmd = j.at("compile").get<std::vector<std::string>>();

        out.run_cmd = j.at("run").get<std::vector<std::string>>();

        const auto& lim = j.at("limits");
        out.limits.memory_mb    = lim.value("memory_mb",    256ULL);
        out.limits.cpu_time_ms  = lim.value("cpu_time_ms",  2000ULL);
        out.limits.wall_time_ms = lim.value("wall_time_ms", 10000ULL);
        out.limits.max_pids     = lim.value("max_pids",     4U);

    } catch (const json::exception& e) {
        Logger::instance().error("missing field in " + path.string()
                                  + ": " + e.what());
        return false;
    }

    return true;
}

std::expected<void, int> EnvironmentRegistry::load_from(
        const std::filesystem::path& dir_path) {

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
        if (entry.path().extension() != ".json") continue;

        Environment env;
        if (!parse_environment(entry.path(), env)) continue;

        Logger::instance().info("loaded environment: " + env.name);
        envs_.emplace(env.name, std::move(env));
    }

    if (ec) return std::unexpected(ec.value());
    return {};
}

const Environment* EnvironmentRegistry::get(const std::string& name) const {
    auto it = envs_.find(name);
    return (it != envs_.end()) ? &it->second : nullptr;
}
