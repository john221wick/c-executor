/*
 * environment.h — Environment struct and registry.
 *
 * An "Environment" is a JSON config that fully describes how to compile and
 * run code inside a sandbox: rootfs path, commands, resource limits, and two
 * capability flags (network, gpu). Zero code changes are required to add a
 * new language or runtime — just write a JSON file.
 *
 * Placeholder substitution: compile_cmd and run_cmd may contain the tokens
 * {source} and {output}, which are replaced with real paths at exec time via
 * resolved_compile_cmd() / resolved_run_cmd().
 *
 * EnvironmentRegistry loads all *.json files from a directory at startup.
 * After load_from(), every lookup is a read-only unordered_map hit.
 */
#pragma once

#include "common.h"
#include <expected>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

struct ReadOnlyMount {
    std::string source_path; /* host path */
    std::string target_path; /* absolute path inside sandbox */
};

struct Environment {
    std::string              name;
    std::string              rootfs_path;
    std::vector<std::string> compile_cmd; /* empty = interpreted, no compile step */
    std::vector<std::string> run_cmd;
    std::string              extension;   /* ".cpp", ".py", ".js", etc. */
    ResourceLimits           limits;
    std::vector<ReadOnlyMount> read_only_mounts;
    bool                     network = false;
    bool                     gpu     = false;

    bool needs_compilation() const { return !compile_cmd.empty(); }

    /* Replace {source} and {output} in compile_cmd with real paths. */
    std::vector<std::string> resolved_compile_cmd(const std::string& source,
                                                   const std::string& output) const;

    /* Replace {source} and {output} in run_cmd with real paths. */
    std::vector<std::string> resolved_run_cmd(const std::string& source,
                                               const std::string& output) const;
};

class EnvironmentRegistry {
public:
    static EnvironmentRegistry& instance() {
        static EnvironmentRegistry inst;
        return inst;
    }

    EnvironmentRegistry(const EnvironmentRegistry&)            = delete;
    EnvironmentRegistry& operator=(const EnvironmentRegistry&) = delete;
    EnvironmentRegistry(EnvironmentRegistry&&)                 = delete;
    EnvironmentRegistry& operator=(EnvironmentRegistry&&)      = delete;

    /* Read all *.json files from dir_path and populate the registry.
     * Call once at startup before any get() calls. */
    std::expected<void, int> load_from(const std::filesystem::path& dir_path);

    /* Returns nullptr if name is not registered. */
    const Environment* get(const std::string& name) const;

private:
    EnvironmentRegistry() = default;

    std::unordered_map<std::string, Environment> envs_;
};
