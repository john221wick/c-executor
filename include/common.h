/*
 * common.h — Foundation types, constants, and copy/move policy base classes.
 *
 * Every other header in this project depends on this file.
 * This file has no internal project dependencies.
 *
 * Contents:
 *   - NonCopyable / NonMovable base classes (see copy/move table in spec)
 *   - VerdictType enum + verdict_to_string()
 *   - Plain data structs: ResourceLimits, ExecResult, TestCase, TestCaseVerdict
 *   - Process-wide constants
 */
#pragma once

#include <cstdlib>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

/* ── Copy/move policy base classes ─────────────────────────────────────────
 *
 * NonCopyable: deleted copy, defaulted move.
 *   Use when the class owns a resource that can be transferred
 *   (e.g. a file descriptor moved via std::exchange).
 *
 * NonMovable: deleted move (pair with NonCopyable for fully immovable types).
 *   Use when the class owns a resource that cannot be transferred at all
 *   (e.g. a child PID under active ptrace).
 *
 * Neither uses macros. Protected ctor/dtor prevent direct instantiation.
 */
struct NonCopyable {
protected:
    NonCopyable()  = default;
    ~NonCopyable() = default;
    NonCopyable(const NonCopyable&)            = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
    NonCopyable(NonCopyable&&)                 = default;
    NonCopyable& operator=(NonCopyable&&)      = default;
};

struct NonMovable {
protected:
    NonMovable()  = default;
    ~NonMovable() = default;
    NonMovable(NonMovable&&)            = delete;
    NonMovable& operator=(NonMovable&&) = delete;
};

/* ── Verdict ────────────────────────────────────────────────────────────── */

enum class VerdictType : uint8_t {
    AC,                /* Accepted — output matches expected */
    WA,                /* Wrong Answer */
    TLE,               /* Time Limit Exceeded */
    MLE,               /* Memory Limit Exceeded */
    RE,                /* Runtime Error (non-zero exit / signal) */
    CE,                /* Compilation Error */
    SANDBOX_VIOLATION, /* Denied syscall caused crash */
    INTERNAL_ERROR     /* Executor bug — should never reach user */
};

constexpr std::string_view verdict_to_string(VerdictType v) {
    switch (v) {
        case VerdictType::AC:                return "AC";
        case VerdictType::WA:                return "WA";
        case VerdictType::TLE:               return "TLE";
        case VerdictType::MLE:               return "MLE";
        case VerdictType::RE:                return "RE";
        case VerdictType::CE:                return "CE";
        case VerdictType::SANDBOX_VIOLATION: return "SANDBOX_VIOLATION";
        case VerdictType::INTERNAL_ERROR:    return "INTERNAL_ERROR";
    }
    return "UNKNOWN";
}

/* ── Plain data structs ─────────────────────────────────────────────────── */

struct ResourceLimits {
    uint64_t memory_mb    = 256;
    uint64_t cpu_time_ms  = 2000;
    uint64_t wall_time_ms = 10000;
    uint32_t max_pids     = 4;
};

/* Filled after the child process exits. */
struct ExecResult {
    VerdictType verdict         = VerdictType::INTERNAL_ERROR;
    int         exit_code       = -1;
    int         exit_signal     = 0;
    uint64_t    wall_time_us    = 0;
    uint64_t    cpu_time_us     = 0;
    uint64_t    memory_peak_kb  = 0;
    std::string stderr_snippet;
};

/* Zero-copy: input/expected_output are string_views into mmap'd memory. */
struct TestCase {
    uint32_t         id;
    std::string_view input;
    std::string_view expected_output;
};

struct TestCaseVerdict {
    uint32_t    test_id;
    VerdictType verdict;
    ExecResult  exec_result;
    std::string diff_snippet; /* non-empty on WA */
};

/* ── Process-wide constants ─────────────────────────────────────────────── */

inline constexpr const char* DEFAULT_CGROUP_ROOT = "/sys/fs/cgroup/executor";
inline constexpr const char* DEFAULT_SANDBOX_ROOT = "/tmp/executor/sandboxes";
inline constexpr size_t      CLONE_STACK_SIZE   = 1 * 1024 * 1024; /* 1 MB */
inline constexpr int         DEFAULT_THREADS    = 4;
inline constexpr size_t      MAX_STDERR_CAPTURE = 4096;

inline std::string cgroup_root() {
    if (const char* value = std::getenv("EXECUTOR_CGROUP_ROOT");
            value && *value) {
        return value;
    }
    return DEFAULT_CGROUP_ROOT;
}

inline std::string sandbox_root() {
    if (const char* value = std::getenv("EXECUTOR_SANDBOX_ROOT");
            value && *value) {
        return value;
    }
    return DEFAULT_SANDBOX_ROOT;
}

inline bool rootfs_is_disabled() {
    if (const char* value = std::getenv("EXECUTOR_DISABLE_ROOTFS");
            value && *value && std::string_view(value) != "0") {
        return true;
    }
    return false;
}
