/*
 * tracer.h — Ptrace-based syscall tracing: clock, events, record, policy, loop.
 *
 * Design:
 *   ExecutionRecord stores raw SyscallEvents — no precomputed aggregates.
 *   Compute stats at the call site when needed (e.g. total_syscall_ns()).
 *
 *   TracerPolicy is constructed from an Environment. It decides ALLOW /
 *   DENY_EPERM / KILL for each syscall entry based on dynamic state
 *   (first_execve_done, open_count, env.network, env.limits.max_pids).
 *
 *   PtraceTracer owns the trace loop. It drives the child one syscall at a
 *   time, consults the policy on entry (optionally rewriting orig_rax to -1
 *   to inject ENOSYS), records the entry/exit pair, and stops when the child
 *   exits or the wall timeout is exceeded.
 */
#pragma once

#include "common.h"
#include "environment.h"
#include <expected>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>
#include <sys/user.h>

/* ── Clock ──────────────────────────────────────────────────────────────── */

struct Clock {
    static uint64_t now_ns();
    static uint64_t ns_to_us(uint64_t ns) { return ns / 1000; }
    static double   ns_to_ms(uint64_t ns) { return static_cast<double>(ns) / 1e6; }
};

/* ── Syscall arguments extracted from x86_64 registers ─────────────────── */

struct SyscallArgs {
    long number;
    long args[6];
    long return_value;

    /* number=orig_rax, args={rdi,rsi,rdx,r10,r8,r9} */
    static SyscallArgs from_entry(const user_regs_struct& regs);
    static long        ret_from_regs(const user_regs_struct& regs);
};

/* Flat array lookup, not a class. Returns "unknown" for unmapped numbers. */
std::string_view syscall_name(long nr);

/* Read a null-terminated C string from the child's virtual address space.
 * Uses PTRACE_PEEKDATA word by word. Stops at null or max_len. */
std::string read_child_string(pid_t pid, unsigned long addr, size_t max_len = 256);

/* ── Syscall event — one entry/exit pair ────────────────────────────────── */

struct SyscallEvent {
    uint64_t         sequence;
    long             syscall_nr;
    std::string_view syscall_name_sv; /* points into static name table, no alloc */
    SyscallArgs      entry_args;
    std::string      resolved_path;   /* populated when syscall accepts a pathname */
    uint64_t         entry_ts_ns  = 0;
    uint64_t         exit_ts_ns   = 0;
    long             return_value = 0;
    bool             completed    = false;
    bool             denied       = false;

    uint64_t duration_ns() const { return exit_ts_ns - entry_ts_ns; }

    /* Build entry half of the event. Resolves the path if applicable. */
    static SyscallEvent begin(uint64_t seq, const SyscallArgs& args,
                               uint64_t ts_ns, pid_t child_pid);

    void complete(long ret_val, uint64_t ts_ns);
};

/* ── Execution record ───────────────────────────────────────────────────── */

struct ExecutionRecord {
    std::vector<SyscallEvent> events;
    uint64_t wall_start_ns = 0;
    uint64_t wall_end_ns   = 0;
    int      exit_code     = -1;
    int      exit_signal   = 0;

    uint64_t wall_time_ns()     const { return wall_end_ns - wall_start_ns; }
    uint64_t total_syscall_ns() const;
    size_t   total_events()     const { return events.size(); }

    void set_start(uint64_t ts)              { wall_start_ns = ts; }
    void set_end(uint64_t ts)                { wall_end_ns = ts; }
    void set_exit_status(int code, int sig)  { exit_code = code; exit_signal = sig; }
    void add_event(SyscallEvent e)           { events.push_back(std::move(e)); }
};

/* ── Policy ─────────────────────────────────────────────────────────────── */

enum class PolicyDecision : uint8_t { ALLOW, DENY_EPERM, KILL };

class TracerPolicy {
public:
    explicit TracerPolicy(const Environment& env);

    PolicyDecision on_entry(const SyscallEvent& ev);
    void           on_exit(const SyscallEvent& ev); /* logging only */

private:
    bool     first_execve_done_ = false;
    uint32_t open_count_        = 0;
    bool     allow_network_;
    bool     allow_threads_;   /* heuristic: max_pids > 4 implies threading */
};

/* ── Tracer ─────────────────────────────────────────────────────────────── */

class PtraceTracer : public NonCopyable, public NonMovable {
public:
    PtraceTracer(pid_t child, TracerPolicy* policy, uint64_t wall_timeout_ns);

    /* Drive the child to completion. Returns the execution record.
     * Returns errno on fatal tracer error (not child error). */
    std::expected<ExecutionRecord, int> run();

    ~PtraceTracer();

private:
    pid_t         child_;
    TracerPolicy* policy_;
    uint64_t      wall_timeout_ns_;
    bool          attached_ = true;
};
