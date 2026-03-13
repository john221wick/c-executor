/*
 * logger.h — Header-only thread-safe singleton logger.
 *
 * Uses std::source_location so every log line carries file:line automatically
 * without macros. The singleton is guarded by a private constructor; copy and
 * move are explicitly deleted (not via a base class) because Logger is the
 * canonical singleton pattern with no resource to transfer.
 *
 * Format: [seconds.microseconds] [LVL] [file:line] message
 * Flushes on WARN and above.
 *
 * Usage:
 *   Logger::instance().info("sandbox ready");
 *   Logger::instance().error("clone failed: " + std::to_string(errno));
 */
#pragma once

#include <chrono>
#include <cstdio>
#include <mutex>
#include <source_location>
#include <string_view>

enum class LogLevel : uint8_t { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    /* Explicit deletes — private ctor is the real guard, not a base class. */
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

    void set_level(LogLevel l) { min_level_ = l; }

    void log(std::string_view msg,
             LogLevel level,
             std::source_location loc = std::source_location::current())
    {
        if (level < min_level_) return;

        auto now  = std::chrono::system_clock::now();
        auto us   = std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch()).count();
        long sec  = static_cast<long>(us / 1'000'000);
        long usec = static_cast<long>(us % 1'000'000);

        std::lock_guard lock(mu_);
        std::fprintf(out_, "[%ld.%06ld] [%s] [%s:%d] %.*s\n",
                     sec, usec, level_str(level),
                     loc.file_name(), loc.line(),
                     static_cast<int>(msg.size()), msg.data());
        if (level >= LogLevel::WARN) std::fflush(out_);
    }

    void debug(std::string_view msg,
               std::source_location loc = std::source_location::current())
    { log(msg, LogLevel::DEBUG, loc); }

    void info(std::string_view msg,
              std::source_location loc = std::source_location::current())
    { log(msg, LogLevel::INFO, loc); }

    void warn(std::string_view msg,
              std::source_location loc = std::source_location::current())
    { log(msg, LogLevel::WARN, loc); }

    void error(std::string_view msg,
               std::source_location loc = std::source_location::current())
    { log(msg, LogLevel::ERROR, loc); }

private:
    Logger() = default;

    static constexpr const char* level_str(LogLevel l) {
        switch (l) {
            case LogLevel::DEBUG: return "DBG";
            case LogLevel::INFO:  return "INF";
            case LogLevel::WARN:  return "WRN";
            case LogLevel::ERROR: return "ERR";
        }
        return "???";
    }

    std::mutex mu_;
    std::FILE* out_       = stderr;
    LogLevel   min_level_ = LogLevel::INFO;
};
