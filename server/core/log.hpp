// Logging for MC5 Offline.
//
// On Android everything goes to logcat under a single tag ("MC5Offline"), because
// the owner's file uploads from the phone often arrive as 0 bytes while logcat text
// is reliable. On the desktop (dev loop, tests) it goes to stderr with a timestamp.
// A rolling in-memory ring buffer is also kept so the embedded server can later
// serve a phone-readable copy of the log.
//
// C++17, header-only.
#pragma once

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace mc5 {

enum class LogLevel { Debug = 3, Info = 4, Warn = 5, Error = 6, Fatal = 7 };

class Log {
public:
    static Log& instance() {
        static Log inst;
        return inst;
    }

    void set_min_level(LogLevel lvl) { min_level_ = lvl; }
    LogLevel min_level() const { return min_level_; }

    void write(LogLevel lvl, const char* fmt, va_list ap) {
        if (static_cast<int>(lvl) < static_cast<int>(min_level_)) return;
        char buf[2048];
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        emit(lvl, buf);
    }

    // Snapshot of the recent log lines (newest last), for the on-device viewer.
    std::vector<std::string> tail(std::size_t max_lines) const {
        std::lock_guard<std::mutex> g(mu_);
        if (ring_.size() <= max_lines) return ring_;
        return std::vector<std::string>(ring_.end() - max_lines, ring_.end());
    }

private:
    Log() = default;

    void emit(LogLevel lvl, const char* msg) {
        static const char* kTag = "MC5Offline";
#if defined(__ANDROID__)
        int prio = ANDROID_LOG_INFO;
        switch (lvl) {
            case LogLevel::Debug: prio = ANDROID_LOG_DEBUG; break;
            case LogLevel::Info: prio = ANDROID_LOG_INFO; break;
            case LogLevel::Warn: prio = ANDROID_LOG_WARN; break;
            case LogLevel::Error: prio = ANDROID_LOG_ERROR; break;
            case LogLevel::Fatal: prio = ANDROID_LOG_FATAL; break;
        }
        __android_log_write(prio, kTag, msg);
#else
        std::time_t t = std::time(nullptr);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%H:%M:%S", std::localtime(&t));
        const char* lc = "I";
        switch (lvl) {
            case LogLevel::Debug: lc = "D"; break;
            case LogLevel::Info: lc = "I"; break;
            case LogLevel::Warn: lc = "W"; break;
            case LogLevel::Error: lc = "E"; break;
            case LogLevel::Fatal: lc = "F"; break;
        }
        std::fprintf(stderr, "%s %s/%s: %s\n", ts, lc, kTag, msg);
        std::fflush(stderr);
#endif
        std::lock_guard<std::mutex> g(mu_);
        ring_.emplace_back(msg);
        if (ring_.size() > kRingCap) ring_.erase(ring_.begin(), ring_.begin() + (ring_.size() - kRingCap));
    }

    static constexpr std::size_t kRingCap = 4000;
    LogLevel min_level_ = LogLevel::Debug;
    mutable std::mutex mu_;
    std::vector<std::string> ring_;
};

inline void logd(const char* fmt, ...) { va_list ap; va_start(ap, fmt); Log::instance().write(LogLevel::Debug, fmt, ap); va_end(ap); }
inline void logi(const char* fmt, ...) { va_list ap; va_start(ap, fmt); Log::instance().write(LogLevel::Info, fmt, ap); va_end(ap); }
inline void logw(const char* fmt, ...) { va_list ap; va_start(ap, fmt); Log::instance().write(LogLevel::Warn, fmt, ap); va_end(ap); }
inline void loge(const char* fmt, ...) { va_list ap; va_start(ap, fmt); Log::instance().write(LogLevel::Error, fmt, ap); va_end(ap); }
inline void logf(const char* fmt, ...) { va_list ap; va_start(ap, fmt); Log::instance().write(LogLevel::Fatal, fmt, ap); va_end(ap); }

} // namespace mc5
