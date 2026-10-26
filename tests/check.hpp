// Tiny assertion harness for the MC5 Offline unit tests (keeps the build
// dependency-free). CHECK records a failure and continues; main returns the
// failure count.
#pragma once
#include <cstdio>
#include <string>

namespace mc5test {
inline int& failures() { static int f = 0; return f; }
inline void report(bool ok, const char* expr, const char* file, int line) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
        ++failures();
    }
}
} // namespace mc5test

#define CHECK(cond) ::mc5test::report((cond), #cond, __FILE__, __LINE__)
#define CHECK_EQ(a, b) ::mc5test::report((a) == (b), #a " == " #b, __FILE__, __LINE__)
