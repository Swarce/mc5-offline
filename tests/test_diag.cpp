// Host test for the diagnostics crash reporter (M0.5). diag.cpp is portable
// Linux, so the signal handler, the /proc/self/maps backtrace resolution and the
// async-signal-safe formatter can be exercised on the desktop.
//
// A child process installs the handler and dereferences null; we capture its
// stderr (the handler writes there with raw write()) and assert the crash line,
// at least one resolved backtrace frame, and that the child really died from the
// signal after the handler chained through.
#include "hosts/embedded/diag.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

#include "tests/check.hpp"

static std::string run_crashing_child() {
    int p[2];
    if (pipe(p) != 0) { perror("pipe"); return {}; }
    pid_t pid = fork();
    if (pid == 0) {
        // child: route stderr into the pipe, install handler, crash.
        dup2(p[1], 2);
        close(p[0]);
        close(p[1]);
        mc5::diag::init(std::string());
        volatile int* np = nullptr;
        *np = 42;        // SIGSEGV
        _exit(0);        // not reached
    }
    close(p[1]);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = read(p[0], buf, sizeof(buf))) > 0) out.append(buf, static_cast<size_t>(n));
    close(p[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) CHECK_EQ(WTERMSIG(status), SIGSEGV);
    return out;
}

int main() {
    // boot_trace / dump_threads should not crash and should emit something.
    mc5::diag::boot_trace("test start");
    mc5::diag::dump_threads("test");

    std::string out = run_crashing_child();
    std::fprintf(stderr, "---- captured child crash output ----\n%s\n-------------------------------------\n",
                 out.c_str());

    CHECK(out.find("MC5Offline native crash") != std::string::npos);
    CHECK(out.find("SIGSEGV") != std::string::npos);
    CHECK(out.find("#0") != std::string::npos);
    CHECK(out.find("pc=0x") != std::string::npos);
    CHECK(out.find("end backtrace") != std::string::npos);

    // BALD cache cleanup removes only trees holding our empty DLC map / toc.
    {
        char t[] = "/tmp/mc5baldXXXXXX";
        std::string root = mkdtemp(t);
        auto put = [](const std::string& p, const std::string& c) { FILE* f = std::fopen(p.c_str(), "w"); std::fputs(c.c_str(), f); std::fclose(f); };
        std::string ours = root + "/ours", real = root + "/real";
        mkdir(ours.c_str(), 0700); mkdir((ours + "/sub").c_str(), 0700); mkdir(real.c_str(), 0700);
        put(ours + "/bald___index___.txt", "1");
        put(ours + "/sub/bald_android_astc_h_map_android_dlc_1", "<dlc/>");
        put(real + "/bald___index___.txt", "7");
        put(real + "/pack_01.dlc", "real dlc content");
        CHECK(mc5::diag::remove_offline_bald_cache_in({ours, real, root + "/missing"}) == 1);
        struct stat st;
        CHECK(stat(ours.c_str(), &st) != 0);                       // ours: gone
        CHECK(stat((real + "/pack_01.dlc").c_str(), &st) == 0);     // real DLC: kept
        std::string cmd = "rm -rf '" + root + "'";
        if (std::system(cmd.c_str()) != 0) std::fprintf(stderr, "cleanup failed\n");
    }

    if (mc5test::failures() == 0) std::fprintf(stderr, "test_diag: OK\n");
    return mc5test::failures();
}
