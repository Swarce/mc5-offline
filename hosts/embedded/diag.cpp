#include "diag.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "../../server/core/log.hpp"

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace mc5 {
namespace diag {
namespace {

std::atomic<bool> g_inited{false};
struct timespec g_boot{};

long now_ms_since_boot() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec - g_boot.tv_sec) * 1000L + (ts.tv_nsec - g_boot.tv_nsec) / 1000000L;
}

pid_t self_tid() { return static_cast<pid_t>(syscall(__NR_gettid)); }

// ---- async-signal-safe output ---------------------------------------------
//
// The crash handler must avoid malloc / stdio / locks. It builds each line in a
// fixed stack buffer and writes it with raw write() plus a best-effort
// __android_log_write.

class SafeBuf {
public:
    void reset() { len_ = 0; buf_[0] = '\0'; }
    const char* c_str() { buf_[len_] = '\0'; return buf_; }
    std::size_t len() const { return len_; }

    SafeBuf& s(const char* str) {
        if (!str) str = "(null)";
        while (*str && len_ < kCap - 1) buf_[len_++] = *str++;
        return *this;
    }
    SafeBuf& d(long v) {
        if (v < 0) { if (len_ < kCap - 1) buf_[len_++] = '-'; v = -v; }
        char tmp[24]; int n = 0;
        if (v == 0) tmp[n++] = '0';
        while (v > 0 && n < 24) { tmp[n++] = static_cast<char>('0' + v % 10); v /= 10; }
        while (n > 0 && len_ < kCap - 1) buf_[len_++] = tmp[--n];
        return *this;
    }
    SafeBuf& h(uintptr_t v) {
        s("0x");
        char tmp[16]; int n = 0;
        if (v == 0) tmp[n++] = '0';
        while (v > 0 && n < 16) { int d = v & 0xf; tmp[n++] = static_cast<char>(d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; }
        while (n > 0 && len_ < kCap - 1) buf_[len_++] = tmp[--n];
        return *this;
    }
private:
    static constexpr std::size_t kCap = 512;
    char buf_[kCap];
    std::size_t len_ = 0;
};

void emit_line(const char* s) {
#if defined(__ANDROID__)
    __android_log_write(ANDROID_LOG_FATAL, "MC5Offline", s);
#endif
    std::size_t n = std::strlen(s);
    int fd = Log::instance().logfile_fd();
    if (fd >= 0) { (void)!write(fd, s, n); (void)!write(fd, "\n", 1); }
    (void)!write(2, s, n); (void)!write(2, "\n", 1); // stderr (desktop / adb)
}

// ---- /proc/self/maps scan (for module+offset resolution) -------------------

char g_maps[256 * 1024];
std::size_t g_maps_len = 0;

void load_maps() {
    g_maps_len = 0;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    for (;;) {
        ssize_t r = read(fd, g_maps + g_maps_len, sizeof(g_maps) - g_maps_len - 1);
        if (r <= 0) break;
        g_maps_len += static_cast<std::size_t>(r);
        if (g_maps_len >= sizeof(g_maps) - 1) break;
    }
    close(fd);
    g_maps[g_maps_len] = '\0';
}

uintptr_t parse_hex(const char* p, const char** end) {
    uintptr_t v = 0;
    while (*p) {
        char c = *p;
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | static_cast<uintptr_t>(d);
        ++p;
    }
    if (end) *end = p;
    return v;
}

// For the line of maps containing ip, return the path pointer/length and the
// module load base (min start of all lines with that same path). Returns false
// if ip is not in any mapping.
bool resolve(uintptr_t ip, const char** path, std::size_t* path_len, uintptr_t* base) {
    const char* containing_path = nullptr;
    std::size_t containing_len = 0;
    const char* line = g_maps;
    while (line < g_maps + g_maps_len && *line) {
        const char* nl = line;
        while (*nl && *nl != '\n') ++nl;
        const char* p = line;
        const char* e = nullptr;
        uintptr_t start = parse_hex(p, &e);
        uintptr_t end = 0;
        if (e && *e == '-') end = parse_hex(e + 1, nullptr);
        if (ip >= start && ip < end) {
            // path is the last field: first '/' or '[' on the line, else empty
            const char* ph = line;
            while (ph < nl && *ph != '/' && *ph != '[') ++ph;
            if (ph < nl) { containing_path = ph; containing_len = static_cast<std::size_t>(nl - ph); }
            break;
        }
        line = (*nl == '\n') ? nl + 1 : nl;
    }
    if (!containing_path) return false;

    uintptr_t min_start = UINTPTR_MAX;
    line = g_maps;
    while (line < g_maps + g_maps_len && *line) {
        const char* nl = line;
        while (*nl && *nl != '\n') ++nl;
        const char* e = nullptr;
        uintptr_t start = parse_hex(line, &e);
        const char* ph = line;
        while (ph < nl && *ph != '/' && *ph != '[') ++ph;
        std::size_t plen = (ph < nl) ? static_cast<std::size_t>(nl - ph) : 0;
        if (plen == containing_len && std::memcmp(ph, containing_path, plen) == 0) {
            if (start < min_start) min_start = start;
        }
        line = (*nl == '\n') ? nl + 1 : nl;
    }
    *path = containing_path;
    *path_len = containing_len;
    *base = (min_start == UINTPTR_MAX) ? 0 : min_start;
    return true;
}

// ---- crash handler ---------------------------------------------------------

struct BtState { uintptr_t pcs[64]; int count; };

_Unwind_Reason_Code bt_cb(struct _Unwind_Context* ctx, void* arg) {
    auto* st = static_cast<BtState*>(arg);
    uintptr_t ip = _Unwind_GetIP(ctx);
    if (ip && st->count < 64) st->pcs[st->count++] = ip;
    return (st->count >= 64) ? _URC_END_OF_STACK : _URC_NO_REASON;
}

const char* sig_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGFPE:  return "SIGFPE";
        case SIGTRAP: return "SIGTRAP";
        default:      return "signal";
    }
}

constexpr int kSigs[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};
struct sigaction g_old[8];
std::atomic<int> g_in_handler{0};

void crash_handler(int sig, siginfo_t* info, void* uctx) {
    // Guard against a fault inside the handler itself.
    if (g_in_handler.fetch_add(1) != 0) _exit(1);

    SafeBuf b;
    b.reset();
    b.s("*** MC5Offline native crash: ").s(sig_name(sig)).s(" (").d(sig).s(")");
    b.s(" code=").d(info ? info->si_code : 0);
    b.s(" addr=").h(reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr));
    b.s(" tid=").d(self_tid());
    emit_line(b.c_str());

    BtState st{};
    _Unwind_Backtrace(bt_cb, &st);
    load_maps();

    for (int i = 0; i < st.count; ++i) {
        uintptr_t pc = st.pcs[i];
        b.reset();
        b.s("  #").d(i).s(i < 10 ? "  pc=" : " pc=").h(pc);
        const char* path; std::size_t plen; uintptr_t base;
        if (resolve(pc, &path, &plen, &base)) {
            b.s("  +").h(pc - base).s("  ");
            for (std::size_t k = 0; k < plen; ++k) { char t[2] = {path[k], '\0'}; b.s(t); }
        }
        emit_line(b.c_str());
    }
    b.reset();
    b.s("*** end backtrace (offsets are module-relative: ELF vaddr = offset) ***");
    emit_line(b.c_str());

    // Chain to the previous handler so the platform tombstone/Crashlytics runs.
    for (std::size_t i = 0; i < sizeof(kSigs) / sizeof(kSigs[0]); ++i) {
        if (kSigs[i] == sig) {
            sigaction(sig, &g_old[i], nullptr);
            break;
        }
    }
    g_in_handler.store(0);
    raise(sig); // re-raise into the restored handler (platform default/next)
}

char g_altstack[64 * 1024];

void install_crash_handler() {
    stack_t ss{};
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);

    for (std::size_t i = 0; i < sizeof(kSigs) / sizeof(kSigs[0]); ++i) {
        struct sigaction sa{};
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(kSigs[i], &sa, &g_old[i]);
    }
}

// ---- watchdog ---------------------------------------------------------------

int count_threads() {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] != '.') ++n;
    }
    closedir(d);
    return n;
}

void watchdog_loop() {
    long last = 0;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        long up = now_ms_since_boot() / 1000;
        logi("[watchdog] uptime=%lds threads=%d", up, count_threads());
        // Every ~2 minutes, also dump thread states for a periodic snapshot.
        if (up - last >= 120) { last = up; dump_threads("watchdog periodic"); }
    }
}

} // namespace

void boot_trace(const char* stage) {
    logi("[boot +%ldms] %s", now_ms_since_boot(), stage);
}

void dump_threads(const char* reason) {
    DIR* d = opendir("/proc/self/task");
    if (!d) { logw("[threads] cannot open /proc/self/task"); return; }
    logi("[threads] dump (%s):", reason ? reason : "");
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        char path[300], comm[64] = {0}, stat[256] = {0};
        std::snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { ssize_t r = read(fd, comm, sizeof(comm) - 1); if (r > 0) { comm[r] = 0; for (char& c : comm) if (c == '\n') c = 0; } close(fd); }
        std::snprintf(path, sizeof(path), "/proc/self/task/%s/stat", e->d_name);
        char state = '?';
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t r = read(fd, stat, sizeof(stat) - 1);
            if (r > 0) { stat[r] = 0; const char* rp = std::strrchr(stat, ')'); if (rp && rp[1] && rp[2]) state = rp[2]; }
            close(fd);
        }
        logi("  tid=%s state=%c %s", e->d_name, state, comm);
    }
    closedir(d);
}

// Open the log-file copy at the first writable candidate. The app's external
// files dir is preferred because it can be pulled with `adb pull` on a
// non-rooted device; the internal data dir is the always-writable fallback.
void open_log_copy(const std::string& data_dir) {
    std::vector<std::string> dirs;
    if (!data_dir.empty()) dirs.push_back(data_dir);
#if defined(__ANDROID__)
    const char* kPkg = "com.gameloft.android.ANMP.GloftM5HM";
    dirs.push_back(std::string("/sdcard/Android/data/") + kPkg + "/files");
    dirs.push_back(std::string("/data/data/") + kPkg + "/files");
#endif
    for (std::string dir : dirs) {
        if (dir.empty()) continue;
        if (dir.back() == '/') dir.pop_back();
        mkdir(dir.c_str(), 0775); // best-effort; dir usually already exists
        std::string path = dir + "/mc5offline.log";
        Log::instance().set_logfile(path);
        if (!Log::instance().logfile_path().empty()) {
            logi("[diag] log copy: %s (adb pull this)", Log::instance().logfile_path().c_str());
            return;
        }
    }
    logw("[diag] no writable log-file location; logcat only");
}

void init(const std::string& data_dir) {
    bool expected = false;
    if (!g_inited.compare_exchange_strong(expected, true)) return;
    clock_gettime(CLOCK_MONOTONIC, &g_boot);

    open_log_copy(data_dir);
    install_crash_handler();
    boot_trace("diagnostics ready (crash handler + watchdog)");
    std::thread(watchdog_loop).detach();
}

} // namespace diag
} // namespace mc5
