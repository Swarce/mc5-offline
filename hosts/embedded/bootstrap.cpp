// Embedded bootstrap: the entry point of libmc5offline.so inside the game process.
//
// The patched game loads this library (M0.4 makes MainActivity load it before
// libMC5). On load it starts the Federation server on its own thread and logs to
// logcat. The native GOT hooks and loopback TLS that make the game actually talk
// to it arrive in M0.3; until then loading the library proves the server boots in
// the process and surfaces in logcat.
//
// Exposes both a C entry point (mc5offline_start, for the hook/patcher to call)
// and a JNI method (for an injected Java call), and also self-starts on load so a
// bare System.loadLibrary boots it. Starting is idempotent.
//
// C++17.
#include <jni.h>

#include <atomic>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <string>

#include "../../server/core/log.hpp"
#include "../../server/core/server.hpp"
#include "../../server/services/services.hpp"
#include "diag.hpp"
#include "redirect.hpp"
#include "tls.hpp"

namespace {

std::mutex g_mu;
std::unique_ptr<mc5::Server> g_server;
std::unique_ptr<mc5::ServerContext> g_ctx;
std::atomic<bool> g_started{false};

// Unlock-code item lists read from the game's memory (patch.cpp, game thread) -> the save.
void on_item_lists(const std::map<std::string, std::vector<std::string>>& groups, const char* source) {
    if (!g_ctx) return;
    mc5::ItemUniverse u;
    u.groups = groups;
    u.source = std::string("in-game dump at ") + (source ? source : "?");
    g_ctx->progress.set_universe(std::move(u));
}

void start_locked(const std::string& data_dir) {
    if (g_started.load()) return;

    // Diagnostics first, so a crash during server/hook setup is still reported.
    mc5::diag::init(data_dir);
    mc5::diag::boot_trace("server starting");

    g_ctx = std::make_unique<mc5::ServerContext>();
    // Serve the game over loopback. scheme=https: the native Gaia rewrites its
    // service URLs http->https at runtime and expects https, so the URLs we hand
    // out in eve config / pandora locate must be https (our one listener on 51780
    // auto-detects TLS vs plain, so https on :51780 is served fine). Giving it
    // http URLs made OpenSession reject the config (the "connection error" popup).
    g_ctx->public_host = "127.0.0.1";
    g_ctx->port = 51780;
    g_ctx->scheme = "https";
    // The player's save (profile/progression, redeemed codes, settings.json) lives
    // next to the log copy: <files>/MC5Offline (pullable with adb on most devices).
    {
        std::string base = !data_dir.empty() ? data_dir : mc5::diag::data_dir();
        if (!base.empty() && base.back() == '/') base.pop_back();
        g_ctx->progress.open(base.empty() ? std::string() : base + "/MC5Offline");
        mc5::diag::boot_trace("save loaded");
        if (!g_ctx->progress.settings()["bald"]["serve"].as_bool(false)) mc5::diag::remove_offline_bald_cache();
    }

    mc5::ServerConfig cfg;
    cfg.bind = "127.0.0.1";
    cfg.port = g_ctx->port;
    g_server = std::make_unique<mc5::Server>(cfg);
    mc5::register_services(g_server->router(), *g_ctx);
    // Terminate TLS on the same loopback port: the game speaks HTTPS to its
    // backend hosts and to our redirect, so the listener auto-detects a TLS
    // ClientHello and wraps the fd. The client doesn't verify certs.
    g_server->set_tls_upgrade([](int fd) { return mc5::tls_upgrade(fd); });
    // Route non-HTTP connections (the Anubis controller / TS meta-channel) to the
    // Federation meta handler instead of the HTTP state machine.
    g_server->set_meta_handler([](mc5::Conn& c, const std::string& peer) {
        if (g_ctx) mc5::serve_meta_conn(*g_ctx, c, peer);
    });

    if (g_server->start()) {
        g_started.store(true);
        mc5::logi("libmc5offline: server started on %s (data_dir=%s)",
                  g_ctx->base_url().c_str(), data_dir.empty() ? "(default)" : data_dir.c_str());
        mc5::diag::boot_trace("server started");
        mc5::diag::dump_threads("after server start");
        // Redirect libMC5's Gaia traffic to us once the game loads it. TLS port is
        // wired next; until then the https path is redirected but not yet served.
        mc5::start_redirect_installer(g_ctx->port, g_ctx->port, &on_item_lists); // no TLS in M0: :443 also lands on http
    } else {
        mc5::loge("libmc5offline: server failed to start");
        g_server.reset();
        g_ctx.reset();
    }
}

} // namespace

extern "C" {

// Callable from the native hook (M0.3) or any loader. data_dir may be null.
void mc5offline_start(const char* data_dir) {
    std::lock_guard<std::mutex> g(g_mu);
    start_locked(data_dir ? std::string(data_dir) : std::string());
}

// Injected Java glue (patcher, M0.4) calls this: a static native void init(String).
JNIEXPORT void JNICALL
Java_com_gameloft_android_ANMP_GloftM5HM_MC5Offline_init(JNIEnv* env, jclass, jstring data_dir) {
    std::string dir;
    if (data_dir) {
        const char* c = env->GetStringUTFChars(data_dir, nullptr);
        if (c) { dir = c; env->ReleaseStringUTFChars(data_dir, c); }
    }
    mc5offline_start(dir.c_str());
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) {
    // Install diagnostics at the earliest possible moment (before the server),
    // so even a crash during startup is captured.
    mc5::diag::init(std::string());
    mc5::diag::boot_trace("JNI_OnLoad");
    mc5::logi("libmc5offline: JNI_OnLoad");
    // Self-start so a bare System.loadLibrary boots the server even before the
    // Java init glue exists. Idempotent with the explicit entry points above.
    mc5offline_start(nullptr);
    return JNI_VERSION_1_6;
}

} // extern "C"
