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
#include <memory>
#include <mutex>
#include <string>

#include "../../server/core/log.hpp"
#include "../../server/core/server.hpp"
#include "../../server/services/services.hpp"
#include "redirect.hpp"

namespace {

std::mutex g_mu;
std::unique_ptr<mc5::Server> g_server;
std::unique_ptr<mc5::ServerContext> g_ctx;
std::atomic<bool> g_started{false};

void start_locked(const std::string& data_dir) {
    if (g_started.load()) return;

    g_ctx = std::make_unique<mc5::ServerContext>();
    // Embedded build serves the game over loopback. TLS (scheme https) is wired in
    // M0.3; until then the server listens plain and is only reached by our tools.
    g_ctx->public_host = "127.0.0.1";
    g_ctx->port = 51780;
    g_ctx->scheme = "http";

    mc5::ServerConfig cfg;
    cfg.bind = "127.0.0.1";
    cfg.port = g_ctx->port;
    g_server = std::make_unique<mc5::Server>(cfg);
    mc5::register_services(g_server->router(), *g_ctx);

    if (g_server->start()) {
        g_started.store(true);
        mc5::logi("libmc5offline: server started on %s (data_dir=%s)",
                  g_ctx->base_url().c_str(), data_dir.empty() ? "(default)" : data_dir.c_str());
        // Redirect libMC5's Gaia traffic to us once the game loads it. TLS port is
        // wired next; until then the https path is redirected but not yet served.
        mc5::start_redirect_installer(g_ctx->port, 51443);
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
    mc5::logi("libmc5offline: JNI_OnLoad");
    // Self-start so a bare System.loadLibrary boots the server even before the
    // Java init glue exists. Idempotent with the explicit entry points above.
    mc5offline_start(nullptr);
    return JNI_VERSION_1_6;
}

} // extern "C"
