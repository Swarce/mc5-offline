// Standalone desktop host for the MC5 Offline Federation server.
//
// Used for the development loop and for later LAN/VPS hosting: it runs the same
// server the embedded build runs, over plain HTTP, so requests can be watched and
// the protocol worked out before anything touches a device.
//
//   mc5-offline-standalone [--port N] [--bind ADDR] [--public-host H]
//                          [--scheme http|https] [--data-center DC] [--log-level L]
//
// C++17.
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../../server/core/log.hpp"
#include "../../server/core/server.hpp"
#include "../../server/services/services.hpp"

namespace {
std::atomic<mc5::Server*> g_server{nullptr};

void on_signal(int) {
    mc5::Server* s = g_server.load();
    if (s) s->stop();
}

mc5::LogLevel parse_level(const std::string& v) {
    if (v == "debug") return mc5::LogLevel::Debug;
    if (v == "info") return mc5::LogLevel::Info;
    if (v == "warn") return mc5::LogLevel::Warn;
    if (v == "error") return mc5::LogLevel::Error;
    return mc5::LogLevel::Debug;
}
} // namespace

int main(int argc, char** argv) {
    mc5::ServerConfig cfg;
    mc5::ServerContext ctx;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def) -> std::string {
            return (i + 1 < argc) ? std::string(argv[++i]) : std::string(def);
        };
        if (a == "--port") { cfg.port = std::atoi(next("51780").c_str()); ctx.port = cfg.port; }
        else if (a == "--bind") cfg.bind = next("127.0.0.1");
        else if (a == "--public-host") ctx.public_host = next("127.0.0.1");
        else if (a == "--scheme") ctx.scheme = next("http");
        else if (a == "--data-center") ctx.data_center = next("mc5");
        else if (a == "--client-id") ctx.client_id = next(ctx.client_id.c_str());
        else if (a == "--log-level") mc5::Log::instance().set_min_level(parse_level(next("debug")));
        else if (a == "--help") {
            std::puts("mc5-offline-standalone [--port N] [--bind ADDR] [--public-host H] "
                      "[--scheme http|https] [--data-center DC] [--client-id ID] [--log-level L]");
            return 0;
        }
    }

    mc5::Server server(cfg);
    mc5::register_services(server.router(), ctx);

    g_server.store(&server);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (!server.start()) {
        mc5::loge("failed to start server");
        return 1;
    }
    mc5::logi("standalone host ready; base URL %s", ctx.base_url().c_str());
    server.wait();
    mc5::logi("standalone host stopped");
    return 0;
}
