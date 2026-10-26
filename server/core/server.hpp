// The MC5 Offline Federation server: a Router plus a threaded TCP listener that
// parses HTTP/1.1 and dispatches to it. Transport is abstracted (Conn) so a TLS
// layer can wrap the socket on loopback (M0.3) without touching the HTTP code.
//
// C++17.
#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "http.hpp"

namespace mc5 {

// A byte-stream connection. FdConn is plain TCP; a TlsConn will implement the
// same interface over the same fd later.
class Conn {
public:
    virtual ~Conn() = default;
    virtual long read(char* buf, std::size_t n) = 0;
    virtual long write(const char* buf, std::size_t n) = 0;
    virtual void close() = 0;
};

struct ServerConfig {
    std::string bind = "127.0.0.1";
    int port = 51780;
    int backlog = 64;
    int worker_threads = 4;
};

class Server {
public:
    explicit Server(ServerConfig cfg) : cfg_(std::move(cfg)) {}
    ~Server() { stop(); }

    Router& router() { return router_; }
    const ServerConfig& config() const { return cfg_; }

    // Binds and starts accepting on a background thread. Returns false if the
    // listen socket could not be opened (port in use, permission).
    bool start();
    void stop();

    // Blocks until stop() is called; used by the standalone host.
    void wait();

    // Handle one already-connected Conn to completion (keep-alive loop). Public
    // so a future TLS acceptor can reuse the HTTP state machine.
    void serve_conn(Conn& c, const std::string& peer);

private:
    void accept_loop();

    ServerConfig cfg_;
    Router router_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

} // namespace mc5
