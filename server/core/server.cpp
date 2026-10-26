#include "server.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.hpp"

namespace mc5 {

namespace {

// Plain TCP connection over a socket fd.
class FdConn : public Conn {
public:
    explicit FdConn(int fd) : fd_(fd) {}
    ~FdConn() override { close(); }
    long read(char* buf, std::size_t n) override { return ::recv(fd_, buf, n, 0); }
    long write(const char* buf, std::size_t n) override {
        std::size_t sent = 0;
        while (sent < n) {
            long w = ::send(fd_, buf + sent, n - sent, 0);
            if (w <= 0) return w;
            sent += static_cast<std::size_t>(w);
        }
        return static_cast<long>(sent);
    }
    void close() override {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

private:
    int fd_;
};

const char* status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 408: return "Request Timeout";
        case 500: return "Internal Server Error";
        default: return "OK";
    }
}

std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    return s;
}

// Read until the given delimiter is found in the accumulated buffer, or the
// connection closes. Returns false on EOF/error with nothing more to read.
bool read_until(Conn& c, std::string& buf, const std::string& delim, std::size_t& found_at) {
    char tmp[4096];
    while (true) {
        std::size_t pos = buf.find(delim);
        if (pos != std::string::npos) { found_at = pos; return true; }
        long r = c.read(tmp, sizeof(tmp));
        if (r <= 0) return false;
        buf.append(tmp, static_cast<std::size_t>(r));
        if (buf.size() > (1u << 20) * 8) return false; // 8 MB header guard
    }
}

bool parse_request_head(const std::string& head, Request& req) {
    std::size_t line_end = head.find("\r\n");
    if (line_end == std::string::npos) return false;
    std::string line = head.substr(0, line_end);
    std::size_t s1 = line.find(' ');
    std::size_t s2 = line.rfind(' ');
    if (s1 == std::string::npos || s2 == std::string::npos || s1 == s2) return false;
    req.method = line.substr(0, s1);
    req.raw_target = line.substr(s1 + 1, s2 - s1 - 1);

    std::size_t q = req.raw_target.find('?');
    if (q == std::string::npos) {
        req.path = url_decode(req.raw_target);
    } else {
        req.path = url_decode(req.raw_target.substr(0, q));
        req.query = req.raw_target.substr(q + 1);
        req.query_params = parse_urlencoded(req.query);
    }

    std::size_t i = line_end + 2;
    while (i < head.size()) {
        std::size_t eol = head.find("\r\n", i);
        if (eol == std::string::npos) eol = head.size();
        if (eol == i) break;
        std::string hline = head.substr(i, eol - i);
        std::size_t colon = hline.find(':');
        if (colon != std::string::npos) {
            std::string name = lower(hline.substr(0, colon));
            std::size_t v = colon + 1;
            while (v < hline.size() && (hline[v] == ' ' || hline[v] == '\t')) ++v;
            req.headers[name] = hline.substr(v);
        }
        i = eol + 2;
    }
    return true;
}

} // namespace

void Server::serve_conn(Conn& c, const std::string& peer) {
    std::string buf;
    while (running_.load()) {
        std::size_t head_end = 0;
        if (!read_until(c, buf, "\r\n\r\n", head_end)) break;
        std::string head = buf.substr(0, head_end);
        buf.erase(0, head_end + 4);

        Request req;
        if (!parse_request_head(head, req)) {
            const char* bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            c.write(bad, std::strlen(bad));
            break;
        }

        std::size_t content_length = 0;
        auto cl = req.headers.find("content-length");
        if (cl != req.headers.end()) {
            try { content_length = static_cast<std::size_t>(std::stoul(cl->second)); } catch (...) { content_length = 0; }
        }
        while (buf.size() < content_length) {
            char tmp[8192];
            long r = c.read(tmp, sizeof(tmp));
            if (r <= 0) break;
            buf.append(tmp, static_cast<std::size_t>(r));
        }
        req.body = buf.substr(0, content_length);
        buf.erase(0, content_length);

        std::string ctype = lower(req.header("content-type"));
        if (ctype.find("application/x-www-form-urlencoded") != std::string::npos) {
            req.form = parse_urlencoded(req.body);
        }

        Response resp = router_.route(req);

        logi("%s %s -> %d (%zu B)%s", req.method.c_str(), req.raw_target.c_str(), resp.status,
             resp.body.size(), peer.empty() ? "" : (" [" + peer + "]").c_str());

        bool keep_alive = lower(req.header("connection")) != "close";

        std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + status_text(resp.status) + "\r\n";
        out += "Content-Type: " + resp.content_type + "\r\n";
        out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
        for (auto& h : resp.extra_headers) out += h.first + ": " + h.second + "\r\n";
        out += keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
        out += "\r\n";
        out += resp.body;

        if (c.write(out.data(), out.size()) <= 0) break;
        if (!keep_alive) break;
    }
    c.close();
}

bool Server::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        loge("socket() failed: %s", std::strerror(errno));
        return false;
    }
    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(cfg_.port));
    if (::inet_pton(AF_INET, cfg_.bind.c_str(), &addr.sin_addr) != 1) {
        loge("bad bind address %s", cfg_.bind.c_str());
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        loge("bind %s:%d failed: %s", cfg_.bind.c_str(), cfg_.port, std::strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (::listen(listen_fd_, cfg_.backlog) < 0) {
        loge("listen failed: %s", std::strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    running_.store(true);
    accept_thread_ = std::thread([this] { accept_loop(); });
    logi("Federation server listening on %s:%d", cfg_.bind.c_str(), cfg_.port);
    return true;
}

void Server::accept_loop() {
    while (running_.load()) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (fd < 0) {
            if (!running_.load()) break;
            if (errno == EINTR) continue;
            continue;
        }
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        char ip[64] = {0};
        ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        std::string peer_str = std::string(ip) + ":" + std::to_string(ntohs(peer.sin_port));
        // One thread per connection; Gaia keeps few concurrent connections.
        std::thread([this, fd, peer_str] {
            FdConn c(fd);
            serve_conn(c, peer_str);
        }).detach();
    }
}

void Server::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) accept_thread_.join();
}

void Server::wait() {
    if (accept_thread_.joinable()) accept_thread_.join();
}

} // namespace mc5
