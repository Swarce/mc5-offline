#include "redirect.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <string>
#include <thread>

#include "../../server/core/log.hpp"
#include "gothook.hpp"

namespace mc5 {

namespace {

std::atomic<int> g_http_port{51780};
std::atomic<int> g_tls_port{51443};

bool contains_ci(const char* hay, const char* needle) {
    if (!hay) return false;
    std::string h(hay);
    for (char& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return h.find(needle) != std::string::npos;
}

// getaddrinfo wrapper: Gameloft hosts resolve to loopback; everything else is
// passed through to the real resolver (which we reach directly — only libMC5's
// GOT is hooked, not ours).
int my_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints,
                   struct addrinfo** res) {
    if (node && (contains_ci(node, "gameloft") || contains_ci(node, "ecomapis"))) {
        logd("redirect: getaddrinfo(%s) -> 127.0.0.1", node);
        return ::getaddrinfo("127.0.0.1", service, hints, res);
    }
    return ::getaddrinfo(node, service, hints, res);
}

// connect wrapper: a connect to loopback :80/:443 is sent to our HTTP/TLS port.
int my_connect(int fd, const struct sockaddr* addr, socklen_t len) {
    if (addr && addr->sa_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const sockaddr_in* in = reinterpret_cast<const sockaddr_in*>(addr);
        if (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            uint16_t port = ntohs(in->sin_port);
            int target = 0;
            if (port == 443) target = g_tls_port.load();
            else if (port == 80) target = g_http_port.load();
            if (target != 0) {
                sockaddr_in red = *in;
                red.sin_port = htons(static_cast<uint16_t>(target));
                logd("redirect: connect 127.0.0.1:%u -> :%d", port, target);
                return ::connect(fd, reinterpret_cast<sockaddr*>(&red), sizeof(red));
            }
        }
    }
    return ::connect(fd, addr, len);
}

void install_now() {
    int n1 = got_hook("libMC5.so", "getaddrinfo", reinterpret_cast<void*>(my_getaddrinfo), nullptr);
    int n2 = got_hook("libMC5.so", "connect", reinterpret_cast<void*>(my_connect), nullptr);
    logi("redirect: hooks installed (getaddrinfo x%d, connect x%d); http=%d tls=%d",
         n1, n2, g_http_port.load(), g_tls_port.load());
    if (n1 == 0 || n2 == 0)
        logw("redirect: a hook did not patch (getaddrinfo=%d connect=%d) — the client may reach Gameloft directly", n1, n2);
}

} // namespace

void start_redirect_installer(int http_port, int tls_port) {
    g_http_port.store(http_port);
    g_tls_port.store(tls_port);
    std::thread([] {
        // Our library loads before the game loads libMC5; wait for it to appear.
        for (int i = 0; i < 1200; ++i) { // up to ~60s at 50ms
            if (so_loaded("libMC5.so")) {
                install_now();
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        logw("redirect: libMC5.so not seen within timeout; hooks not installed");
    }).detach();
}

} // namespace mc5
