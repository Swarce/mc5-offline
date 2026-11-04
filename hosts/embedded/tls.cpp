#include "tls.hpp"

#include <unistd.h>

#include <cstring>
#include <mutex>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "../../server/core/log.hpp"
#include "tls_cert.hpp"

namespace mc5 {
namespace {

// ctr_drbg is shared across connection threads; mbedTLS only guards it when
// built with threading. Rather than reconfigure mbedTLS, wrap the RNG with our
// own mutex and hand that wrapper to mbedTLS — the only shared mutable state the
// handshake/signing touches. I/O (read/write) stays lock-free per connection.
std::mutex g_rng_mu;
mbedtls_ctr_drbg_context* g_drbg = nullptr;

int locked_rng(void* p, unsigned char* out, std::size_t len) {
    std::lock_guard<std::mutex> g(g_rng_mu);
    return mbedtls_ctr_drbg_random(p, out, len);
}

// mbedTLS internal debug -> logcat, so a failed handshake says why (chosen
// version/cipher, the alert received, how far it got).
void tls_dbg(void*, int level, const char*, int, const char* str) {
    std::size_t n = std::strlen(str);
    if (n && str[n - 1] == '\n') --n;
    char buf[256];
    if (n > sizeof(buf) - 1) n = sizeof(buf) - 1;
    std::memcpy(buf, str, n);
    buf[n] = '\0';
    logd("mbedtls(%d): %s", level, buf);
}

// Process-wide server TLS context (cert, key, config), built once.
struct TlsServer {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_ssl_config conf;
    bool ok = false;

    TlsServer() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_x509_crt_init(&cert);
        mbedtls_pk_init(&key);
        mbedtls_ssl_config_init(&conf);
        g_drbg = &drbg;

        const char* pers = "mc5offline-tls";
        int r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                      reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
        if (r != 0) { loge("tls: ctr_drbg_seed failed -0x%04x", -r); return; }

        r = mbedtls_x509_crt_parse(&cert, reinterpret_cast<const unsigned char*>(kTlsCertPem),
                                   std::strlen(kTlsCertPem) + 1);
        if (r != 0) { loge("tls: cert parse failed -0x%04x", -r); return; }

        r = mbedtls_pk_parse_key(&key, reinterpret_cast<const unsigned char*>(kTlsKeyPem),
                                 std::strlen(kTlsKeyPem) + 1, nullptr, 0, locked_rng, &drbg);
        if (r != 0) { loge("tls: key parse failed -0x%04x", -r); return; }

        r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (r != 0) { loge("tls: config_defaults failed -0x%04x", -r); return; }

        mbedtls_ssl_conf_rng(&conf, locked_rng, &drbg);
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // no client cert
        // Force TLS 1.2: universally supported by this era of client, and avoids
        // any 1.3-only negotiation quirks while we bring the transport up.
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        // Log handshake internals so a reset/alert is explained in logcat.
        mbedtls_ssl_conf_dbg(&conf, tls_dbg, nullptr);
        mbedtls_debug_set_threshold(3);
        r = mbedtls_ssl_conf_own_cert(&conf, &cert, &key);
        if (r != 0) { loge("tls: conf_own_cert failed -0x%04x", -r); return; }

        ok = true;
        logi("tls: loopback TLS context ready (self-signed, verify-none)");
    }
};

TlsServer& server() {
    static TlsServer s;
    return s;
}

// A TLS-terminating connection over an accepted fd.
class TlsConn : public Conn {
public:
    explicit TlsConn(int fd) : fd_(fd) {
        mbedtls_ssl_init(&ssl_);
        mbedtls_net_init(&net_);
        net_.fd = fd;

        if (mbedtls_ssl_setup(&ssl_, &server().conf) != 0) { loge("tls: ssl_setup failed"); return; }
        mbedtls_ssl_set_bio(&ssl_, &net_, mbedtls_net_send, mbedtls_net_recv, nullptr);

        int r;
        while ((r = mbedtls_ssl_handshake(&ssl_)) != 0) {
            if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) {
                logw("tls: handshake failed -0x%04x", -r);
                return;
            }
        }
        ok_ = true;
    }

    ~TlsConn() override {
        close();
        mbedtls_ssl_free(&ssl_);
    }

    bool ok() const { return ok_; }

    long read(char* buf, std::size_t n) override {
        for (;;) {
            int r = mbedtls_ssl_read(&ssl_, reinterpret_cast<unsigned char*>(buf), n);
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
            if (r < 0) return -1;
            return r;
        }
    }

    long write(const char* buf, std::size_t n) override {
        std::size_t sent = 0;
        while (sent < n) {
            int r = mbedtls_ssl_write(&ssl_, reinterpret_cast<const unsigned char*>(buf) + sent, n - sent);
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r <= 0) return -1;
            sent += static_cast<std::size_t>(r);
        }
        return static_cast<long>(sent);
    }

    void close() override {
        if (fd_ >= 0) {
            mbedtls_ssl_close_notify(&ssl_);
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_;
    bool ok_ = false;
    mbedtls_ssl_context ssl_;
    mbedtls_net_context net_;
};

} // namespace

std::unique_ptr<Conn> tls_upgrade(int fd) {
    // tls_upgrade owns fd: on any failure it closes fd and returns null, so the
    // caller must NOT close fd when null comes back.
    if (!server().ok) {
        loge("tls: server context not ready; dropping TLS connection");
        ::close(fd);
        return nullptr;
    }
    auto c = std::make_unique<TlsConn>(fd); // ~TlsConn closes fd if handshake failed
    if (!c->ok()) return nullptr;
    return c;
}

} // namespace mc5
