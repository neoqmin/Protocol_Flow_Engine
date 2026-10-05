#include "pf/crypto/tls_session.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace pf {
namespace {

template <typename T, void (*F)(T*)> struct Free { void operator()(T* p) const { F(p); } };
using BioPtr = std::unique_ptr<BIO, Free<BIO, BIO_free_all>>;
using CertPtr = std::unique_ptr<X509, Free<X509, X509_free>>;
using KeyPtr = std::unique_ptr<EVP_PKEY, Free<EVP_PKEY, EVP_PKEY_free>>;

std::string last_openssl_error() {
    unsigned long e = ERR_get_error();
    if (e == 0) return "unknown TLS error";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

// Reads every certificate of a PEM bundle (first one = leaf for identities).
std::vector<CertPtr> read_certs(const std::string& pem) {
    std::vector<CertPtr> out;
    BioPtr b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!b) return out;
    while (CertPtr c{PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr)}) out.push_back(std::move(c));
    ERR_clear_error();   // the final "no start line" is the normal end of the bundle
    return out;
}

}  // namespace

struct TlsSession::Impl {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;          // owns rbio/wbio
    BIO* wbio = nullptr;         // borrowed from ssl
    BIO* rbio = nullptr;
    State state = State::Handshaking;
    std::string reason;

    ~Impl() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
    }

    void fail(const std::string& why) {
        state = State::Failed;
        if (reason.empty()) reason = why;
    }
};

TlsSession::TlsSession() : impl_(new Impl) {}
TlsSession::~TlsSession() = default;

std::unique_ptr<TlsSession> TlsSession::create(const TlsConfig& cfg, std::string& error) {
    ERR_clear_error();
    if (cfg.ca_pem.empty()) { error = "no trust anchors (ca_pem is empty)"; return nullptr; }
    if (cfg.role == TlsRole::Server && (cfg.cert_pem.empty() || cfg.key_pem.empty())) {
        error = "a server needs a certificate and private key"; return nullptr;
    }
    if (cfg.cert_pem.empty() != cfg.key_pem.empty()) { error = "certificate and key must be given together"; return nullptr; }

    std::unique_ptr<TlsSession> s(new TlsSession);
    Impl& m = *s->impl_;
    m.ctx = SSL_CTX_new(TLS_method());
    if (!m.ctx) { error = last_openssl_error(); return nullptr; }

    const int min_ver = (cfg.tls13_only && !cfg.cap_at_tls12) ? TLS1_3_VERSION : TLS1_2_VERSION;
    const int max_ver = cfg.cap_at_tls12 ? TLS1_2_VERSION : TLS1_3_VERSION;
    if (SSL_CTX_set_min_proto_version(m.ctx, min_ver) != 1 || SSL_CTX_set_max_proto_version(m.ctx, max_ver) != 1) {
        error = last_openssl_error(); return nullptr;
    }
    SSL_CTX_set_options(m.ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_num_tickets(m.ctx, 0);

    // Trust anchors.
    auto cas = read_certs(cfg.ca_pem);
    if (cas.empty()) { error = "ca_pem contains no certificate"; return nullptr; }
    X509_STORE* store = SSL_CTX_get_cert_store(m.ctx);
    for (auto& ca : cas)
        if (X509_STORE_add_cert(store, ca.get()) != 1) { error = last_openssl_error(); return nullptr; }

    // Our identity.
    if (!cfg.cert_pem.empty()) {
        auto chain = read_certs(cfg.cert_pem);
        if (chain.empty()) { error = "cert_pem contains no certificate"; return nullptr; }
        if (SSL_CTX_use_certificate(m.ctx, chain[0].get()) != 1) { error = last_openssl_error(); return nullptr; }
        for (size_t i = 1; i < chain.size(); ++i)
            if (SSL_CTX_add_extra_chain_cert(m.ctx, chain[i].get()) == 1) (void)chain[i].release();   // ctx owns it now
        BioPtr kb(BIO_new_mem_buf(cfg.key_pem.data(), static_cast<int>(cfg.key_pem.size())));
        KeyPtr key(kb ? PEM_read_bio_PrivateKey(kb.get(), nullptr, nullptr, nullptr) : nullptr);
        if (!key) { error = "private key is not valid PEM"; ERR_clear_error(); return nullptr; }
        if (SSL_CTX_use_PrivateKey(m.ctx, key.get()) != 1 || SSL_CTX_check_private_key(m.ctx) != 1) {
            error = "private key does not match the certificate"; ERR_clear_error(); return nullptr;
        }
    }

    // Peer verification: always on. The servers insists on a client certificate.
    int mode = SSL_VERIFY_PEER;
    if (cfg.role == TlsRole::Server) mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(m.ctx, mode, nullptr);
    const int purpose = !cfg.require_peer_eku ? X509_PURPOSE_ANY
                        : (cfg.role == TlsRole::Client ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT);
    if (SSL_CTX_set_purpose(m.ctx, purpose) != 1) { error = last_openssl_error(); return nullptr; }

    m.ssl = SSL_new(m.ctx);
    if (!m.ssl) { error = last_openssl_error(); return nullptr; }
    BIO* rb = BIO_new(BIO_s_mem());
    BIO* wb = BIO_new(BIO_s_mem());
    if (!rb || !wb) { BIO_free(rb); BIO_free(wb); error = last_openssl_error(); return nullptr; }
    BIO_set_mem_eof_return(rb, -1);       // empty input = "try again", not end of stream
    SSL_set_bio(m.ssl, rb, wb);           // ownership moves to ssl
    m.rbio = rb; m.wbio = wb;
    if (cfg.role == TlsRole::Client) SSL_set_connect_state(m.ssl); else SSL_set_accept_state(m.ssl);
    return s;
}

void TlsSession::feed(const uint8_t* data, size_t len) {
    if (len == 0 || impl_->state == State::Failed) return;
    BIO_write(impl_->rbio, data, static_cast<int>(len));
}

std::vector<uint8_t> TlsSession::take_output() {
    std::vector<uint8_t> out;
    const size_t n = static_cast<size_t>(BIO_ctrl_pending(impl_->wbio));
    if (n == 0) return out;
    out.resize(n);
    const int got = BIO_read(impl_->wbio, out.data(), static_cast<int>(n));
    out.resize(got > 0 ? static_cast<size_t>(got) : 0);
    return out;
}

TlsSession::State TlsSession::step() {
    Impl& m = *impl_;
    if (m.state != State::Handshaking) return m.state;
    ERR_clear_error();
    const int r = SSL_do_handshake(m.ssl);
    if (r == 1) { m.state = State::Established; return m.state; }
    const int err = SSL_get_error(m.ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return m.state;

    std::string why = last_openssl_error();
    const long vr = SSL_get_verify_result(m.ssl);
    if (vr != X509_V_OK) why += std::string(" (certificate: ") + X509_verify_cert_error_string(vr) + ")";
    m.fail(why);
    return m.state;
}

TlsSession::State TlsSession::state() const { return impl_->state; }

bool TlsSession::write(const uint8_t* data, size_t len) {
    Impl& m = *impl_;
    if (m.state != State::Established || len > 0x7FFFFFFF) return false;
    if (len == 0) return true;
    ERR_clear_error();
    return SSL_write(m.ssl, data, static_cast<int>(len)) == static_cast<int>(len);
}

std::vector<uint8_t> TlsSession::read() {
    Impl& m = *impl_;
    std::vector<uint8_t> out;
    if (m.state != State::Established) return out;
    uint8_t buf[16384];
    for (;;) {
        ERR_clear_error();
        const int n = SSL_read(m.ssl, buf, sizeof buf);
        if (n > 0) { out.insert(out.end(), buf, buf + n); continue; }
        const int err = SSL_get_error(m.ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_ZERO_RETURN)
            m.fail(last_openssl_error());
        break;
    }
    return out;
}

bool TlsSession::export_keying_material(std::string_view label, const uint8_t* context, size_t context_len,
                                        uint8_t* out, size_t out_len) const {
    if (impl_->state != State::Established) return false;
    return SSL_export_keying_material(impl_->ssl, out, out_len, label.data(), label.size(), context, context_len,
                                      context != nullptr ? 1 : 0) == 1;
}

std::string TlsSession::protocol_version() const { return SSL_get_version(impl_->ssl); }
std::string TlsSession::failure_reason() const { return impl_->reason; }

}  // namespace pf
