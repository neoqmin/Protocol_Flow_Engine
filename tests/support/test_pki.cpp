#include "test_pki.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <stdexcept>

namespace pf_test {
namespace {

template <typename T, void (*F)(T*)> struct Free { void operator()(T* p) const { F(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, Free<EVP_PKEY, EVP_PKEY_free>>;
using Cert = std::unique_ptr<X509, Free<X509, X509_free>>;
using Mem = std::unique_ptr<BIO, Free<BIO, BIO_free_all>>;

void check(bool ok, const char* what) { if (!ok) throw std::runtime_error(std::string("test_pki: ") + what); }

Pkey new_key() {
    Pkey k(EVP_EC_gen("P-256"));
    check(k != nullptr, "EC keygen");
    return k;
}

void add_ext(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    check(e != nullptr, "extension");
    X509_add_ext(cert, e, -1);
    X509_EXTENSION_free(e);
}

// issuer == nullptr => self-signed CA.
Cert make_cert(const char* cn, EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key, const char* eku) {
    Cert c(X509_new());
    check(c != nullptr, "X509_new");
    X509_set_version(c.get(), 2);
    static long serial = 1000;
    ASN1_INTEGER_set(X509_get_serialNumber(c.get()), serial++);
    X509_gmtime_adj(X509_getm_notBefore(c.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(c.get()), 3600);
    X509_set_pubkey(c.get(), key);
    X509_NAME* name = X509_get_subject_name(c.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(c.get(), issuer ? X509_get_subject_name(issuer) : name);
    if (issuer == nullptr) {
        add_ext(c.get(), nullptr, NID_basic_constraints, "critical,CA:TRUE");
        add_ext(c.get(), nullptr, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_ext(c.get(), issuer, NID_basic_constraints, "CA:FALSE");
        add_ext(c.get(), issuer, NID_key_usage, "critical,digitalSignature");
        add_ext(c.get(), issuer, NID_ext_key_usage, eku);
    }
    check(X509_sign(c.get(), issuer ? issuer_key : key, EVP_sha256()) > 0, "sign");
    return c;
}

std::string cert_pem(X509* c) {
    Mem b(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(b.get(), c);
    char* p = nullptr; long n = BIO_get_mem_data(b.get(), &p);
    return std::string(p, static_cast<size_t>(n));
}

std::string key_pem(EVP_PKEY* k) {
    Mem b(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(b.get(), k, nullptr, nullptr, 0, nullptr, nullptr);
    char* p = nullptr; long n = BIO_get_mem_data(b.get(), &p);
    return std::string(p, static_cast<size_t>(n));
}

}  // namespace

TestPki make_test_pki() {
    TestPki t;
    Pkey ca_key = new_key(), srv_key = new_key(), cli_key = new_key(), bad_key = new_key();
    Pkey oca_key = new_key(), osrv_key = new_key();
    Cert ca = make_cert("pf-test-ca", ca_key.get(), nullptr, nullptr, nullptr);
    Cert srv = make_cert("pf-server", srv_key.get(), ca.get(), ca_key.get(), "serverAuth");
    Cert cli = make_cert("pf-client", cli_key.get(), ca.get(), ca_key.get(), "clientAuth");
    Cert bad = make_cert("pf-wrong-eku", bad_key.get(), ca.get(), ca_key.get(), "clientAuth");
    Cert oca = make_cert("pf-other-ca", oca_key.get(), nullptr, nullptr, nullptr);
    Cert osrv = make_cert("pf-other-server", osrv_key.get(), oca.get(), oca_key.get(), "serverAuth");
    t.ca_pem = cert_pem(ca.get());
    t.server_cert_pem = cert_pem(srv.get()); t.server_key_pem = key_pem(srv_key.get());
    t.client_cert_pem = cert_pem(cli.get()); t.client_key_pem = key_pem(cli_key.get());
    t.wrong_eku_server_cert_pem = cert_pem(bad.get()); t.wrong_eku_server_key_pem = key_pem(bad_key.get());
    t.other_ca_pem = cert_pem(oca.get());
    t.other_server_cert_pem = cert_pem(osrv.get()); t.other_server_key_pem = key_pem(osrv_key.get());
    return t;
}

}  // namespace pf_test
