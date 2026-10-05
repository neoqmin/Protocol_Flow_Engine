// Test-only PKI generated at run time with OpenSSL (EC P-256, short lived). Nothing is stored on disk,
// so no private key ever needs to be committed. Needs OpenSSL.
#pragma once
#include <string>

namespace pf_test {

struct TestPki {
    std::string ca_pem;
    std::string server_cert_pem, server_key_pem;      // EKU serverAuth, KU digitalSignature
    std::string client_cert_pem, client_key_pem;      // EKU clientAuth, KU digitalSignature
    std::string wrong_eku_server_cert_pem, wrong_eku_server_key_pem;   // signed by ca, EKU clientAuth only
    std::string other_ca_pem;                          // an unrelated CA
    std::string other_server_cert_pem, other_server_key_pem;           // signed by other_ca
};

// Throws std::runtime_error on failure.
TestPki make_test_pki();

}  // namespace pf_test
