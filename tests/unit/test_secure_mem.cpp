#include "pf/secure_mem.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(secure_zero_clears_bytes) {
    uint8_t buf[16];
    for (auto& b : buf) b = 0xAA;
    secure_zero(buf, sizeof buf);
    for (auto b : buf) PF_CHECK_EQ(b, 0);
}

PF_TEST(secure_zero_handles_null_and_zero_length) {
    secure_zero(nullptr, 0);
    uint8_t b = 7;
    secure_zero(&b, 0);
    PF_CHECK_EQ(b, 7);
}

PF_TEST(constant_time_equal_matches_memcmp_semantics) {
    const uint8_t a[] = {1, 2, 3, 4}, b[] = {1, 2, 3, 4}, c[] = {1, 2, 3, 5}, d[] = {9, 2, 3, 4};
    PF_CHECK(ct_equal(a, b, 4));
    PF_CHECK(!ct_equal(a, c, 4));
    PF_CHECK(!ct_equal(a, d, 4));
    PF_CHECK(ct_equal(a, c, 3));      // only first 3 bytes compared
    PF_CHECK(ct_equal(a, c, 0));
}

#include "pf/secret.h"

PF_TEST(secret_string_holds_moves_and_wipes) {
    pf::SecretString a("hunter2");
    PF_CHECK_EQ(a.size(), size_t{7});
    PF_CHECK(a.reveal() == "hunter2");
    pf::SecretString b(std::move(a));
    PF_CHECK(a.empty());                                   // the source no longer holds it
    PF_CHECK(a.reveal().empty());
    PF_CHECK(b.reveal() == "hunter2");
    pf::SecretString c;
    c = std::move(b);
    PF_CHECK(b.empty());
    PF_CHECK(c.reveal() == "hunter2");
    c.wipe();
    PF_CHECK(c.empty());
    PF_CHECK(pf::SecretString("").empty());
}
