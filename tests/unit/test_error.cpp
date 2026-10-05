#include <cstring>
#include "pf/error.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(error_none_is_zero_and_falsy_by_helper) {
    PF_CHECK_EQ(static_cast<int>(Error::None), 0);
    PF_CHECK(!is_error(Error::None));
    PF_CHECK(is_error(Error::Truncated));
}

PF_TEST(every_error_has_a_distinct_nonempty_name) {
    for (size_t i = 0; i < kErrorCount; ++i) {
        const char* n = error_name(static_cast<Error>(i));
        PF_REQUIRE(n != nullptr);
        PF_CHECK(std::strlen(n) > 0);
        for (size_t j = i + 1; j < kErrorCount; ++j)
            PF_CHECK(std::strcmp(n, error_name(static_cast<Error>(j))) != 0);
    }
}

PF_TEST(out_of_range_error_name_is_safe) {
    PF_CHECK(std::strcmp(error_name(static_cast<Error>(60000)), "Unknown") == 0);
}
