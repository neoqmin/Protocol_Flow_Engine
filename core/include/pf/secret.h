#pragma once
#include <cstddef>
#include <cstring>
#include <memory>
#include <string_view>

#include "pf/secure_mem.h"

namespace pf {

// A password or similar secret held in memory (D-048). Its own buffer is wiped on destruction and when moved from;
// it cannot be copied, printed or compared by accident. reveal() is the one place the bytes come out: use it only
// where they must go (a constant-time comparison, a 0600 file for an auth hook), never into logs or traces.
class SecretString {
public:
    SecretString() = default;
    explicit SecretString(std::string_view s) : len_(s.size()) {
        if (len_ == 0) return;
        buf_.reset(new char[len_]);
        std::memcpy(buf_.get(), s.data(), len_);
    }
    SecretString(SecretString&& o) noexcept : buf_(std::move(o.buf_)), len_(o.len_) { o.len_ = 0; }
    SecretString& operator=(SecretString&& o) noexcept {
        if (this != &o) { wipe(); buf_ = std::move(o.buf_); len_ = o.len_; o.len_ = 0; }
        return *this;
    }
    SecretString(const SecretString&) = delete;
    SecretString& operator=(const SecretString&) = delete;
    ~SecretString() { wipe(); }

    size_t size() const { return len_; }
    bool empty() const { return len_ == 0; }
    std::string_view reveal() const { return {buf_.get(), len_}; }
    void wipe() {
        if (buf_) secure_zero(buf_.get(), len_);
        buf_.reset();
        len_ = 0;
    }

private:
    std::unique_ptr<char[]> buf_;
    size_t len_ = 0;
};

}  // namespace pf
