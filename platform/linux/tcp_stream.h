#pragma once
#include <netinet/in.h>

#include <memory>
#include <string>

#include "pf/byte_stream.h"
#include "pf/framed_transport.h"

namespace pf::pal {

// Non-blocking IPv4 TCP socket as a ByteStream (TCP_NODELAY: VPN packets must not wait for Nagle).
class TcpStream : public ByteStream {
public:
    TcpStream() = default;
    ~TcpStream() override { close(); }
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    // Connects within `timeout_ms` (blocking only this call), then switches to non-blocking.
    // false + error on refusal/timeout/unreachable - the caller (fallback policy) decides what to do next.
    bool connect_to(const sockaddr_in& peer, uint32_t timeout_ms, std::string& error);

    StreamResult read(uint8_t* buf, size_t cap) override;
    StreamResult write(const uint8_t* data, size_t len) override;
    void close() override;
    int poll_fd() const override { return fd_; }

private:
    int fd_ = -1;
};

// Connected TCP Transport (OpenVPN 2-byte length framing). nullptr + error on failure.
std::unique_ptr<Transport> open_tcp_transport(const sockaddr_in& peer, uint32_t timeout_ms, std::string& error);

}  // namespace pf::pal
