#pragma once
#include <netinet/in.h>

#include <string>

#include "pf/transport.h"

namespace pf::pal {

// UDP Transport on a connected, non-blocking IPv4 socket: one OpenVPN packet = one datagram.
class UdpTransport : public Transport {
public:
    UdpTransport() = default;
    ~UdpTransport() override { close(); }
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    // `bind_addr` may be null (kernel picks). false + error on failure.
    bool open(const sockaddr_in& peer, const sockaddr_in* bind_addr, std::string& error);
    // Port actually bound locally (useful with port 0), 0 if not open.
    uint16_t local_port() const;

    TransportKind kind() const override { return TransportKind::Udp; }
    TransportStatus send(const uint8_t* data, size_t len) override;
    RecvResult recv(uint8_t* buf, size_t cap) override;
    bool is_open() const override { return fd_ >= 0; }
    void close() override;
    size_t max_packet() const override { return 65507; }     // IPv4 UDP payload limit
    int poll_fd() const override { return fd_; }

private:
    int fd_ = -1;
};

}  // namespace pf::pal
