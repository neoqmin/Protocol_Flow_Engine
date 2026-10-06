#pragma once
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace pf::pal {

// Unconnected, non-blocking IPv4 UDP socket: send to / receive from anyone. STUN needs it (RFC 5780 answers arrive from
// the server's OTHER address and port); OpenVPN uses the connected UdpTransport instead.
class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket() { close(); }
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // `bind_addr` null = any address, kernel-chosen port.
    bool open(const sockaddr_in* bind_addr, std::string& error);
    void close();
    bool is_open() const { return fd_ >= 0; }
    int fd() const { return fd_; }
    sockaddr_in local() const;

    enum class Status { Ok, WouldBlock, TooLarge, Error };
    Status send_to(const sockaddr_in& to, const uint8_t* data, size_t len);
    // One datagram; `from` = its source.
    Status recv_from(uint8_t* buf, size_t cap, size_t& len, sockaddr_in& from);

private:
    int fd_ = -1;
};

}  // namespace pf::pal
