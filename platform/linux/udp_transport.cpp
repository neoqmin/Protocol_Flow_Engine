#include "udp_transport.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace pf::pal {

bool UdpTransport::open(const sockaddr_in& peer, const sockaddr_in* bind_addr, std::string& error) {
    close();
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { error = std::string("socket: ") + std::strerror(errno); return false; }
    if (bind_addr && bind(fd, reinterpret_cast<const sockaddr*>(bind_addr), sizeof *bind_addr) != 0) {
        error = std::string("bind: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (connect(fd, reinterpret_cast<const sockaddr*>(&peer), sizeof peer) != 0) {
        error = std::string("connect: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    fd_ = fd;
    return true;
}

uint16_t UdpTransport::local_port() const {
    if (fd_ < 0) return 0;
    sockaddr_in a{};
    socklen_t n = sizeof a;
    if (getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &n) != 0) return 0;
    return ntohs(a.sin_port);
}

void UdpTransport::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

TransportStatus UdpTransport::send(const uint8_t* data, size_t len) {
    if (fd_ < 0) return TransportStatus::Closed;
    if (len > max_packet()) return TransportStatus::TooLarge;
    for (;;) {
        const ssize_t n = ::send(fd_, data, len, 0);
        if (n == static_cast<ssize_t>(len)) return TransportStatus::Ok;
        if (n >= 0) return TransportStatus::Error;                                   // cannot happen for datagrams
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) return TransportStatus::WouldBlock;
        if (errno == ECONNREFUSED) return TransportStatus::Ok;                       // ICMP from an earlier packet: UDP is lossy, not an error
        return TransportStatus::Error;
    }
}

RecvResult UdpTransport::recv(uint8_t* buf, size_t cap) {
    RecvResult r;
    if (fd_ < 0) { r.status = TransportStatus::Closed; return r; }
    for (;;) {
        // MSG_TRUNC makes the return value the real datagram length, so an oversized datagram is detected, not clipped.
        const ssize_t n = ::recv(fd_, buf, cap, MSG_DONTWAIT | MSG_TRUNC);
        if (n >= 0) {
            if (static_cast<size_t>(n) > cap) { r.status = TransportStatus::TooLarge; return r; }
            r.status = TransportStatus::Ok;
            r.len = static_cast<size_t>(n);
            return r;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { r.status = TransportStatus::WouldBlock; return r; }
        if (errno == ECONNREFUSED) { r.status = TransportStatus::WouldBlock; return r; }
        r.status = TransportStatus::Error;
        return r;
    }
}

}  // namespace pf::pal
