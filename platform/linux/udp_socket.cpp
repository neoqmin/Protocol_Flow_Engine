#include "udp_socket.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace pf::pal {

bool UdpSocket::open(const sockaddr_in* bind_addr, std::string& error) {
    close();
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { error = std::string("socket: ") + std::strerror(errno); return false; }
    sockaddr_in any{};
    any.sin_family = AF_INET;
    const sockaddr_in* a = bind_addr ? bind_addr : &any;
    if (bind(fd, reinterpret_cast<const sockaddr*>(a), sizeof *a) != 0) {
        error = std::string("bind: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    fd_ = fd;
    return true;
}

void UdpSocket::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

sockaddr_in UdpSocket::local() const {
    sockaddr_in a{};
    socklen_t n = sizeof a;
    if (fd_ >= 0) getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &n);
    return a;
}

UdpSocket::Status UdpSocket::send_to(const sockaddr_in& to, const uint8_t* data, size_t len) {
    if (fd_ < 0) return Status::Error;
    if (len > 65507) return Status::TooLarge;
    for (;;) {
        const ssize_t n = ::sendto(fd_, data, len, 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
        if (n == static_cast<ssize_t>(len)) return Status::Ok;
        if (n >= 0) return Status::Error;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) return Status::WouldBlock;
        if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH) return Status::Ok;   // UDP: lossy, not fatal
        return Status::Error;
    }
}

UdpSocket::Status UdpSocket::recv_from(uint8_t* buf, size_t cap, size_t& len, sockaddr_in& from) {
    if (fd_ < 0) return Status::Error;
    for (;;) {
        socklen_t fl = sizeof from;
        const ssize_t n = ::recvfrom(fd_, buf, cap, MSG_DONTWAIT | MSG_TRUNC, reinterpret_cast<sockaddr*>(&from), &fl);
        if (n >= 0) {
            if (static_cast<size_t>(n) > cap) return Status::TooLarge;
            len = static_cast<size_t>(n);
            return Status::Ok;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED) return Status::WouldBlock;
        return Status::Error;
    }
}

}  // namespace pf::pal
