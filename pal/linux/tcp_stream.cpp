#include "tcp_stream.h"

#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

namespace pf::pal {

bool TcpStream::connect_to(const sockaddr_in& peer, uint32_t timeout_ms, std::string& error) {
    close();
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { error = std::string("socket: ") + std::strerror(errno); return false; }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&peer), sizeof peer);
    if (rc != 0 && errno != EINPROGRESS) { error = std::string("connect: ") + std::strerror(errno); ::close(fd); return false; }
    if (rc != 0) {
        pollfd p{fd, POLLOUT, 0};
        do { rc = poll(&p, 1, static_cast<int>(timeout_ms)); } while (rc < 0 && errno == EINTR);
        if (rc == 0) { error = "connect: timeout"; ::close(fd); return false; }
        if (rc < 0) { error = std::string("poll: ") + std::strerror(errno); ::close(fd); return false; }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            error = std::string("connect: ") + std::strerror(soerr ? soerr : errno);
            ::close(fd);
            return false;
        }
    }
    fd_ = fd;
    return true;
}

void TcpStream::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

StreamResult TcpStream::read(uint8_t* buf, size_t cap) {
    StreamResult r;
    if (fd_ < 0) { r.status = StreamStatus::Closed; return r; }
    for (;;) {
        const ssize_t n = ::recv(fd_, buf, cap, MSG_DONTWAIT);
        if (n > 0) { r.status = StreamStatus::Ok; r.n = static_cast<size_t>(n); return r; }
        if (n == 0) { r.status = StreamStatus::Closed; return r; }            // orderly FIN
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { r.status = StreamStatus::WouldBlock; return r; }
        r.status = (errno == ECONNRESET || errno == EPIPE) ? StreamStatus::Closed : StreamStatus::Error;
        return r;
    }
}

StreamResult TcpStream::write(const uint8_t* data, size_t len) {
    StreamResult r;
    if (fd_ < 0) { r.status = StreamStatus::Closed; return r; }
    for (;;) {
        const ssize_t n = ::send(fd_, data, len, MSG_NOSIGNAL | MSG_DONTWAIT);   // never SIGPIPE
        if (n > 0) { r.status = StreamStatus::Ok; r.n = static_cast<size_t>(n); return r; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { r.status = StreamStatus::WouldBlock; return r; }
        r.status = (n < 0 && (errno == ECONNRESET || errno == EPIPE)) ? StreamStatus::Closed : StreamStatus::Error;
        return r;
    }
}

std::unique_ptr<Transport> open_tcp_transport(const sockaddr_in& peer, uint32_t timeout_ms, std::string& error) {
    auto s = std::make_unique<TcpStream>();
    if (!s->connect_to(peer, timeout_ms, error)) return nullptr;
    return std::make_unique<FramedTransport>(std::move(s), TransportKind::Tcp);
}

}  // namespace pf::pal
