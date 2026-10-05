#include "linux_net.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace pf::pal {

namespace {
std::string errno_text(const char* what) { return std::string(what) + ": " + std::strerror(errno); }

bool set_nonblocking(int fd) {
    const int fl = fcntl(fd, F_GETFL, 0);
    return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

sockaddr_in sin(uint32_t host_order_ip) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(host_order_ip);
    return a;
}
}  // namespace

UdpSocket::~UdpSocket() { if (fd_ >= 0) ::close(fd_); }

bool UdpSocket::open_connected(const std::string& host_port, std::string& error) {
    const size_t colon = host_port.rfind(':');
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    const int port = colon == std::string::npos ? 0 : std::atoi(host_port.c_str() + colon + 1);
    if (port <= 0 || port > 65535 || inet_pton(AF_INET, host_port.substr(0, colon).c_str(), &addr.sin_addr) != 1) {
        error = "bad server address (want a.b.c.d:port)";
        return false;
    }
    addr.sin_port = htons(static_cast<uint16_t>(port));
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) { error = errno_text("socket"); return false; }
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) { error = errno_text("connect"); return false; }
    if (!set_nonblocking(fd_)) { error = errno_text("fcntl"); return false; }
    return true;
}

bool UdpSocket::send(const uint8_t* data, size_t len) { return ::send(fd_, data, len, 0) == static_cast<ssize_t>(len); }

long UdpSocket::recv(uint8_t* buf, size_t cap) {
    const ssize_t n = ::recv(fd_, buf, cap, 0);
    if (n >= 0) return n;
    // ECONNREFUSED arrives for an earlier datagram when the server's port is closed: not fatal, the session timers decide.
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ECONNREFUSED) ? 0 : -1;
}

TunDevice::~TunDevice() { if (fd_ >= 0) ::close(fd_); }

bool TunDevice::open(const std::string& name, std::string& error) {
    fd_ = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd_ < 0) { error = errno_text("open /dev/net/tun"); return false; }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name.size() >= IFNAMSIZ) { error = "TUN name too long"; return false; }
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd_, TUNSETIFF, &ifr) != 0) { error = errno_text("TUNSETIFF"); return false; }
    name_ = ifr.ifr_name;
    if (!set_nonblocking(fd_)) { error = errno_text("fcntl"); return false; }
    return true;
}

bool TunDevice::configure(uint32_t ip, uint32_t netmask, unsigned mtu, std::string& error) {
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { error = errno_text("socket"); return false; }
    struct Closer { int fd; ~Closer() { ::close(fd); } } closer{s};
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    sockaddr_in a = sin(ip);
    std::memcpy(&ifr.ifr_addr, &a, sizeof a);
    if (ioctl(s, SIOCSIFADDR, &ifr) != 0) { error = errno_text("SIOCSIFADDR"); return false; }
    a = sin(netmask);
    std::memcpy(&ifr.ifr_netmask, &a, sizeof a);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) != 0) { error = errno_text("SIOCSIFNETMASK"); return false; }
    ifr.ifr_mtu = static_cast<int>(mtu);
    if (ioctl(s, SIOCSIFMTU, &ifr) != 0) { error = errno_text("SIOCSIFMTU"); return false; }
    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) { error = errno_text("SIOCGIFFLAGS"); return false; }
    ifr.ifr_flags = static_cast<short>(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) { error = errno_text("SIOCSIFFLAGS"); return false; }
    return true;
}

bool TunDevice::add_route(const TunRoute& r, std::string& error) {
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { error = errno_text("socket"); return false; }
    struct Closer { int fd; ~Closer() { ::close(fd); } } closer{s};
    rtentry rt{};
    const sockaddr_in dst = sin(r.network), mask = sin(r.netmask), gw = sin(r.gateway);
    std::memcpy(&rt.rt_dst, &dst, sizeof dst);
    std::memcpy(&rt.rt_genmask, &mask, sizeof mask);
    rt.rt_flags = RTF_UP;
    if (r.has_gateway) { std::memcpy(&rt.rt_gateway, &gw, sizeof gw); rt.rt_flags |= RTF_GATEWAY; }
    std::string dev = name_;                                   // rt_dev is a non-const char*
    rt.rt_dev = dev.data();
    if (ioctl(s, SIOCADDRT, &rt) != 0 && errno != EEXIST) { error = errno_text("SIOCADDRT"); return false; }
    return true;
}

long TunDevice::read(uint8_t* buf, size_t cap) {
    const ssize_t n = ::read(fd_, buf, cap);
    if (n >= 0) return n;
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
}

bool TunDevice::write(const uint8_t* data, size_t len) { return ::write(fd_, data, len) == static_cast<ssize_t>(len); }

}  // namespace pf::pal
