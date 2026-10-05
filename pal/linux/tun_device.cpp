#include "tun_device.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace pf::pal {

namespace {
std::string errno_text(const char* what) { return std::string(what) + ": " + std::strerror(errno); }

sockaddr_in make_addr(uint32_t host_order) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(host_order);
    return a;
}
}  // namespace

TunDevice::~TunDevice() { close(); }

void TunDevice::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

bool TunDevice::open(const std::string& name_hint, std::string& error) {
    close();
    const int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { error = errno_text("open /dev/net/tun"); return false; }
    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name_hint.size() >= IFNAMSIZ) { ::close(fd); error = "interface name too long"; return false; }
    std::strncpy(ifr.ifr_name, name_hint.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { error = errno_text("TUNSETIFF"); ::close(fd); return false; }
    fd_ = fd;
    name_ = ifr.ifr_name;
    return true;
}

bool TunDevice::configure(uint32_t ip, uint32_t netmask, int mtu, std::string& error) {
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) { error = errno_text("socket"); return false; }
    bool ok = true;
    auto fail = [&](const char* what) { if (ok) error = errno_text(what); ok = false; };
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    auto addr = make_addr(ip);
    std::memcpy(&ifr.ifr_addr, &addr, sizeof addr);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) fail("SIOCSIFADDR");
    auto mask = make_addr(netmask);
    std::memcpy(&ifr.ifr_netmask, &mask, sizeof mask);
    if (ok && ioctl(s, SIOCSIFNETMASK, &ifr) < 0) fail("SIOCSIFNETMASK");
    ifr.ifr_mtu = mtu;
    if (ok && ioctl(s, SIOCSIFMTU, &ifr) < 0) fail("SIOCSIFMTU");
    if (ok && ioctl(s, SIOCGIFFLAGS, &ifr) < 0) fail("SIOCGIFFLAGS");
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ok && ioctl(s, SIOCSIFFLAGS, &ifr) < 0) fail("SIOCSIFFLAGS");
    ::close(s);
    return ok;
}

bool TunDevice::add_route(uint32_t network, uint32_t netmask, uint32_t gateway, std::string& error) {
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) { error = errno_text("socket"); return false; }
    rtentry rt{};
    auto dst = make_addr(network), gw = make_addr(gateway), mask = make_addr(netmask);
    std::memcpy(&rt.rt_dst, &dst, sizeof dst);
    std::memcpy(&rt.rt_gateway, &gw, sizeof gw);
    std::memcpy(&rt.rt_genmask, &mask, sizeof mask);
    rt.rt_flags = RTF_UP | (gateway ? RTF_GATEWAY : 0);
    char dev[IFNAMSIZ];
    std::strncpy(dev, name_.c_str(), IFNAMSIZ - 1);
    dev[IFNAMSIZ - 1] = 0;
    rt.rt_dev = dev;
    const bool ok = ioctl(s, SIOCADDRT, &rt) == 0 || errno == EEXIST;
    if (!ok) error = errno_text("SIOCADDRT");
    ::close(s);
    return ok;
}

long TunDevice::read_packet(uint8_t* buf, size_t cap) {
    const ssize_t n = ::read(fd_, buf, cap);
    if (n >= 0) return n;
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
}

bool TunDevice::write_packet(const uint8_t* data, size_t len) {
    return ::write(fd_, data, len) == static_cast<ssize_t>(len);
}

}  // namespace pf::pal
