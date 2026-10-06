#pragma once
// Linux platform layer (PAL) for the A4 client: UDP socket and TUN device. POSIX/Linux only; the core never includes this.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pf::pal {

// Connected IPv4 UDP socket (non-blocking). `fd()` is for poll().
class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // "a.b.c.d:port". false + `error` on failure.
    bool open_connected(const std::string& host_port, std::string& error);
    int fd() const { return fd_; }
    bool send(const uint8_t* data, size_t len);                 // false if the kernel did not accept it (drop, never blocks)
    long recv(uint8_t* buf, size_t cap);                        // bytes, 0 = nothing available, -1 = hard error

private:
    int fd_ = -1;
};

struct TunRoute { uint32_t network, netmask, gateway; bool has_gateway; };   // host byte order

// Layer-3 TUN device (IFF_TUN | IFF_NO_PI: reads/writes are bare IP packets). Needs CAP_NET_ADMIN.
class TunDevice {
public:
    TunDevice() = default;
    ~TunDevice();
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    // `name` may be empty (kernel picks). The device disappears when this object is destroyed.
    bool open(const std::string& name, std::string& error);
    // Address/netmask (host byte order), MTU, and link up. Adds the connected-subnet route implicitly (kernel).
    bool configure(uint32_t ip, uint32_t netmask, unsigned mtu, std::string& error);
    bool add_route(const TunRoute& r, std::string& error);

    int fd() const { return fd_; }
    const std::string& name() const { return name_; }
    long read(uint8_t* buf, size_t cap);                        // bytes, 0 = nothing available, -1 = hard error
    bool write(const uint8_t* data, size_t len);

private:
    int fd_ = -1;
    std::string name_;
};

}  // namespace pf::pal
