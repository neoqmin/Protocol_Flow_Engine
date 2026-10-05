#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace pf::pal {

// Linux TUN device (IFF_TUN | IFF_NO_PI): reads/writes bare IP packets. Needs CAP_NET_ADMIN.
// Platform code lives here (PAL); the core never includes it.
class TunDevice {
public:
    TunDevice() = default;
    ~TunDevice();
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    // `name_hint` may be empty (kernel picks tunN). Non-blocking, close-on-exec. false + error on failure.
    bool open(const std::string& name_hint, std::string& error);
    // IPv4 address/netmask (host byte order), MTU, link up. The connected route comes with the address.
    bool configure(uint32_t ip, uint32_t netmask, int mtu, std::string& error);
    // IPv4 route through this device (gateway 0 = on-link).
    bool add_route(uint32_t network, uint32_t netmask, uint32_t gateway, std::string& error);

    int fd() const { return fd_; }
    const std::string& name() const { return name_; }
    // >0 bytes read, 0 = nothing available now, <0 = error.
    long read_packet(uint8_t* buf, size_t cap);
    // true if the whole packet was written.
    bool write_packet(const uint8_t* data, size_t len);
    void close();

private:
    int fd_ = -1;
    std::string name_;
};

}  // namespace pf::pal
