#pragma once
#include <cstddef>
#include <cstdint>

#include "pf/transport_fallback.h"

namespace pf {

enum class TransportStatus {
    Ok,           // done (send: whole packet accepted; recv: one whole packet delivered)
    WouldBlock,   // nothing to receive / no room to send right now (not an error)
    TooLarge,     // recv: the packet did not fit `cap` and was discarded; send: longer than max_packet()
    Closed,       // the peer or we closed the transport
    Error,        // I/O failure; the transport is unusable
};

struct RecvResult {
    TransportStatus status = TransportStatus::WouldBlock;
    size_t len = 0;       // valid when status == Ok
};

// How OpenVPN packets travel (docs/Block_API.md is about packets, this is about the pipe). Packet-oriented:
// one send() = one OpenVPN packet, one recv() = one whole OpenVPN packet, whatever the carrier is. UDP maps this 1:1
// onto datagrams; TCP (B2) adds the 2-byte length framing and reassembly behind the same interface, so the control
// client, data path and event loop never see the difference. Non-blocking: callers wait with poll() on poll_fd().
//
// Device (TUN/TAP) is an independent axis (docs/DECISIONS.md D-004); nothing here knows about it.
class Transport {
public:
    virtual ~Transport() = default;

    virtual TransportKind kind() const = 0;
    virtual TransportStatus send(const uint8_t* data, size_t len) = 0;
    virtual RecvResult recv(uint8_t* buf, size_t cap) = 0;

    virtual bool is_open() const = 0;
    virtual void close() = 0;

    // Largest packet send() accepts (UDP: one datagram; TCP: 65535, the framing limit).
    virtual size_t max_packet() const = 0;
    // File descriptor to poll for readability, or -1 (in-memory fakes: the caller polls recv() itself).
    virtual int poll_fd() const { return -1; }
};

}  // namespace pf
