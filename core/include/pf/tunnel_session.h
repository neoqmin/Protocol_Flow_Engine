#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "pf/control_client.h"
#include "pf/crypto/aead_provider.h"
#include "pf/data_path.h"
#include "pf/keepalive.h"
#include "pf/key_store.h"

namespace pf {

// Data plane + keepalive wired to a ControlClient: the sans-I/O core of the Linux client (A4).
// The caller owns the sockets/TUN device and the clock; this class never touches either.
//
//   network datagram  -> on_datagram()  -> Control (handled)  | Packet (an IP packet for the TUN device) | Keepalive | Dropped
//   TUN IP packet     -> encapsulate()  -> wire datagram for the server
//   timers            -> poll()         -> control datagrams (acks, retransmits, renegotiation) + keepalive pings
//
// Not thread-safe. `client` and `keys` must outlive the session; `keys` is the KeyStore the client installs into.
class TunnelSession {
public:
    enum class RxKind {
        Control,     // consumed by the control channel
        Packet,      // authenticated IP packet, written to `out`
        Keepalive,   // authenticated OpenVPN ping (nothing to deliver)
        Dropped,     // failed authentication / replay / unknown key / not IP / before the tunnel is up
    };
    struct Stats {
        uint64_t tx_packets = 0, tx_bytes = 0, tx_pings = 0, tx_failed = 0;
        uint64_t rx_packets = 0, rx_bytes = 0, rx_pings = 0;
        uint64_t rx_dropped = 0;                 // data packets rejected by the RX flow (auth, replay, unknown key, ...)
        uint64_t rx_not_ip = 0;                  // authenticated, but neither ping nor an IP packet (e.g. OCC)
        uint64_t rx_before_established = 0;
        uint64_t tx_before_established = 0;
    };

    static std::unique_ptr<TunnelSession> create(ControlClient& client, KeyStore& keys, std::string& error);

    // `out` is overwritten with the plaintext IP packet when RxKind::Packet is returned.
    RxKind on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s, PacketBuffer& out);

    // Encrypts one IP packet read from the TUN device. false (and nothing in `wire`) when the tunnel is not up,
    // the packet is empty/too large, or the TX flow failed (counted in stats).
    bool encapsulate(const uint8_t* ip, size_t len, uint64_t now_ms, std::vector<uint8_t>& wire);

    // Everything to transmit now: control datagrams, then a keepalive ping if one is due.
    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s);
    std::optional<uint64_t> next_wakeup_ms() const;

    // ping-restart fired: the peer has been silent too long, the session must be restarted by the caller.
    bool timed_out() const { return timed_out_; }
    bool established() const { return keepalive_.has_value(); }
    const Stats& stats() const { return stats_; }

private:
    TunnelSession(ControlClient& c, KeyStore& k);
    void maybe_start_keepalive(uint64_t now_ms);
    bool encrypt(const uint8_t* payload, size_t len, std::vector<uint8_t>& wire);

    ControlClient& client_;
    KeyStore& keys_;
    std::unique_ptr<AeadProvider> aead_;
    DataPath data_;                               // the DATA_V2 RX/TX Flows (shared piece, see data_path.h)
    std::optional<KeepaliveTimer> keepalive_;     // created when the control channel reaches Established
    bool timed_out_ = false;
    Stats stats_;
};

}  // namespace pf
