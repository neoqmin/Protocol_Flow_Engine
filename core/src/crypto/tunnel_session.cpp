#include "pf/tunnel_session.h"

#include <algorithm>

#include "pf/crypto/openssl_aes_gcm.h"

namespace pf {

namespace {
constexpr size_t kMaxIpPacket = 65535;
}  // namespace

TunnelSession::TunnelSession(ControlClient& c, KeyStore& k) : client_(c), keys_(k), aead_(make_openssl_aes256gcm()) {}

std::unique_ptr<TunnelSession> TunnelSession::create(ControlClient& client, KeyStore& keys, std::string& error) {
    std::unique_ptr<TunnelSession> s(new TunnelSession(client, keys));
    if (!s->aead_ || !s->data_.init(&keys, s->aead_.get())) { error = "data plane init failed"; return nullptr; }
    return s;
}

void TunnelSession::maybe_start_keepalive(uint64_t now_ms) {
    if (keepalive_ || client_.state() != ControlClient::State::Established) return;
    const PushReply& p = client_.push();
    keepalive_.emplace(p.ping_seconds, p.ping_restart_seconds, now_ms);
}

TunnelSession::RxKind TunnelSession::on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s, PacketBuffer& out) {
    stamp(now_ms);
    const bool was_established = client_.state() == ControlClient::State::Established;
    if (client_.on_datagram(data, len, now_ms, unix_s)) {
        maybe_start_keepalive(now_ms);
        if (keepalive_) keepalive_->on_received(now_ms);       // an authenticated control packet proves the peer is alive
        return RxKind::Control;
    }
    if (!was_established || !keepalive_) { ++stats_.rx_before_established; return RxKind::Dropped; }

    PacketBuffer pkt = PacketBuffer::from_bytes(data, len);
    const DataPath::Opened opened = data_.open(pkt);
    if (opened.error != Error::None) { ++stats_.rx_dropped; return RxKind::Dropped; }
    keepalive_->on_received(now_ms);

    if (opened.kind == PayloadKind::Ping) { ++stats_.rx_pings; return RxKind::Keepalive; }
    if (opened.kind != PayloadKind::Ip) { ++stats_.rx_not_ip; return RxKind::Dropped; }
    ++stats_.rx_packets;
    stats_.rx_bytes += pkt.size();
    out = std::move(pkt);
    return RxKind::Packet;
}

bool TunnelSession::encrypt(const uint8_t* payload, size_t len, std::vector<uint8_t>& wire) {
    PacketBuffer pkt = PacketBuffer::from_bytes(payload, len);
    if (data_.seal(pkt, client_.tx_key_id(), client_.push().peer_id) != Error::None) { ++stats_.tx_failed; return false; }
    wire.assign(pkt.data(), pkt.data() + pkt.size());
    return true;
}

bool TunnelSession::encapsulate(const uint8_t* ip, size_t len, uint64_t now_ms, std::vector<uint8_t>& wire) {
    stamp(now_ms);
    if (!keepalive_) { ++stats_.tx_before_established; return false; }
    if (len == 0 || len > kMaxIpPacket) { ++stats_.tx_failed; return false; }
    if (!encrypt(ip, len, wire)) return false;
    keepalive_->on_sent(now_ms);
    ++stats_.tx_packets;
    stats_.tx_bytes += len;
    return true;
}

std::vector<std::vector<uint8_t>> TunnelSession::poll(uint64_t now_ms, uint32_t unix_s) {
    stamp(now_ms);
    std::vector<std::vector<uint8_t>> out = client_.poll(now_ms, unix_s);
    maybe_start_keepalive(now_ms);
    if (!keepalive_) return out;
    if (!out.empty()) keepalive_->on_sent(now_ms);
    switch (keepalive_->poll(now_ms)) {
        case KeepaliveTimer::Action::SendPing: {
            std::vector<uint8_t> wire;
            if (encrypt(kPingPayload, kPingPayloadLen, wire)) { out.push_back(std::move(wire)); ++stats_.tx_pings; }
            break;
        }
        case KeepaliveTimer::Action::Timeout: timed_out_ = true; break;
        case KeepaliveTimer::Action::None: break;
    }
    return out;
}

std::optional<uint64_t> TunnelSession::next_wakeup_ms() const {
    std::optional<uint64_t> w = client_.next_wakeup_ms();
    if (keepalive_) {
        if (auto k = keepalive_->next_deadline_ms()) w = w ? std::min(*w, *k) : *k;
    }
    return w;
}

}  // namespace pf
