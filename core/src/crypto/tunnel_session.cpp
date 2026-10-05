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
    if (!s->aead_ || !register_data_plane_blocks(s->reg_)) { error = "data plane init failed"; return nullptr; }
    FlowBuilder r("rx");
    r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
     .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
    FlowBuilder t("tx");
    t.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
    auto rr = r.build(s->reg_);
    auto tt = t.build(s->reg_);
    if (!rr.ok() || !tt.ok()) { error = "data plane flow invalid"; return nullptr; }
    s->rx_ = std::move(rr.flow);
    s->tx_ = std::move(tt.flow);
    return s;
}

void TunnelSession::maybe_start_keepalive(uint64_t now_ms) {
    if (keepalive_ || client_.state() != ControlClient::State::Established) return;
    const PushReply& p = client_.push();
    keepalive_.emplace(p.ping_seconds, p.ping_restart_seconds, now_ms);
}

TunnelSession::RxKind TunnelSession::on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t unix_s, PacketBuffer& out) {
    const bool was_established = client_.state() == ControlClient::State::Established;
    if (client_.on_datagram(data, len, now_ms, unix_s)) {
        maybe_start_keepalive(now_ms);
        if (keepalive_) keepalive_->on_received(now_ms);       // an authenticated control packet proves the peer is alive
        return RxKind::Control;
    }
    if (!was_established || !keepalive_) { ++stats_.rx_before_established; return RxKind::Dropped; }

    PacketBuffer pkt = PacketBuffer::from_bytes(data, len);
    FlowContext ctx;
    ctx.packet = &pkt; ctx.keys = &keys_; ctx.aead = aead_.get();
    if (run_flow(rx_, ctx).outcome != FlowOutcome::Completed) { ++stats_.rx_dropped; return RxKind::Dropped; }
    keepalive_->on_received(now_ms);

    if (is_ping_payload(pkt.data(), pkt.size())) { ++stats_.rx_pings; return RxKind::Keepalive; }
    const unsigned version = pkt.size() ? (pkt.data()[0] >> 4) : 0;
    if (version != 4 && version != 6) { ++stats_.rx_not_ip; return RxKind::Dropped; }
    ++stats_.rx_packets;
    stats_.rx_bytes += pkt.size();
    out = std::move(pkt);
    return RxKind::Packet;
}

bool TunnelSession::encrypt(const uint8_t* payload, size_t len, std::vector<uint8_t>& wire) {
    PacketBuffer pkt = PacketBuffer::from_bytes(payload, len);
    FlowContext ctx;
    ctx.packet = &pkt; ctx.keys = &keys_; ctx.aead = aead_.get();
    ctx.header = OvpnHeader{OvpnOpcode::DataV2, client_.tx_key_id(), client_.push().peer_id};
    ctx.header_valid = true;
    if (run_flow(tx_, ctx).outcome != FlowOutcome::Completed) { ++stats_.tx_failed; return false; }
    wire.assign(pkt.data(), pkt.data() + pkt.size());
    return true;
}

bool TunnelSession::encapsulate(const uint8_t* ip, size_t len, uint64_t now_ms, std::vector<uint8_t>& wire) {
    if (!keepalive_) { ++stats_.tx_before_established; return false; }
    if (len == 0 || len > kMaxIpPacket) { ++stats_.tx_failed; return false; }
    if (!encrypt(ip, len, wire)) return false;
    keepalive_->on_sent(now_ms);
    ++stats_.tx_packets;
    stats_.tx_bytes += len;
    return true;
}

std::vector<std::vector<uint8_t>> TunnelSession::poll(uint64_t now_ms, uint32_t unix_s) {
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
