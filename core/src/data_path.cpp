#include "pf/data_path.h"

namespace pf {

PayloadKind classify_payload(const uint8_t* data, size_t len) {
    if (is_ping_payload(data, len)) return PayloadKind::Ping;
    if (len >= 20 && (data[0] >> 4) == 4) return PayloadKind::Ip;      // IPv4 header minimum
    if (len >= 40 && (data[0] >> 4) == 6) return PayloadKind::Ip;      // IPv6 header
    return PayloadKind::Other;
}

bool DataPath::init(KeyStore* keys, AeadProvider* aead) {
    keys_ = keys;
    aead_ = aead;
    if (!keys_ || !aead_ || !register_data_plane_blocks(reg_)) return false;
    FlowBuilder r("data_rx");
    r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
     .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
    FlowBuilder t("data_tx");
    t.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
    auto rr = r.build(reg_);
    auto tt = t.build(reg_);
    if (!rr.ok() || !tt.ok()) return false;
    rx_ = std::move(rr.flow);
    tx_ = std::move(tt.flow);
    return true;
}

PacketBuffer DataPath::make_tx_buffer(size_t max_payload) {
    return PacketBuffer(kDefaultHeadroom, max_payload, kDefaultTailroom);
}

Error DataPath::seal(PacketBuffer& pkt, uint8_t key_id, uint32_t peer_id) {
    FlowContext ctx;
    ctx.packet = &pkt;
    ctx.keys = keys_;
    ctx.aead = aead_;
    ctx.header = OvpnHeader{OvpnOpcode::DataV2, key_id, peer_id};
    ctx.header_valid = true;
    const FlowResult r = run_flow(tx_, ctx);
    return r.outcome == FlowOutcome::Completed ? Error::None : (is_error(r.error) ? r.error : Error::Internal);
}

DataPath::Opened DataPath::open(PacketBuffer& pkt) {
    FlowContext ctx;
    ctx.packet = &pkt;
    ctx.keys = keys_;
    ctx.aead = aead_;
    const FlowResult r = run_flow(rx_, ctx);
    Opened o;
    if (r.outcome != FlowOutcome::Completed) {
        o.error = is_error(r.error) ? r.error : Error::Internal;
        return o;
    }
    o.kind = classify_payload(pkt.data(), pkt.size());
    return o;
}

}  // namespace pf
