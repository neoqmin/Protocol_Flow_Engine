#include "pf/server_core.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstring>

#include "pf/crypto/os_random.h"
#include "pf/secure_mem.h"

namespace pf {

namespace {

constexpr uint8_t op(OvpnOpcode o) { return static_cast<uint8_t>(o); }
constexpr uint32_t kNoPeerId = 0xFFFFFF;          // reserved on the wire

}  // namespace

ServerCore::ServerCore(ServerCoreConfig cfg)
    : cfg_(std::move(cfg)), tls_crypt_(derive_tls_crypt_keys(cfg_.session.tls_crypt_key, TlsCryptRole::Server)) {}

ServerCore::~ServerCore() {
    std::vector<SessionId> ids;
    for (const auto& kv : sessions_) ids.push_back(kv.first);
    for (const SessionId id : ids) remove(id, "server shutting down");
    secure_zero(cfg_.session.tls_crypt_key.data(), cfg_.session.tls_crypt_key.size());
    secure_zero(cookie_secret_.data(), cookie_secret_.size());
}

std::unique_ptr<ServerCore> ServerCore::create(ServerCoreConfig cfg, std::string& error) {
    if (!cfg.prepare_push) { error = "prepare_push is required (who gives clients their address?)"; return nullptr; }
    if (cfg.max_clients == 0 || cfg.max_sessions_per_ip == 0) { error = "client limits must be positive"; return nullptr; }
    if (cfg.max_clients >= kNoPeerId) { error = "max_clients exceeds the peer-id space"; return nullptr; }
    if (cfg.new_sessions_per_second == 0 || cfg.new_session_burst == 0) { error = "session rate limits must be positive"; return nullptr; }
    if (cfg.cookie_window_ms < 1000) { error = "cookie_window_ms too small"; return nullptr; }
    if (cfg.session.tls.role != TlsRole::Server) { error = "the session template needs a TLS server configuration"; return nullptr; }
    {   // Validate the session template once with a placeholder push (the real one comes from prepare_push).
        std::string probe_err;
        ControlServerConfig probe = cfg.session;
        probe.push.ifconfig_ip = probe.push.ifconfig_ip ? probe.push.ifconfig_ip : 1;
        probe.push.peer_id = 0;
        DeterministicRandom r(1);
        probe.random = &r;
        if (!ControlServer::create(std::move(probe), probe_err)) { error = "session template: " + probe_err; return nullptr; }
    }
    std::unique_ptr<ServerCore> s(new ServerCore(std::move(cfg)));
    if (s->cfg_.random == nullptr) s->own_random_ = make_os_random();
    s->random_ = s->cfg_.random ? s->cfg_.random : s->own_random_.get();
    if (!s->random_ || !s->random_->fill(s->cookie_secret_.data(), s->cookie_secret_.size())) { error = "random source failed"; return nullptr; }
    s->tokens_ = s->cfg_.new_session_burst;
    return s;
}

std::array<uint8_t, kSessionIdLen> ServerCore::cookie(const NetAddress& a, const std::array<uint8_t, kSessionIdLen>& client_sid,
                                                      uint64_t window) const {
    uint8_t msg[1 + 16 + 2 + kSessionIdLen + 8];
    size_t n = 0;
    msg[n++] = static_cast<uint8_t>(a.family);
    const size_t iplen = a.family == NetAddress::Family::V4 ? 4 : 16;
    std::memset(msg + n, 0, 16);
    std::memcpy(msg + n, a.ip.data(), iplen);
    n += 16;
    msg[n++] = static_cast<uint8_t>(a.port >> 8);
    msg[n++] = static_cast<uint8_t>(a.port);
    std::memcpy(msg + n, client_sid.data(), kSessionIdLen);
    n += kSessionIdLen;
    for (int i = 7; i >= 0; --i) msg[n++] = static_cast<uint8_t>(window >> (8 * i));
    uint8_t mac[32];
    unsigned int mac_len = 0;
    std::array<uint8_t, kSessionIdLen> out{};
    if (HMAC(EVP_sha256(), cookie_secret_.data(), static_cast<int>(cookie_secret_.size()), msg, n, mac, &mac_len) != nullptr)
        std::memcpy(out.data(), mac, kSessionIdLen);
    secure_zero(mac, sizeof mac);
    return out;
}

bool ServerCore::cookie_valid(const NetAddress& a, const std::array<uint8_t, kSessionIdLen>& client_sid,
                              const std::array<uint8_t, kSessionIdLen>& echoed, uint64_t now_ms) const {
    const uint64_t w = now_ms / cfg_.cookie_window_ms;
    const auto c0 = cookie(a, client_sid, w);
    bool ok = ct_equal(c0.data(), echoed.data(), kSessionIdLen);
    if (w > 0) {
        const auto c1 = cookie(a, client_sid, w - 1);
        ok = ct_equal(c1.data(), echoed.data(), kSessionIdLen) || ok;
    }
    return ok;
}

void ServerCore::answer_reset(const ControlPacket& p, const NetAddress& from, uint64_t window, uint32_t unix_s,
                              std::vector<Outgoing>& out) {
    ControlPacket r;
    r.opcode = op(OvpnOpcode::ControlHardResetServerV2);
    r.key_id = 0;
    r.session_id = cookie(from, p.session_id, window);
    r.remote_session_id = p.session_id;
    r.acks = {0};
    r.has_message = true;
    r.message_id = 0;
    std::vector<uint8_t> pt, wire;
    if (!build_control_plaintext(r, pt)) return;
    const uint8_t op_keyid = static_cast<uint8_t>(r.opcode << 3);
    // tls-crypt packet-ids of stateless replies: one counter, restarted with every new net_time (the receiver starts a
    // fresh replay window then). Repeated replies to one client therefore never look like replays, and an adopted
    // session continues above every id used in its second (ControlServer::Adopted).
    if (unix_s != stateless_time_) { stateless_time_ = unix_s; stateless_next_ = 1; }
    if (stateless_next_ == 0xFFFFFFFFu) return;                // exhausted for this second (2^32 replies): wait
    const uint32_t packet_id = stateless_next_++;
    if (!tls_crypt_seal(tls_crypt_.tx, op_keyid, r.session_id.data(), packet_id, unix_s, pt.data(), pt.size(), wire)) return;
    out.push_back({from, std::move(wire)});
    ++stats_.cookies_sent;
}

size_t ServerCore::sessions_on_ip(const NetAddress& a) const {
    size_t n = 0;
    for (const auto& kv : sessions_)
        if (kv.second.address.same_ip(a)) ++n;
    return n;
}

bool ServerCore::take_token(uint64_t now_ms) {
    if (now_ms > tokens_at_ms_) {
        tokens_ = std::min<double>(cfg_.new_session_burst,
                                   tokens_ + static_cast<double>(now_ms - tokens_at_ms_) * cfg_.new_sessions_per_second / 1000.0);
    }
    tokens_at_ms_ = std::max(tokens_at_ms_, now_ms);
    if (tokens_ < 1.0) return false;
    tokens_ -= 1.0;
    return true;
}

std::optional<uint32_t> ServerCore::allocate_peer_id() {
    uint32_t candidate = 0;
    for (const auto& kv : by_peer_id_) {                       // ordered: the first gap is the lowest free id
        if (kv.first != candidate) break;
        ++candidate;
    }
    if (candidate >= kNoPeerId) return std::nullopt;
    return candidate;
}

void ServerCore::collect(Entry& e, std::vector<std::vector<uint8_t>>&& dgs, std::vector<Outgoing>& out) {
    for (auto& d : dgs) out.push_back({e.address, std::move(d)});
}

ServerCore::Received ServerCore::open_session(const ControlPacket& p, const uint8_t* data, size_t len, const NetAddress& from,
                                              uint64_t now_ms, uint32_t unix_s, std::vector<Outgoing>& out) {
    Received rx;
    rx.route = Route::Dropped;
    // The client at this address proved it is reachable there: a session it had before is gone (it restarted).
    if (auto old = find_by_address(from)) {
        remove(*old, "replaced by a new session from the same address");
        ++stats_.sessions_replaced;
    }
    if (sessions_.size() >= cfg_.max_clients) { ++stats_.limit_clients; rx.reason = DropReason::LimitClients; return rx; }
    if (sessions_on_ip(from) >= cfg_.max_sessions_per_ip) { ++stats_.limit_per_ip; rx.reason = DropReason::LimitPerIp; return rx; }
    if (!take_token(now_ms)) { ++stats_.limit_rate; rx.reason = DropReason::LimitRate; return rx; }
    const std::optional<uint32_t> pid = allocate_peer_id();
    if (!pid) { rx.reason = DropReason::LimitClients; return rx; }

    ControlServerConfig sc = cfg_.session;
    sc.push.peer_id = *pid;
    if (!cfg_.prepare_push(*pid, sc.push)) { secure_zero(sc.tls_crypt_key.data(), sc.tls_crypt_key.size()); rx.reason = DropReason::SetupFailed; return rx; }
    sc.push.peer_id = *pid;                                    // not the callback's to change
    auto keys = std::make_unique<KeyStore>();
    sc.keys = keys.get();
    sc.random = random_;
    ControlServer::Adopted a;
    a.client_sid = p.session_id;
    a.server_sid = p.remote_session_id;
    a.next_tls_crypt_packet_id = unix_s == stateless_time_ ? std::max<uint32_t>(2, stateless_next_) : 2;
    std::string err;
    std::unique_ptr<ControlServer> server = ControlServer::adopt(std::move(sc), a, now_ms, err);
    if (!server) { rx.reason = DropReason::SetupFailed; return rx; }

    const SessionId id = next_id_++;
    Entry& e = sessions_[id];
    e.id = id;
    e.address = from;
    e.peer_id = *pid;
    e.keys = std::move(keys);
    e.server = std::move(server);
    by_address_[from] = id;
    by_peer_id_[*pid] = id;
    ++stats_.sessions_opened;
    events_.push_back({Event::Kind::Opened, id, from, *pid, {}});

    e.server->on_datagram(data, len, now_ms, unix_s);
    collect(e, e.server->poll(now_ms, unix_s), out);
    rx.route = Route::Control;
    rx.session = id;
    return rx;
}

ServerCore::Received ServerCore::on_datagram(const uint8_t* d, size_t len, const NetAddress& from, uint64_t now_ms,
                                             uint32_t unix_s, std::vector<Outgoing>& out) {
    Received rx;
    if (d == nullptr || len == 0) { ++stats_.malformed; rx.reason = DropReason::Malformed; return rx; }
    const uint8_t opcode = d[0] >> 3;

    if (opcode == op(OvpnOpcode::DataV2)) {
        if (len < 4) { ++stats_.malformed; rx.reason = DropReason::Malformed; return rx; }
        const uint32_t pid = (uint32_t{d[1]} << 16) | (uint32_t{d[2]} << 8) | d[3];
        const auto it = by_peer_id_.find(pid);
        if (it == by_peer_id_.end()) { ++stats_.data_unknown_peer; rx.reason = DropReason::UnknownPeerId; return rx; }
        const Entry& e = sessions_.at(it->second);
        if (e.server->state() != ControlServer::State::Established) { ++stats_.data_no_keys; rx.reason = DropReason::NoDataKeys; return rx; }
        rx.route = Route::Data;
        rx.session = e.id;
        rx.new_address = e.address != from;
        return rx;
    }
    if (!is_control_opcode(opcode)) { rx.reason = DropReason::Unsupported; return rx; }
    if (len < 1 + kSessionIdLen) { ++stats_.malformed; rx.reason = DropReason::Malformed; return rx; }
    std::array<uint8_t, kSessionIdLen> sid{};
    std::memcpy(sid.data(), d + 1, kSessionIdLen);             // cleartext header: used for routing only

    // A packet of the session at this address goes to it (it authenticates everything itself).
    if (const auto it = by_address_.find(from); it != by_address_.end()) {
        Entry& e = sessions_.at(it->second);
        if (sid == e.server->client_session_id()) {
            e.server->on_datagram(d, len, now_ms, unix_s);
            collect(e, e.server->poll(now_ms, unix_s), out);
            rx.route = Route::Control;
            rx.session = e.id;
            return rx;
        }
        // Another client session id from the same address: a restarted client. Same stateless path as a stranger.
    }

    TlsCryptPlain plain;
    if (tls_crypt_open(tls_crypt_.rx, d, len, plain) != TlsCryptStatus::Ok) { ++stats_.not_ours; rx.reason = DropReason::NotOurs; return rx; }
    ControlPacket p;
    if (parse_control(plain.op_keyid, plain.session_id, plain.payload.data(), plain.payload.size(), p) != ControlParseStatus::Ok) {
        ++stats_.malformed;
        rx.reason = DropReason::Malformed;
        return rx;
    }
    if (p.opcode == op(OvpnOpcode::ControlHardResetClientV2)) {
        if (p.key_id != 0 || !p.has_message || p.message_id != 0 || !p.acks.empty()) { ++stats_.malformed; rx.reason = DropReason::Malformed; return rx; }
        answer_reset(p, from, now_ms / cfg_.cookie_window_ms, unix_s, out);
        rx.route = Route::Control;
        return rx;
    }
    if (p.key_id == 0 && !p.acks.empty() && cookie_valid(from, p.session_id, p.remote_session_id, now_ms)) {
        Received r = open_session(p, d, len, from, now_ms, unix_s, out);
        if (r.route == Route::Control) return r;
        // Refused for now (limits): the client will retransmit without acks (each ack is sent once). Challenge it again
        // so it acknowledges our reset once more and carries the cookie when we may have room.
        if (r.reason == DropReason::LimitClients || r.reason == DropReason::LimitPerIp || r.reason == DropReason::LimitRate)
            answer_reset(p, from, now_ms / cfg_.cookie_window_ms, unix_s, out);
        return r;
    }
    ++stats_.bad_cookies;
    rx.reason = DropReason::BadCookie;
    if (p.key_id == 0 && p.acks.empty()) {
        // An authentic packet of a client that has our reset but whose ack (with the cookie) was lost or refused:
        // repeat the reset (stateless, about the size of the request). The client accepts the copy whose session id it
        // bound - current or previous window - and acks it, which carries the cookie this time.
        const uint64_t w = now_ms / cfg_.cookie_window_ms;
        answer_reset(p, from, w, unix_s, out);
        if (w > 0) answer_reset(p, from, w - 1, unix_s, out);
    }
    return rx;
}

void ServerCore::remove(SessionId id, const std::string& why) {
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return;
    Entry& e = it->second;
    e.server->close(why);
    events_.push_back({Event::Kind::Closed, id, e.address, e.peer_id, e.server->close_reason()});
    by_address_.erase(e.address);
    by_peer_id_.erase(e.peer_id);
    e.server.reset();                                          // unbinds into e.keys, which goes next
    sessions_.erase(it);
    ++stats_.sessions_closed;
}

std::vector<ServerCore::Outgoing> ServerCore::poll(uint64_t now_ms, uint32_t unix_s) {
    std::vector<Outgoing> out;
    std::vector<SessionId> finished;
    for (auto& kv : sessions_) {
        Entry& e = kv.second;
        collect(e, e.server->poll(now_ms, unix_s), out);
        if (!e.announced_established && e.server->state() == ControlServer::State::Established) {
            e.announced_established = true;
            events_.push_back({Event::Kind::Established, e.id, e.address, e.peer_id, e.server->common_name()});
        }
        if (e.server->done()) finished.push_back(e.id);
    }
    for (const SessionId id : finished) remove(id, "closed");
    return out;
}

std::optional<uint64_t> ServerCore::next_wakeup_ms() const {
    std::optional<uint64_t> best;
    for (const auto& kv : sessions_) {
        if (kv.second.server->done()) return 0;                // removal is due
        if (auto t = kv.second.server->next_wakeup_ms(); t && (!best || *t < *best)) best = t;
    }
    return best;
}

std::vector<ServerCore::PendingAuth> ServerCore::take_auth_requests() {
    std::vector<PendingAuth> out;
    for (auto& kv : sessions_)
        if (auto r = kv.second.server->take_auth_request()) out.push_back({kv.first, std::move(*r)});
    return out;
}

bool ServerCore::resolve_auth(SessionId id, bool accept, const std::string& reason) {
    const auto it = sessions_.find(id);
    if (it == sessions_.end() || it->second.server->state() != ControlServer::State::AuthPending) return false;
    it->second.server->resolve_auth(accept, reason);
    return true;
}

bool ServerCore::kill(SessionId id, const std::string& why) {
    if (sessions_.count(id) == 0) return false;
    remove(id, why);
    return true;
}

bool ServerCore::confirm_float(SessionId id, const NetAddress& from) {
    const auto it = sessions_.find(id);
    if (it == sessions_.end()) return false;
    Entry& e = it->second;
    if (e.address == from) return true;
    if (by_address_.count(from) != 0) return false;            // another session lives there
    by_address_.erase(e.address);
    e.address = from;
    by_address_[from] = id;
    ++stats_.floats;
    return true;
}

std::vector<ServerCore::Event> ServerCore::take_events() {
    std::vector<Event> out;
    out.swap(events_);
    return out;
}

const ControlServer* ServerCore::session(SessionId id) const {
    const auto it = sessions_.find(id);
    return it == sessions_.end() ? nullptr : it->second.server.get();
}

KeyStore* ServerCore::keys(SessionId id) {
    const auto it = sessions_.find(id);
    return it == sessions_.end() ? nullptr : it->second.keys.get();
}

std::optional<ServerCore::SessionId> ServerCore::find_by_peer_id(uint32_t peer_id) const {
    const auto it = by_peer_id_.find(peer_id);
    if (it == by_peer_id_.end()) return std::nullopt;
    return it->second;
}

std::optional<ServerCore::SessionId> ServerCore::find_by_address(const NetAddress& a) const {
    const auto it = by_address_.find(a);
    if (it == by_address_.end()) return std::nullopt;
    return it->second;
}

std::optional<NetAddress> ServerCore::address_of(SessionId id) const {
    const auto it = sessions_.find(id);
    if (it == sessions_.end()) return std::nullopt;
    return it->second.address;
}

uint32_t ServerCore::peer_id_of(SessionId id) const {
    const auto it = sessions_.find(id);
    return it == sessions_.end() ? kNoPeerId : it->second.peer_id;
}

}  // namespace pf
