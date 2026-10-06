#pragma once
#include <optional>
#include <string_view>
#include <vector>

#include "pf/stun.h"

namespace pf::stun {

// STUN Binding responder (RFC 8489 Binding + RFC 5780 NAT behaviour discovery), sans-I/O: one request in, the reply and
// the local address to send it FROM out. PM-2b N3 (D-047) uses it as the test server; the connection server
// (pf_connectd, N5) builds on it.
//
// A server for RFC 5780 has two addresses and two ports: `primary` and `alternate` differ in BOTH. A request may arrive
// on any of the four combinations; CHANGE-REQUEST asks for the reply to leave from the other IP and/or port, and
// OTHER-ADDRESS tells the client the combination that differs in both from where its request arrived.
//
// No authentication (this responder holds no credentials; MESSAGE-INTEGRITY in a request is ignored). Unknown
// comprehension-required attributes - and CHANGE-REQUEST when there is no alternate address - get a 420 error with
// UNKNOWN-ATTRIBUTES. Indications, responses and malformed messages get no reply.
struct ResponderAddresses {
    Address primary;
    std::optional<Address> alternate;
};

struct ResponderReply {
    Address from;                     // local address to send from
    Address to;
    std::vector<uint8_t> bytes;
};

std::optional<ResponderReply> respond_to_binding(const uint8_t* req, size_t len, const Address& source, const Address& local,
                                                 const ResponderAddresses& addrs, std::string_view software = {});

}  // namespace pf::stun
