#pragma once
#include <cstdint>

namespace pf {

// NAT behaviour in RFC 4787 terms, shared by what the simulator models (pf/nat_sim.h) and what STUN discovery
// observes (pf/stun_client.h, RFC 5780) so a test can compare the two directly.
//   mapping    which outbound flows share one external address:port (RFC 4787 4.1)
//   filtering  which inbound packets a mapping lets through       (RFC 4787 5)
enum class NatMapping : uint8_t { EndpointIndependent, AddressDependent, AddressAndPortDependent };
enum class NatFiltering : uint8_t { EndpointIndependent, AddressDependent, AddressAndPortDependent };

const char* nat_mapping_name(NatMapping m);       // "EIM" | "ADM" | "APDM"
const char* nat_filtering_name(NatFiltering f);   // "EIF" | "ADF" | "APDF"

}  // namespace pf
