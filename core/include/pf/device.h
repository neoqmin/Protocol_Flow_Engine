#pragma once

namespace pf {

enum class Platform { Linux, Windows, MacOS, Android, IOS };
enum class DeviceMode { Tun, Tap };

// TUN carries L3 (IP) packets, TAP carries L2 (Ethernet) frames.
constexpr int device_layer(DeviceMode m) { return m == DeviceMode::Tun ? 3 : 2; }

// TAP exists only where a native/maintained L2 virtual adapter is available.
constexpr bool device_supported(Platform p, DeviceMode m) {
    if (m == DeviceMode::Tun) return true;
    return p == Platform::Linux || p == Platform::Windows;
}

constexpr bool device_resolvable(Platform p, DeviceMode requested, bool allow_fallback) {
    return device_supported(p, requested) || (allow_fallback && device_supported(p, DeviceMode::Tun));
}

// Returns the mode to actually use. Caller must check device_resolvable() first
// when allow_fallback is false; an unsupported request is returned unchanged.
constexpr DeviceMode resolve_device(Platform p, DeviceMode requested, bool allow_fallback) {
    if (device_supported(p, requested)) return requested;
    return allow_fallback ? DeviceMode::Tun : requested;
}

}  // namespace pf
