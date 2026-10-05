#include "pf/device.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(tun_supported_on_all_platforms) {
    for (Platform p : {Platform::Linux, Platform::Windows, Platform::MacOS,
                       Platform::Android, Platform::IOS})
        PF_CHECK(device_supported(p, DeviceMode::Tun));
}

PF_TEST(tap_supported_only_on_linux_and_windows) {
    PF_CHECK(device_supported(Platform::Linux, DeviceMode::Tap));
    PF_CHECK(device_supported(Platform::Windows, DeviceMode::Tap));
    PF_CHECK(!device_supported(Platform::MacOS, DeviceMode::Tap));
    PF_CHECK(!device_supported(Platform::Android, DeviceMode::Tap));
    PF_CHECK(!device_supported(Platform::IOS, DeviceMode::Tap));
}

PF_TEST(tap_carries_l2_tun_carries_l3) {
    PF_CHECK(device_layer(DeviceMode::Tun) == 3);
    PF_CHECK(device_layer(DeviceMode::Tap) == 2);
}

PF_TEST(resolve_falls_back_to_tun_when_tap_unsupported) {
    PF_CHECK(resolve_device(Platform::IOS, DeviceMode::Tap, /*allow_fallback=*/true) == DeviceMode::Tun);
    PF_CHECK(resolve_device(Platform::Linux, DeviceMode::Tap, true) == DeviceMode::Tap);
}

PF_TEST(resolve_reports_unsupported_without_fallback) {
    PF_CHECK(!device_resolvable(Platform::IOS, DeviceMode::Tap, /*allow_fallback=*/false));
    PF_CHECK(device_resolvable(Platform::Linux, DeviceMode::Tap, false));
}
