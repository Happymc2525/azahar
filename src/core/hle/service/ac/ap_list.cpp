// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <cstring>
#include "core/hle/service/ac/ap_list.h"

namespace Service::AC {

namespace {

constexpr int RssiOffset = 100;
constexpr u16 MaxStrength = 100;
constexpr u8 MinChannel = 1;
constexpr u8 MaxChannel = 13;
constexpr u16 BestLevelStrength = 20;
constexpr u16 GoodLevelStrength = 16;
constexpr u16 PoorLevelStrength = 10;

} // namespace

u16 StrengthFromRssi(s16 rssi) {
    return static_cast<u16>(std::clamp<int>(RssiOffset + rssi, 0, MaxStrength));
}

u8 LevelFromStrength(u16 strength) {
    if (strength >= BestLevelStrength) {
        return 3;
    }
    if (strength >= GoodLevelStrength) {
        return 2;
    }
    if (strength >= PoorLevelStrength) {
        return 1;
    }
    return 0;
}

std::array<u8, 4> SecurityBytes(ApSecurity security) {
    switch (security) {
    case ApSecurity::Secured:
        return {5, 5, 0, 0};
    case ApSecurity::SecuredMixed:
        return {5, 4, 0, 0};
    case ApSecurity::Open:
        break;
    }
    return {0, 0, 0, 0};
}

ApInfo ToApInfo(const HostApInfo& host) {
    ApInfo entry{};
    const std::size_t length = std::min(host.ssid.size(), MaxSsidLength);
    const u16 strength = StrengthFromRssi(host.rssi);
    entry.ssid_length = static_cast<u32>(length);
    std::memcpy(entry.ssid.data(), host.ssid.data(), length);
    entry.bssid = host.bssid;
    entry.signal_strength = strength;
    entry.link_level = LevelFromStrength(strength);
    entry.channel = host.channel;
    entry.security = SecurityBytes(host.security);
    return entry;
}

std::vector<ApInfo> BuildApList(std::vector<HostApInfo> host, std::size_t capacity) {
    std::erase_if(host, [](const HostApInfo& ap) {
        return ap.channel < MinChannel || ap.channel > MaxChannel;
    });
    std::stable_sort(host.begin(), host.end(), [](const HostApInfo& a, const HostApInfo& b) {
        return StrengthFromRssi(a.rssi) > StrengthFromRssi(b.rssi);
    });

    std::vector<ApInfo> list;
    const std::size_t limit = std::min(capacity, MaxApEntries);
    for (const HostApInfo& ap : host) {
        if (list.size() >= limit) {
            break;
        }
        const bool duplicated = std::any_of(list.begin(), list.end(), [&ap](const ApInfo& entry) {
            return entry.bssid == ap.bssid;
        });
        if (!duplicated) {
            list.push_back(ToApInfo(ap));
        }
    }
    return list;
}

} // namespace Service::AC
