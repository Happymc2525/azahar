// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <type_traits>
#include <vector>
#include "common/common_types.h"
#include "common/swap.h"

namespace Service::AC {

constexpr std::size_t MaxApEntries = 32;
constexpr std::size_t MaxSsidLength = 0x20;

enum class ApSecurity : u8 {
    Open,
    Secured,
    SecuredMixed,
};

/**
 * Description of a wireless access point found by the host. The SSID holds raw bytes, an empty SSID
 * is a hidden network. The RSSI is the received signal strength in dBm and the channel is the one
 * of the 2.4 GHz band, 0 when the access point is not on that band.
 */
struct HostApInfo {
    std::string ssid;
    std::array<u8, 6> bssid{};
    s16 rssi = -100;
    u8 channel = 0;
    ApSecurity security = ApSecurity::Open;
};

/**
 * Access point entry of the AC::ScanAPs output buffer, as the hardware writes it.
 */
struct ApInfo {
    u32_le ssid_length;
    std::array<char, MaxSsidLength> ssid;
    std::array<u8, 6> bssid;
    std::array<u8, 2> padding;
    u16_le signal_strength;
    u8 link_level;
    u8 channel;
    std::array<u8, 4> security;
};
static_assert(sizeof(ApInfo) == 0x34, "ApInfo has an incorrect size");
static_assert(std::is_trivially_copyable_v<ApInfo>);

/**
 * Converts an RSSI in dBm to the signal strength of the hardware, from 0 to 100.
 */
u16 StrengthFromRssi(s16 rssi);

/**
 * Converts a signal strength to the link level of the hardware, from 0 to 3.
 */
u8 LevelFromStrength(u16 strength);

/**
 * Gets the two security bytes that the hardware reports for a kind of security.
 */
std::array<u8, 4> SecurityBytes(ApSecurity security);

/**
 * Converts a host access point to the entry of the output buffer.
 */
ApInfo ToApInfo(const HostApInfo& host);

/**
 * Builds the list that the hardware reports for the access points around: only the 2.4 GHz band,
 * without duplicated BSSIDs, the strongest first, and at most as many entries as fit in the buffer.
 * @param host The access points found by the host, in any order.
 * @param capacity The number of entries that fit in the output buffer of the guest.
 */
std::vector<ApInfo> BuildApList(std::vector<HostApInfo> host, std::size_t capacity);

} // namespace Service::AC
