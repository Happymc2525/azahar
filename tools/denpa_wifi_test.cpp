// SPDX-License-Identifier: GPL-2.0-or-later
#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include "core/hle/service/ac/ap_list.h"

using namespace Service::AC;

int main() {
    static_assert(sizeof(ApInfo) == 52);
    static_assert(offsetof(ApInfo, bssid) == 36);
    static_assert(offsetof(ApInfo, signal_strength) == 44);
    static_assert(offsetof(ApInfo, channel) == 47);
    static_assert(offsetof(ApInfo, security) == 48);
    assert(StrengthFromRssi(-127) == 0);
    assert(StrengthFromRssi(-60) == 40);
    assert(StrengthFromRssi(20) == 100);
    HostApInfo hidden{"", {2, 0, 0, 0, 0, 1}, -60, 1, ApSecurity::Open};
    HostApInfo weak{"weak", {2, 0, 0, 0, 0, 2}, -90, 13, ApSecurity::Secured};
    HostApInfo duplicate = hidden;
    duplicate.rssi = -80;
    HostApInfo wrong_band{"5GHz", {2, 0, 0, 0, 0, 3}, -20, 0, ApSecurity::Open};
    auto list = BuildApList({weak, wrong_band, duplicate, hidden}, 32);
    assert(list.size() == 2);
    assert(list[0].bssid == hidden.bssid);
    assert(list[0].ssid_length == 0);
    assert(list[0].signal_strength == 40);
    assert(list[0].link_level == 3);
    assert(list[1].channel == 13);
    assert(list[1].security == (std::array<u8, 4>{5, 5, 0, 0}));
    assert(BuildApList({hidden, weak}, 1).size() == 1);
    assert(BuildApList({hidden}, 0).empty());
    assert(BuildApList({}, 32).empty());
    hidden.ssid = std::string(50, 'x');
    auto entry = ToApInfo(hidden);
    assert(entry.ssid_length == 32);
    assert(entry.ssid.back() == 'x');
    const auto* bytes = reinterpret_cast<const u8*>(&entry);
    assert(bytes[0] == 32 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0);
    std::vector<HostApInfo> many;
    for (u8 i = 0; i < 40; ++i) {
        auto ap = weak;
        ap.bssid[5] = i;
        many.push_back(ap);
    }
    assert(BuildApList(many, 100).size() == 32);
    std::cout << "PASS: 52-byte AP layout, endian encoding, empty/hidden SSIDs, RSSI, "
                 "2.4GHz filter, sorting, deduplication, bounds and 32-entry limit\n";
}
