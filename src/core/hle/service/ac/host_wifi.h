// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <optional>
#include <vector>
#include "core/hle/service/ac/ap_list.h"

namespace Service::AC {
std::optional<std::vector<HostApInfo>> ScanPlatformWifi();
}
