// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/hle/service/ac/host_wifi.h"
#include "common/logging/log.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wlanapi.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>

namespace Service::AC {
namespace {
struct ScanWait {
    std::mutex mutex;
    std::condition_variable cv;
    GUID interface_id{};
    bool completed = false;
};
void WINAPI OnScan(PWLAN_NOTIFICATION_DATA data, PVOID context) {
    if (data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM ||
        (data->NotificationCode != wlan_notification_acm_scan_complete &&
         data->NotificationCode != wlan_notification_acm_scan_fail)) {
        return;
    }
    auto& wait = *static_cast<ScanWait*>(context);
    std::scoped_lock lock{wait.mutex};
    if (IsEqualGUID(wait.interface_id, data->InterfaceGuid)) {
        wait.completed = true;
        wait.cv.notify_one();
    }
}
struct WlanMemory {
    void operator()(void* value) const { if (value) WlanFreeMemory(value); }
};
struct WlanHandle {
    HANDLE handle = nullptr;
    ~WlanHandle() { if (handle) WlanCloseHandle(handle, nullptr); }
};
}

std::optional<std::vector<HostApInfo>> ScanPlatformWifi() {
    WlanHandle client;
    DWORD version = 0;
    DWORD status = WlanOpenHandle(2, nullptr, &version, &client.handle);
    if (status != ERROR_SUCCESS) {
        LOG_WARNING(Service_AC, "WlanOpenHandle failed: {}", status);
        return std::nullopt;
    }
    WLAN_INTERFACE_INFO_LIST* raw_interfaces = nullptr;
    status = WlanEnumInterfaces(client.handle, nullptr, &raw_interfaces);
    std::unique_ptr<WLAN_INTERFACE_INFO_LIST, WlanMemory> interfaces(raw_interfaces);
    if (status != ERROR_SUCCESS || !interfaces || interfaces->dwNumberOfItems == 0) {
        LOG_WARNING(Service_AC, "Wi-Fi adapter unavailable, status={}", status);
        return std::nullopt;
    }
    std::vector<HostApInfo> access_points;
    bool readable = false;
    for (DWORD i = 0; i < interfaces->dwNumberOfItems; ++i) {
        const auto& id = interfaces->InterfaceInfo[i].InterfaceGuid;
        ScanWait wait;
        wait.interface_id = id;
        const bool registered = WlanRegisterNotification(client.handle,
            WLAN_NOTIFICATION_SOURCE_ACM, TRUE, OnScan, &wait, nullptr, nullptr) == ERROR_SUCCESS;
        status = WlanScan(client.handle, &id, nullptr, nullptr, nullptr);
        if (registered && status == ERROR_SUCCESS) {
            std::unique_lock lock{wait.mutex};
            if (!wait.cv.wait_for(lock, std::chrono::seconds(4), [&] { return wait.completed; })) {
                LOG_WARNING(Service_AC, "Wi-Fi scan timed out; using Windows cached results");
            }
        } else {
            LOG_WARNING(Service_AC, "Wi-Fi scan request status={}; using cached results", status);
        }
        // Unregistration waits for pending callbacks; wait remains alive until after this call.
        const DWORD unregistered = WlanRegisterNotification(client.handle,
            WLAN_NOTIFICATION_SOURCE_NONE, TRUE, nullptr, nullptr, nullptr, nullptr);
        if (registered && unregistered != ERROR_SUCCESS) {
            // Close synchronously before destroying the callback context.
            WlanCloseHandle(client.handle, nullptr);
            client.handle = nullptr;
            LOG_WARNING(Service_AC, "Could not unregister Wi-Fi notifications: {}", unregistered);
            return std::nullopt;
        }
        WLAN_BSS_LIST* raw_list = nullptr;
        status = WlanGetNetworkBssList(client.handle, &id, nullptr,
            dot11_BSS_type_infrastructure, FALSE, nullptr, &raw_list);
        std::unique_ptr<WLAN_BSS_LIST, WlanMemory> list(raw_list);
        if (status != ERROR_SUCCESS || !list) {
            LOG_WARNING(Service_AC, "WlanGetNetworkBssList failed: {} (5: location access denied)", status);
            continue;
        }
        readable = true;
        for (DWORD j = 0; j < list->dwNumberOfItems; ++j) {
            const auto& bss = list->wlanBssEntries[j];
            const auto frequency = bss.ulChCenterFrequency / 1000;
            if (frequency < 2412 || frequency > 2472 || (frequency - 2407) % 5 != 0) continue;
            HostApInfo info;
            const auto length = std::min<ULONG>(bss.dot11Ssid.uSSIDLength, 32);
            info.ssid.assign(reinterpret_cast<const char*>(bss.dot11Ssid.ucSSID), length);
            std::copy_n(bss.dot11Bssid, info.bssid.size(), info.bssid.begin());
            info.rssi = static_cast<s16>(std::clamp<LONG>(bss.lRssi, -127, 0));
            info.channel = static_cast<u8>((frequency - 2407) / 5);
            info.security = (bss.usCapabilityInformation & 0x10) ? ApSecurity::Secured : ApSecurity::Open;
            access_points.push_back(std::move(info));
        }
    }
    if (!readable) return std::nullopt;
    return access_points;
}
}
#else
namespace Service::AC {
std::optional<std::vector<HostApInfo>> ScanPlatformWifi() { return std::nullopt; }
}
#endif
