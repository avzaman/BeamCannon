#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct APInfo {
    std::string bssid;
    std::string ssid;
    int channel;
    uint8_t bssid_raw[6];
};

struct ClientInfo {
    std::string mac;
    uint8_t mac_raw[6];
    int rssi;
    int Nc; // Spatial streams
    std::string standard;
};

enum class AttackMode {
    NONE,
    PILLAGE, // Disruption
    PLUNDER  // Hijacking/Boosting
};
