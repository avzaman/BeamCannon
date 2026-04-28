#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

// Represents a discovered access point
struct APInfo {
    std::string ssid;
    std::string bssid;        // "aa:bb:cc:dd:ee:ff" format
    uint8_t     bssid_raw[6];
    int         channel;
    int         bw_mhz;       // 20, 40, 80, 160
    int         center_freq;  // MHz, primary channel center
    int         center_freq2; // MHz, secondary center for 80MHz (VHT/HE op ie)
    int         rssi;
    std::string standard;     // "ac", "ax", "n" etc
};

// Represents a beamforming client discovered on the target AP
struct ClientInfo {
    std::string mac;
    uint8_t     mac_raw[6];
    int         Nc;           // Stream count from BFI frame
    int         rssi;
    std::string standard;     // "VHT" or "HE"
    double      last_seen;    // seconds since epoch
    bool        active;
};

class Scanner {
public:
    // iface: monitor mode interface name e.g. "wlan0mon"
    explicit Scanner(const std::string& iface);
    ~Scanner();

    // Scan all supported 5GHz channels for 2-3 seconds.
    // Returns list of discovered APs sorted by signal strength.
    std::vector<APInfo> scan_aps();

    // Listen on the target AP's channel for one sounding window
    // (or timeout_ms if no NDP seen) and return discovered BF clients.
    // Also detects the sounding interval in ms.
    std::vector<ClientInfo> scan_clients(const APInfo& ap,
                                          int timeout_ms,
                                          double& out_sounding_interval_ms);

    // Lock NIC to given channel and width for subsequent operations
    bool lock_channel(int channel, int bw_mhz, int center_freq2);

    const std::string& iface() const { return iface_; }

private:
    std::string iface_;

    // Set channel via iw shell command
    bool set_channel_iw(int channel, int bw_mhz, int center_freq2);

    // Format MAC bytes to string
    static std::string mac_to_str(const uint8_t* mac);

    // Parse RSSI from Radiotap header
    static int parse_rssi(const uint8_t* pkt, int len);

    // Parse channel/BW from beacon IEs
    static bool parse_beacon(const uint8_t* body, int body_len, APInfo& out);
};
