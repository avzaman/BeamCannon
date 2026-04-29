#include "scanner.h"
#include "bfi.h"
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <sys/time.h>

// ---------------------------------------------------------------------------
// 802.11 frame offset constants
// ---------------------------------------------------------------------------
#define RADIOTAP_HDR_LEN_OFFSET 2   // uint16 at byte 2 of radiotap header
#define FC_OFFSET               0   // frame control within 802.11 MAC header
#define FC_TYPE_MASK            0x0C
#define FC_SUBTYPE_MASK         0xF0
#define FC_TYPE_MGMT            0x00
#define FC_SUBTYPE_BEACON       0x80
#define FC_SUBTYPE_ACTION       0xD0  // 0xD0 = 1101 0000

// IE tags
#define IE_SSID                 0
#define IE_DS_PARAM             3    // current channel
#define IE_HT_OPERATION         61
#define IE_VHT_OPERATION        192
#define IE_HE_OPERATION         255  // Extension tag 36

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static double now_secs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

std::string Scanner::mac_to_str(const uint8_t* m) {
    char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return std::string(buf);
}

int Scanner::parse_rssi(const uint8_t* pkt, int len) {
    if (len < 4) return -100;
    uint16_t rt_len = pkt[2] | (pkt[3] << 8);
    if (rt_len > len) return -100;
    // Walk radiotap fields to find ANTENNA_SIGNAL (field bit 5)
    // Radiotap present flags at bytes 4-7
    uint32_t present = pkt[4] | (pkt[5] << 8) | (pkt[6] << 16) | (pkt[7] << 24);
    int offset = 8;
    // Skip extended present flags
    while ((present & (1u << 31)) && offset + 4 <= rt_len) {
        present = pkt[offset] | (pkt[offset+1] << 8) |
                  (pkt[offset+2] << 16) | (pkt[offset+3] << 24);
        offset += 4;
    }
    // Reset to first present word
    present = pkt[4] | (pkt[5] << 8) | (pkt[6] << 16) | (pkt[7] << 24);
    offset = 8;
    // Bit 0: TSFT (8 bytes)
    if (present & (1u << 0)) {
        offset = (offset + 7) & ~7; // align to 8
        offset += 8;
    }
    // Bit 1: FLAGS (1 byte)
    if (present & (1u << 1)) offset += 1;
    // Bit 2: RATE (1 byte)
    if (present & (1u << 2)) offset += 1;
    // Bit 3: CHANNEL (2+2 bytes, align 2)
    if (present & (1u << 3)) {
        offset = (offset + 1) & ~1;
        offset += 4;
    }
    // Bit 4: FHSS (2 bytes)
    if (present & (1u << 4)) offset += 2;
    // Bit 5: ANTENNA_SIGNAL (1 byte, signed)
    if (present & (1u << 5)) {
        if (offset < rt_len)
            return (int8_t)pkt[offset];
    }
    return -100;
}

// Parse beacon IEs to fill APInfo fields
bool Scanner::parse_beacon(const uint8_t* body, int body_len, APInfo& out) {
    // Beacon body: 8 bytes timestamp, 2 capability interval, 2 capability info
    // then IEs start at offset 12
    if (body_len < 12) return false;
    int ie_offset = 12;
    out.bw_mhz = 20;
    out.standard = "n";
    bool got_ssid = false;

    while (ie_offset + 2 <= body_len) {
        uint8_t id  = body[ie_offset];
        uint8_t len = body[ie_offset + 1];
        const uint8_t* val = body + ie_offset + 2;
        if (ie_offset + 2 + len > body_len) break;

        switch (id) {
        case IE_SSID:
            out.ssid = std::string((const char*)val, len);
            got_ssid = true;
            break;

        case IE_DS_PARAM:
            if (len >= 1) out.channel = val[0];
            break;

        case IE_HT_OPERATION:
            // HT Operation IE: secondary channel offset at byte 1 bits 0-1
            if (len >= 2) {
                uint8_t sec = val[1] & 0x03;
                if (sec != 0) out.bw_mhz = std::max(out.bw_mhz, 40);
                out.standard = "n";
            }
            break;

        case IE_VHT_OPERATION:
            // VHT Operation IE
            if (len >= 3) {
                uint8_t width = val[0];
                uint8_t chan1 = val[1];
                // uint8_t chan2 = val[2]; // for 80+80
                if (width == 0) {
                    out.bw_mhz = std::max(out.bw_mhz, 40);
                } else if (width == 1) {
                    out.bw_mhz = 80;
                    // center freq = 5000 + 5*chan1
                    out.center_freq2 = 5000 + 5 * chan1;
                } else if (width == 2 || width == 3) {
                    out.bw_mhz = 160;
                }
                out.standard = "ac";
            }
            break;

        case 255: // Extension element
            // HE Operation uses extension tag 36
            if (len >= 1 && val[0] == 36) {
                out.standard = "ax";
                // Parse HE Operation for channel width
                // 6-byte HE Operation params + 3-byte BSS Color
                // Byte at val[1]: BSS color
                // Bytes at val[4..5]: HE Operation params
                if (len >= 7) {
                    uint8_t chwidth = (val[4] >> 0) & 0x7;
                    if (chwidth >= 2) out.bw_mhz = std::max(out.bw_mhz, 80);
                    if (chwidth >= 3) out.bw_mhz = 160;
                }
            }
            break;
        }

        ie_offset += 2 + len;
    }

    // Derive primary center frequency from channel number
    // 5GHz: freq = 5000 + 5 * channel
    out.center_freq = 5000 + 5 * out.channel;
    if (out.center_freq2 == 0) out.center_freq2 = out.center_freq;

    return got_ssid;
}

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

Scanner::Scanner(const std::string& iface) : iface_(iface) {}
Scanner::~Scanner() {}

bool Scanner::set_channel_iw(int channel, int bw_mhz, int center_freq2) {
    char cmd[256];
    if (bw_mhz <= 20) {
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/iw dev %s set channel %d 2>&1 >/dev/null",
                 iface_.c_str(), channel);
    } else if (bw_mhz == 40) {
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/iw dev %s set channel %d HT40+ 2>&1 >/dev/null",
                 iface_.c_str(), channel);
    } else {
        // 80/160 MHz: use freq + width + center2
        int primary_freq = 5000 + 5 * channel;
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/iw dev %s set freq %d %d %d 2>&1 >/dev/null",
                 iface_.c_str(), primary_freq, bw_mhz, center_freq2);
    }
    return system(cmd) == 0;
}

bool Scanner::lock_channel(int channel, int bw_mhz, int center_freq2) {
    return set_channel_iw(channel, bw_mhz, center_freq2);
}

std::vector<APInfo> Scanner::scan_aps() {
    // 5GHz channels to scan: non-DFS first (36-48), then DFS (52-144),
    // then UNII-3 (149-177)
    // Scan all possible 5GHz primary channels at 20MHz.
    // Beacons are always transmitted on the primary 20MHz channel regardless
    // of the AP's operating bandwidth. The beacon IE contains the actual
    // operating bandwidth which parse_beacon extracts.
    // Scanning all channels including non-primary ones (e.g. 153 when primary
    // is 149) ensures we catch APs regardless of their channel plan.
    static const int channels_5g[] = {
        36, 40, 44, 48,           // UNII-1
        52, 56, 60, 64,           // UNII-2A (DFS)
        100,104,108,112,          // UNII-2C (DFS)
        116,120,124,128,
        132,136,140,144,
        149,153,157,161,165,177   // UNII-3
    };
    static const int n_channels = sizeof(channels_5g) / sizeof(channels_5g[0]);

    std::map<std::string, APInfo> seen; // BSSID -> APInfo

    char errbuf[PCAP_ERRBUF_SIZE];

    // Force NIC to 5GHz band before scanning.
    // Some drivers initialise in 2.4GHz mode after monitor mode is set
    // and will silently ignore channel number commands without this.
    {
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/iw dev %s set freq 5180 HT40+ 2>/dev/null",
                 iface_.c_str());
        system(cmd);
        usleep(100000); // 100ms for band switch to settle
    }

    // Single persistent pcap handle for entire scan.
    // Opening/closing per channel causes rapid promiscuous mode toggling
    // which damages rtw88 USB drivers. Channel changes via iw work fine
    // while pcap handle stays open on RTL8812BU.
    pcap_t* pcap = pcap_open_live(iface_.c_str(), 65535, 1, 50, errbuf);
    if (!pcap) return {};
    pcap_setnonblock(pcap, 1, errbuf);

    struct bpf_program fp;
    const char* filter = "type mgt subtype beacon";
    if (pcap_compile(pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(pcap, &fp);

    for (int ci = 0; ci < n_channels; ci++) {
        int ch = channels_5g[ci];
        // Scan at 20MHz - beacons always on primary 20MHz channel
        set_channel_iw(ch, 20, 0);
        usleep(100000); // 100ms settle after channel change

        // 500ms dwell covers 2.5x the standard 200ms beacon interval
        double t_end = now_secs() + 0.50;
        struct pcap_pkthdr* hdr;
        const uint8_t* pkt;

        while (now_secs() < t_end) {
            int r = pcap_next_ex(pcap, &hdr, &pkt);
            if (r != 1) {
                usleep(1000);
                continue;
            }

            uint16_t rt_len = pkt[2] | (pkt[3] << 8);
            if ((int)hdr->caplen < rt_len + 24) continue;

            const uint8_t* mac_hdr = pkt + rt_len;
            // BSSID is at bytes 16-21 of 802.11 header for beacon
            const uint8_t* bssid = mac_hdr + 16;
            std::string bssid_str = mac_to_str(bssid);

            if (seen.count(bssid_str)) continue;

            const uint8_t* body = mac_hdr + 24;
            int body_len = (int)hdr->caplen - rt_len - 24;

            APInfo ap{};
            ap.channel = ch;
            ap.bw_mhz  = 20;
            ap.center_freq2 = 0;
            if (!parse_beacon(body, body_len, ap)) continue;

            memcpy(ap.bssid_raw, bssid, 6);
            ap.bssid = bssid_str;
            ap.rssi  = parse_rssi(pkt, (int)hdr->caplen);
            seen[bssid_str] = ap;
        }
    }

    pcap_close(pcap);

    std::vector<APInfo> result;
    result.reserve(seen.size());
    for (auto& kv : seen) result.push_back(kv.second);

    // Sort by RSSI descending
    std::sort(result.begin(), result.end(),
              [](const APInfo& a, const APInfo& b) {
                  return a.rssi > b.rssi;
              });

    return result;
}

std::vector<ClientInfo> Scanner::scan_clients(const APInfo& ap,
                                               int timeout_ms,
                                               double& out_sounding_ms) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(iface_.c_str(), 65535, 1, 50, errbuf);
    if (!pcap) return {};
    pcap_setnonblock(pcap, 1, errbuf);

    // Capture management action frames from clients directed to this AP
    // and NDP announcement frames from the AP
    char filter[256];
    snprintf(filter, sizeof(filter),
             "type mgt and not (subtype beacon or subtype probe-req "
             "or subtype probe-resp or subtype assoc-req or subtype assoc-resp "
             "or subtype reassoc-req or subtype reassoc-resp "
             "or subtype auth or subtype deauth or subtype disassoc)");
    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(pcap, &fp);

    std::map<std::string, ClientInfo> clients;
    double t_start = now_secs();
    double t_end   = t_start + timeout_ms / 1000.0;

    // Track NDP announcement times to measure sounding interval
    std::vector<double> ndp_times;

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    while (now_secs() < t_end) {
        int r = pcap_next_ex(pcap, &hdr, &pkt);
        if (r != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 24) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        uint8_t fc0 = mac_hdr[0];

        // Check frame type: management (00) and action subtype (1101)
        if ((fc0 & 0x0C) != 0x00) continue;

        const uint8_t* ta  = mac_hdr + 10; // Transmitter address
        const uint8_t* ra  = mac_hdr + 4;  // Receiver address (AP)
        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4; // -4 FCS
        if (body_len < 2) continue;

        // NDP Announcement from AP: subtype 0xe0 (action no-ack)
        // The AP sends it to clients before NDP
        bool is_from_ap = (memcmp(ta, ap.bssid_raw, 6) == 0);

        if (is_from_ap) {
            // Record NDP announcement timing for sounding interval detection
            // NDP announcement has category 21 (VHT) or 30 (HE), action 1
            if ((body[0] == 0x15 || body[0] == 0x1e) && body[1] == 0x01) {
                ndp_times.push_back(now_secs());
            }
            continue;
        }

        // BFI report from client to AP
        bool to_ap = (memcmp(ra, ap.bssid_raw, 6) == 0);
        if (!to_ap) continue;

        BFIParams params;
        if (!bfi_detect(body, body_len, params)) continue;

        std::string mac = mac_to_str(ta);
        ClientInfo& ci = clients[mac];
        memcpy(ci.mac_raw, ta, 6);
        ci.mac       = mac;
        ci.Nc        = params.Nc;
        ci.rssi      = parse_rssi(pkt, (int)hdr->caplen);
        ci.standard  = (params.standard == BFIStandard::HE) ? "HE" : "VHT";
        ci.last_seen = now_secs();
        ci.active    = true;
    }

    pcap_close(pcap);

    // Compute sounding interval from NDP announcement timestamps
    out_sounding_ms = 500.0; // default
    if (ndp_times.size() >= 2) {
        double sum = 0;
        int cnt = 0;
        for (size_t i = 1; i < ndp_times.size(); i++) {
            double delta = (ndp_times[i] - ndp_times[i-1]) * 1000.0;
            if (delta > 5.0 && delta < 5000.0) { // sanity range
                sum += delta;
                cnt++;
            }
        }
        if (cnt > 0) out_sounding_ms = sum / cnt;
    }

    std::vector<ClientInfo> result;
    result.reserve(clients.size());
    for (auto& kv : clients) result.push_back(kv.second);

    std::sort(result.begin(), result.end(),
              [](const ClientInfo& a, const ClientInfo& b) {
                  return a.rssi > b.rssi;
              });

    return result;
}
