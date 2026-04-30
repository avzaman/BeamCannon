#include "sniffer.h"
#include <iostream>
#include <map>
#include <cstring>
#include <time.h>

Sniffer::Sniffer(const std::string& iface, bool debug) : iface_(iface), debug_(debug) {}

std::vector<APInfo> Sniffer::scan_aps(int timeout_secs) {
    std::vector<APInfo> results;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface_.c_str(), 65535, 1, 100, errbuf);
    if (!handle) return results;

    // Filter for Beacons (0x80)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "wlan[0] == 0x80", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
    }

    std::map<std::string, APInfo> ap_map;
    time_t start = time(NULL);
    
    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;
    
    while (time(NULL) - start < timeout_secs) {
        if (pcap_next_ex(handle, &hdr, &pkt) != 1) continue;
        
        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        const uint8_t* mac_hdr = pkt + rt_len;
        
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac_hdr[16], mac_hdr[17], mac_hdr[18], mac_hdr[19], mac_hdr[20], mac_hdr[21]);
                 
        if (ap_map.find(bssid_str) == ap_map.end()) {
            APInfo ap;
            ap.bssid = bssid_str;
            memcpy(ap.bssid_raw, mac_hdr + 16, 6);
            ap.channel = 0; // Requires parser to extract from tagged parameters
            ap.ssid = "Parsed_SSID"; // Stub for parsing logic
            ap_map[bssid_str] = ap;
            if (debug_) std::cout << "[DEBUG] Found AP: " << bssid_str << "\n";
        }
    }
    pcap_close(handle);
    for (auto const& [key, val] : ap_map) results.push_back(val);
    return results;
}

std::vector<ClientInfo> Sniffer::scan_clients(const APInfo& target_ap, int timeout_secs) {
    std::vector<ClientInfo> results;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface_.c_str(), 65535, 1, 10, errbuf);
    
    // Filter for NDPA (0x54), Action (0xD0), Action No Ack (0xE0)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "wlan[0] == 0x54 or wlan[0] == 0xd0 or wlan[0] == 0xe0", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
    }

    std::map<std::string, ClientInfo> client_map;
    time_t start = time(NULL);
    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    while (time(NULL) - start < timeout_secs) {
        if (pcap_next_ex(handle, &hdr, &pkt) != 1) continue;
        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        const uint8_t* mac_hdr = pkt + rt_len;
        uint8_t subtype = mac_hdr[0] & 0xFC;

        if (subtype == 0xD0 || subtype == 0xE0) {
            // Check if frame is directed to the AP
            if (memcmp(mac_hdr + 4, target_ap.bssid_raw, 6) != 0) continue;
            
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac_hdr[10], mac_hdr[11], mac_hdr[12], mac_hdr[13], mac_hdr[14], mac_hdr[15]);
                     
            if (client_map.find(mac_str) == client_map.end()) {
                ClientInfo c;
                c.mac = mac_str;
                memcpy(c.mac_raw, mac_hdr + 10, 6);
                c.rssi = -50; // Stub
                client_map[mac_str] = c;
                if (debug_) std::cout << "[DEBUG] Found Client BFI: " << mac_str << "\n";
            }
        }
    }
    pcap_close(handle);
    for (auto const& [key, val] : client_map) results.push_back(val);
    return results;
}
