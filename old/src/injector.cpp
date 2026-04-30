#include "injector.h"
#include <iostream>
#include <pcap.h>

Injector::Injector(const std::string& iface, bool debug) : iface_(iface), debug_(debug) {}

void Injector::run_pillage(const APInfo& ap, const ClientInfo& victim) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface_.c_str(), 65535, 1, 10, errbuf);
    
    // Listen for AP NDPA and Victim BFI
    std::string bpf = "(wlan[0] == 0x54 and wlan addr2 " + ap.bssid + ") or "
                      "((wlan[0] == 0xd0 or wlan[0] == 0xe0) and wlan addr2 " + victim.mac + ")";
                      
    struct bpf_program fp;
    pcap_compile(handle, &fp, bpf.c_str(), 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    std::cout << "[*] Engaging attack loop. Press Ctrl+C to stop.\n";
    
    while (true) {
        if (pcap_next_ex(handle, &hdr, &pkt) != 1) continue;
        
        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        uint8_t subtype = pkt[rt_len] & 0xFC;

        if (subtype == 0x54) {
            if (victim_cache_.ready) {
                if (debug_) std::cout << "[DEBUG] NDPA Detected! Triggering cached injection.\n";
                // TODO: Insert your pcap_inject logic here using the updated dialog token
            }
        } 
        else if (subtype == 0xD0 || subtype == 0xE0) {
            if (debug_) std::cout << "[DEBUG] Captured victim BFI. Calculating and caching matrices.\n";
            // TODO: Extract matrix, apply Gram-Schmidt nulling math, and update victim_cache_
            victim_cache_.ready = true;
        }
    }
}

void Injector::run_plunder(const APInfo& ap, const ClientInfo& victim, const ClientInfo& qm) {
    // Similar to run_pillage, but state machine requires calculating 
    // the interference matrix between both the Victim and the Quartermaster (QM).
    std::cout << "[!] Plunder mode initialized.\n";
}
