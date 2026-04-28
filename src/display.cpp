#include "display.h"
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string fmt_uptime(long s) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02ld:%02ld:%02ld", s/3600, (s%3600)/60, s%60);
    return std::string(buf);
}

static std::string bar(double ratio, int width = 20) {
    // ratio in [0,1]; filled with block chars
    int filled = (int)std::round(ratio * width);
    filled = std::max(0, std::min(filled, width));
    std::string s(filled, '\xe2'); // UTF-8 lead byte for block
    // Use ASCII fallback '#' for simplicity and portability
    return std::string(filled, '#') + std::string(width - filled, '-');
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

Display::Display() {}

void Display::clear_screen() {
    printf(CURSOR_CLEAR CURSOR_HOME);
    fflush(stdout);
}

void Display::move_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
}

void Display::erase_line() {
    printf(ERASE_LINE);
}

void Display::banner() {
    clear_screen();
    printf(COL_CYAN COL_BOLD);
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║        B E A M C A N N O N   v1.0               ║\n");
    printf("║   Wi-Fi Beamforming Injection Tool               ║\n");
    printf("║   Based on BeamCraft (MobiCom'24)                ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf(COL_RESET "\n");
    fflush(stdout);
}

void Display::print_ap_list(const std::vector<APInfo>& aps) {
    printf(COL_BOLD "  #   SSID                BSSID              CH    BW     RSSI  STD\n" COL_RESET);
    printf("  %s\n", std::string(68, '-').c_str());
    for (size_t i = 0; i < aps.size(); i++) {
        const auto& ap = aps[i];
        printf("  %-3zu %-20s %-18s %-5d %-6dMHz %-5d %s\n",
               i + 1,
               ap.ssid.substr(0, 20).c_str(),
               ap.bssid.c_str(),
               ap.channel,
               ap.bw_mhz,
               ap.rssi,
               ap.standard.c_str());
    }
    printf("\n");
    fflush(stdout);
}

void Display::print_client_list(const std::vector<ClientInfo>& clients,
                                  double sounding_ms) {
    printf(COL_BOLD "  #   MAC                 STREAMS  RSSI   STD   LAST SEEN\n" COL_RESET);
    printf("  %s\n", std::string(60, '-').c_str());
    for (size_t i = 0; i < clients.size(); i++) {
        const auto& c = clients[i];
        double age = 0.0; // already filtered to active
        printf("  %-3zu %-20s %-8d %-6d %-5s %.1fs ago\n",
               i + 1,
               c.mac.c_str(),
               c.Nc,
               c.rssi,
               c.standard.c_str(),
               age);
    }
    if (sounding_ms > 0)
        printf("\n  Detected sounding interval: %.1f ms\n", sounding_ms);
    printf("\n");
    fflush(stdout);
}

void Display::draw_attack_frame(const APInfo& ap,
                                  AttackMode mode,
                                  const std::vector<ClientInfo>& victims,
                                  const ClientInfo* quartermaster,
                                  const std::string& log_path,
                                  double sounding_ms) {
    clear_screen();
    printf(COL_CYAN COL_BOLD
           "╔══════════════════════════════════════════════════╗\n"
           "║  B E A M C A N N O N  v1.0  %-21s║\n"
           "╚══════════════════════════════════════════════════╝\n"
           COL_RESET,
           (mode == AttackMode::PILLAGE ? "[ PILLAGING ]  " : "[ PLUNDERING ] "));

    printf("AP     : " COL_WHITE "%s" COL_RESET "  %s  CH%d %dMHz 802.11%s\n",
           ap.ssid.c_str(), ap.bssid.c_str(),
           ap.channel, ap.bw_mhz, ap.standard.c_str());
    printf("Log    : %s\n", log_path.c_str());
    if (quartermaster)
        printf("Qrtmstr: " COL_GREEN "%s" COL_RESET "\n",
               quartermaster->mac.c_str());
    printf("Uptime : 00:00:00\n");  // row 6 — updated dynamically
    printf("%s\n", std::string(52, '-').c_str());

    // Row 8 — broadside counters (updated dynamically)
    printf("Broadsides : %-6d  Success : %-6d  Miss : %-6d\n", 0, 0, 0);
    printf("%s\n", std::string(52, '-').c_str());
    printf("Volley timing (last %d broadsides):\n", VOLLEY_WINDOW);

    // Marks rows start here
    marks_row_ = 11;
    stats_row_ = 6;

    for (size_t i = 0; i < victims.size(); i++) {
        printf("  Mark %-2zu  %-20s  -----ms  [--------------------]  [-----]\n",
               i + 1, victims[i].mac.c_str());
    }

    printf("\n");
    printf("  Sounding interval : %.1f ms\n", sounding_ms);
    printf("  Margin            : -----\n");
    printf("\n");
    printf(COL_BOLD "[Ctrl+C] Stand down\n" COL_RESET);
    fflush(stdout);
}

std::string Display::color_timing(double compute_ms, double sounding_ms) {
    if (sounding_ms <= 0) return COL_WHITE;
    double ratio = compute_ms / sounding_ms;
    if (ratio < 0.40) return COL_GREEN;
    if (ratio < 0.70) return COL_YELLOW;
    return COL_RED;
}

void Display::record_sample(const std::string& mac,
                              double compute_ms,
                              bool /*ok*/) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& dq = timing_windows_[mac];
    dq.push_back(compute_ms);
    if ((int)dq.size() > VOLLEY_WINDOW)
        dq.pop_front();
}

void Display::update_attack_stats(const AttackStats& stats,
                                    const std::vector<InjectSample>& /*samples*/,
                                    double sounding_ms,
                                    long uptime_s) {
    std::lock_guard<std::mutex> lock(mtx_);

    // Update uptime line
    move_cursor(stats_row_, 1);
    erase_line();
    printf("Uptime : %s", fmt_uptime(uptime_s).c_str());

    // Update broadside counters
    move_cursor(stats_row_ + 2, 1);
    erase_line();
    printf("Broadsides : %-6d  Success : " COL_GREEN "%-6d" COL_RESET
           "  Miss : " COL_RED "%-6d" COL_RESET,
           stats.total_broadsides.load(),
           stats.success_count.load(),
           stats.fail_count.load());

    // Update per-victim timing rows
    // Build a map of MAC -> victim index for row positioning
    int row = marks_row_;
    for (auto& kv : timing_windows_) {
        const std::string& mac = kv.first;
        auto& dq = kv.second;
        if (dq.empty()) { row++; continue; }

        double avg = std::accumulate(dq.begin(), dq.end(), 0.0) / dq.size();
        double ratio = (sounding_ms > 0) ? avg / sounding_ms : 0.0;

        const char* col   = color_timing(avg, sounding_ms).c_str();
        const char* label = (ratio < 0.40) ? "CLEAR"
                          : (ratio < 0.70) ? "CAUTION"
                          : "DANGER";

        std::string progress = bar(ratio, 20);

        move_cursor(row, 1);
        erase_line();
        printf("  %-20s  %s%5.2fms" COL_RESET "  [%s%s" COL_RESET "]  [%s%s" COL_RESET "]",
               mac.c_str(),
               col, avg,
               col, progress.c_str(),
               col, label);
        row++;
    }

    // Update margin line (marks_row_ + num_victims + 2)
    move_cursor(row + 2, 1);
    erase_line();
    if (sounding_ms > 0 && !timing_windows_.empty()) {
        // Worst case (max avg across all victims)
        double worst = 0.0;
        for (auto& kv : timing_windows_) {
            if (kv.second.empty()) continue;
            double avg = std::accumulate(kv.second.begin(),
                                          kv.second.end(), 0.0)
                       / kv.second.size();
            worst = std::max(worst, avg);
        }
        double margin = sounding_ms - worst;
        const char* mcol = (margin > sounding_ms * 0.60) ? COL_GREEN
                         : (margin > sounding_ms * 0.30) ? COL_YELLOW
                         : COL_RED;
        printf("  Margin : %s%.2f ms" COL_RESET, mcol, margin);
    }

    // Move cursor below the display so any debug output goes there
    move_cursor(row + 5, 1);
    fflush(stdout);
}
