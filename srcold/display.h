#pragma once
#include "scanner.h"
#include "injector.h"
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>

// ANSI color codes
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[31m"
#define COL_GREEN   "\033[32m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_WHITE   "\033[97m"
#define COL_BOLD    "\033[1m"

// Cursor / screen control
#define CURSOR_HOME     "\033[H"
#define CURSOR_CLEAR    "\033[2J"
#define CURSOR_SAVE     "\033[s"
#define CURSOR_RESTORE  "\033[u"
#define ERASE_LINE      "\033[2K"

// Move cursor to row, col (1-indexed)
#define CURSOR_POS(r, c) "\033[" #r ";" #c "H"

// Rolling window size for timing average
static const int VOLLEY_WINDOW = 20;

class Display {
public:
    Display();

    // ---- Startup screens (print once, no redraw) ----
    void banner();
    void print_ap_list(const std::vector<APInfo>& aps);
    void print_client_list(const std::vector<ClientInfo>& clients,
                            double sounding_ms);

    // ---- Live attack screen (redraws in place) ----
    // Call once to draw the static frame
    void draw_attack_frame(const APInfo& ap,
                            AttackMode mode,
                            const std::vector<ClientInfo>& victims,
                            const ClientInfo* quartermaster,
                            const std::string& log_path,
                            double sounding_ms);

    // Call after each broadside to update the dynamic regions
    void update_attack_stats(const AttackStats& stats,
                              const std::vector<InjectSample>& samples,
                              double sounding_ms,
                              long uptime_s);

    // Record a timing sample for a given victim MAC into the rolling window
    void record_sample(const std::string& mac, double compute_ms, bool ok);

    // ---- Utilities ----
    static void clear_screen();
    static void move_cursor(int row, int col);
    static void erase_line();
    static std::string color_timing(double compute_ms, double sounding_ms);

private:
    // Rolling timing windows per victim MAC
    std::map<std::string, std::deque<double>> timing_windows_;
    std::mutex mtx_;

    // Row at which the dynamic stats block starts (set in draw_attack_frame)
    int stats_row_ = 10;
    int marks_row_ = 14;
};
