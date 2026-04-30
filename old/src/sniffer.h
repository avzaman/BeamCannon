#pragma once
#include <string>
#include <vector>
#include <pcap.h>
#include "core_types.h"

class Sniffer {
public:
    Sniffer(const std::string& iface, bool debug);
    std::vector<APInfo> scan_aps(int timeout_secs);
    std::vector<ClientInfo> scan_clients(const APInfo& target_ap, int timeout_secs);

private:
    std::string iface_;
    bool debug_;
};
