#pragma once
#include <string>
#include "core_types.h"

struct CachedForgery {
    bool ready = false;
    // Add raw byte buffers here to hold your modified BFI frames
};

class Injector {
public:
    Injector(const std::string& iface, bool debug);
    void run_pillage(const APInfo& ap, const ClientInfo& victim);
    void run_plunder(const APInfo& ap, const ClientInfo& victim, const ClientInfo& qm);

private:
    std::string iface_;
    bool debug_;
    CachedForgery victim_cache_;
};
