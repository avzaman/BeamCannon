#pragma once
#include <vector>
#include <complex>
#include <cstdint>
#include <string>
#include <Eigen/Core>

// 802.11 standard identifiers for beamforming frame types
enum class BFIStandard {
    VHT,   // 802.11ac  - action category 21 (0x15)
    HE,    // 802.11ax  - action category 30
    UNKNOWN
};

// Parameters auto-detected from a captured BFI frame
struct BFIParams {
    BFIStandard standard = BFIStandard::UNKNOWN;
    int Nr   = 0;   // AP transmit antennas
    int Nc   = 0;   // Client receive streams (columns in V)
    int Nst  = 0;   // Number of subcarriers
    int Ng   = 1;   // Subcarrier grouping (HE only, 1/2/4/16)
    int Nb_phi = 0; // Quantization bits for phi angles
    int Nb_psi = 0; // Quantization bits for psi angles
    int feedback_len = 0; // Byte length of the raw feedback matrix field
};

// A decoded feedback matrix: one complex matrix per subcarrier
using FeedbackMatrix = std::vector<Eigen::Matrix<std::complex<float>,
                                                  Eigen::Dynamic,
                                                  Eigen::Dynamic>>;

// Detect BFI standard and parameters from a raw captured frame.
// frame_body points to the start of the 802.11 frame body
// (past the radiotap and 802.11 MAC header).
// Returns false if the frame is not a recognised BFI frame.
bool bfi_detect(const uint8_t* frame_body,
                int frame_body_len,
                BFIParams& out_params);

// Decompress a raw BFI byte buffer into a vector of per-subcarrier
// feedback matrices V[kk], size Nr x Nc each.
FeedbackMatrix bfi_decompress(const uint8_t* feedback_bytes,
                               const BFIParams& params);

// Compress a vector of per-subcarrier matrices back into a BFI byte buffer.
// Output buffer must be pre-allocated to params.feedback_len bytes.
void bfi_compress(const FeedbackMatrix& matrices,
                  const BFIParams& params,
                  uint8_t* out_bytes);

// Forge a disruption feedback matrix: orthogonal to the genuine V.
// Returns the forged matrix set ready for bfi_compress.
FeedbackMatrix bfi_forge_disrupt(const FeedbackMatrix& genuine,
                                  const BFIParams& params);

// Forge a plunder feedback matrix for the victim: orthogonal to the
// beneficiary's genuine matrix, maximising beneficiary SINR.
FeedbackMatrix bfi_forge_plunder(const FeedbackMatrix& victim_genuine,
                                  const FeedbackMatrix& beneficiary_genuine,
                                  const BFIParams& params);

// Human-readable parameter description for display/logging
std::string bfi_params_str(const BFIParams& params);

// Returns just the standard name string ("VHT", "HE", "UNKNOWN")
std::string params_standard_str(const BFIParams& params);
