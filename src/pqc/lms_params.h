// lms_params.h - written and placed in the public domain by Colin Brown
//                LMS/LM-OTS internal parameters and helpers (RFC 8554)

#ifndef CRYPTOPP_LMS_PARAMS_H
#define CRYPTOPP_LMS_PARAMS_H

#include <cryptopp/config.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(LMS_Internal)

// ==================== Domain Separation Constants ====================
// RFC 8554 Section 4.2 / Section 5.1

static constexpr uint16_t D_PBLC = 0x8080;
static constexpr uint16_t D_MESG = 0x8181;
static constexpr uint16_t D_LEAF = 0x8282;
static constexpr uint16_t D_INTR = 0x8383;

// ==================== Big-Endian Encoding Helpers ====================

/// \brief Encode a 32-bit value as 4 bytes big-endian (u32str in RFC 8554)
inline void u32str(byte *out, uint32_t val)
{
    out[0] = static_cast<byte>(val >> 24);
    out[1] = static_cast<byte>(val >> 16);
    out[2] = static_cast<byte>(val >> 8);
    out[3] = static_cast<byte>(val);
}

/// \brief Encode a 16-bit value as 2 bytes big-endian (u16str in RFC 8554)
inline void u16str(byte *out, uint16_t val)
{
    out[0] = static_cast<byte>(val >> 8);
    out[1] = static_cast<byte>(val);
}

/// \brief Encode an 8-bit value (u8str in RFC 8554)
inline void u8str(byte *out, uint8_t val)
{
    out[0] = val;
}

// ==================== Coef Extraction ====================
// RFC 8554 Algorithm 1

/// \brief Extract the i-th w-bit coefficient from byte string S
/// \param S the byte string
/// \param i the coefficient index
/// \param w the Winternitz parameter (1, 2, 4, or 8)
/// \return the i-th coefficient value (0 to 2^w - 1)
inline unsigned int coef(const byte *S, unsigned int i, unsigned int w)
{
    // For w=8 this reduces to S[i], but the general form
    // handles w=1, w=2, w=4 as well.
    const unsigned int bitsPerByte = 8;
    const unsigned int byteIndex = (i * w) / bitsPerByte;
    const unsigned int bitOffset = bitsPerByte - (w * (i % (bitsPerByte / w)) + w);
    const unsigned int mask = (1u << w) - 1;
    return (static_cast<unsigned int>(S[byteIndex]) >> bitOffset) & mask;
}

// ==================== Checksum ====================
// RFC 8554 Algorithm 2

/// \brief Compute the LM-OTS checksum over the message hash coefficients
/// \param S the message hash bytes
/// \param w the Winternitz parameter
/// \param ls left-shift value for checksum alignment
/// \param u number of message coefficients (ceil(8*n/w))
/// \return checksum value, left-shifted by ls
inline uint16_t checksum(const byte *S, unsigned int w,
                         unsigned int ls, unsigned int u)
{
    uint32_t sum = 0;
    const unsigned int maxCoef = (1u << w) - 1;
    for (unsigned int i = 0; i < u; i++)
        sum += maxCoef - coef(S, i, w);
    return static_cast<uint16_t>(sum << ls);
}

// ==================== LM-OTS Runtime Parameters ====================

/// \brief Runtime parameter struct for LM-OTS operations
/// \details Allows internal functions to work with any parameter set
///  without template instantiation.
struct OTSParams
{
    uint32_t type_id;   // LM-OTS algorithm type
    unsigned int n;     // hash output length (bytes)
    unsigned int w;     // Winternitz parameter
    unsigned int p;     // number of chains (message + checksum)
    unsigned int ls;    // checksum left-shift
    unsigned int u;     // number of message coefficients

    /// \brief Signature size: type(4) + C(n) + y[0..p-1](p*n)
    size_t SigLen() const { return 4 + n + static_cast<size_t>(p) * n; }
};

/// \brief Runtime parameters for LMOTS_SHA256_N32_W8
inline OTSParams OTSParams_SHA256_N32_W8()
{
    return OTSParams{0x04, 32, 8, 34, 0, 32};
}

// ==================== LMS Runtime Parameters ====================

/// \brief Runtime parameter struct for LMS tree operations
struct LMSParams
{
    uint32_t type_id;   // LMS algorithm type
    unsigned int m;     // hash output length (bytes)
    unsigned int h;     // tree height
};

/// \brief Runtime parameters for LMS_SHA256_M32_H5
inline LMSParams LMSParams_SHA256_M32_H5()
{
    return LMSParams{0x05, 32, 5};
}

/// \brief Runtime parameters for LMS_SHA256_M32_H10
inline LMSParams LMSParams_SHA256_M32_H10()
{
    return LMSParams{0x06, 32, 10};
}

NAMESPACE_END  // LMS_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_LMS_PARAMS_H
