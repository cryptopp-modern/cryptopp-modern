// mlkem_params.h - written and placed in the public domain by Colin Brown
//                  ML-KEM (FIPS 203) internal parameters
//                  Based on CRYSTALS-Kyber reference implementation (public domain)

#ifndef CRYPTOPP_MLKEM_PARAMS_H
#define CRYPTOPP_MLKEM_PARAMS_H

#include <cryptopp/config.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(MLKEM_Internal)

// ******************** Common Constants ************************* //

// Ring dimension
static constexpr unsigned int MLKEM_N = 256;

// Modulus q = 3329 = 13 * 256 + 1
static constexpr int16_t MLKEM_Q = 3329;

// Size of shared secret
static constexpr unsigned int MLKEM_SYMBYTES = 32;

// Size of seeds
static constexpr unsigned int MLKEM_SEEDBYTES = 32;

// ******************** ML-KEM-512 Parameters ************************* //

struct Params_512
{
    static constexpr unsigned int k = 2;      // Module rank
    static constexpr unsigned int eta1 = 3;   // Noise parameter 1
    static constexpr unsigned int eta2 = 2;   // Noise parameter 2
    static constexpr unsigned int du = 10;    // Compression parameter for u
    static constexpr unsigned int dv = 4;     // Compression parameter for v

    // Derived sizes
    static constexpr unsigned int POLYBYTES = 384;  // 256 * 12 / 8
    static constexpr unsigned int POLYVECBYTES = k * POLYBYTES;  // 768
    static constexpr unsigned int POLYCOMPRESSEDBYTES = 128;  // 256 * dv / 8
    static constexpr unsigned int POLYVECCOMPRESSEDBYTES = k * 320;  // k * 256 * du / 8 = 640

    static constexpr unsigned int INDCPA_PUBLICKEYBYTES = POLYVECBYTES + MLKEM_SYMBYTES;  // 800
    static constexpr unsigned int INDCPA_SECRETKEYBYTES = POLYVECBYTES;  // 768
    static constexpr unsigned int INDCPA_BYTES = POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES;  // 768

    static constexpr unsigned int PUBLICKEYBYTES = INDCPA_PUBLICKEYBYTES;  // 800
    static constexpr unsigned int SECRETKEYBYTES = INDCPA_SECRETKEYBYTES + INDCPA_PUBLICKEYBYTES + 2 * MLKEM_SYMBYTES;  // 1632
    static constexpr unsigned int CIPHERTEXTBYTES = INDCPA_BYTES;  // 768
};

// ******************** ML-KEM-768 Parameters ************************* //

struct Params_768
{
    static constexpr unsigned int k = 3;      // Module rank
    static constexpr unsigned int eta1 = 2;   // Noise parameter 1
    static constexpr unsigned int eta2 = 2;   // Noise parameter 2
    static constexpr unsigned int du = 10;    // Compression parameter for u
    static constexpr unsigned int dv = 4;     // Compression parameter for v

    // Derived sizes
    static constexpr unsigned int POLYBYTES = 384;  // 256 * 12 / 8
    static constexpr unsigned int POLYVECBYTES = k * POLYBYTES;  // 1152
    static constexpr unsigned int POLYCOMPRESSEDBYTES = 128;  // 256 * dv / 8
    static constexpr unsigned int POLYVECCOMPRESSEDBYTES = k * 320;  // k * 256 * du / 8 = 960

    static constexpr unsigned int INDCPA_PUBLICKEYBYTES = POLYVECBYTES + MLKEM_SYMBYTES;  // 1184
    static constexpr unsigned int INDCPA_SECRETKEYBYTES = POLYVECBYTES;  // 1152
    static constexpr unsigned int INDCPA_BYTES = POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES;  // 1088

    static constexpr unsigned int PUBLICKEYBYTES = INDCPA_PUBLICKEYBYTES;  // 1184
    static constexpr unsigned int SECRETKEYBYTES = INDCPA_SECRETKEYBYTES + INDCPA_PUBLICKEYBYTES + 2 * MLKEM_SYMBYTES;  // 2400
    static constexpr unsigned int CIPHERTEXTBYTES = INDCPA_BYTES;  // 1088
};

// ******************** ML-KEM-1024 Parameters ************************* //

struct Params_1024
{
    static constexpr unsigned int k = 4;      // Module rank
    static constexpr unsigned int eta1 = 2;   // Noise parameter 1
    static constexpr unsigned int eta2 = 2;   // Noise parameter 2
    static constexpr unsigned int du = 11;    // Compression parameter for u
    static constexpr unsigned int dv = 5;     // Compression parameter for v

    // Derived sizes
    static constexpr unsigned int POLYBYTES = 384;  // 256 * 12 / 8
    static constexpr unsigned int POLYVECBYTES = k * POLYBYTES;  // 1536
    static constexpr unsigned int POLYCOMPRESSEDBYTES = 160;  // 256 * dv / 8
    static constexpr unsigned int POLYVECCOMPRESSEDBYTES = k * 352;  // k * 256 * du / 8 = 1408

    static constexpr unsigned int INDCPA_PUBLICKEYBYTES = POLYVECBYTES + MLKEM_SYMBYTES;  // 1568
    static constexpr unsigned int INDCPA_SECRETKEYBYTES = POLYVECBYTES;  // 1536
    static constexpr unsigned int INDCPA_BYTES = POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES;  // 1568

    static constexpr unsigned int PUBLICKEYBYTES = INDCPA_PUBLICKEYBYTES;  // 1568
    static constexpr unsigned int SECRETKEYBYTES = INDCPA_SECRETKEYBYTES + INDCPA_PUBLICKEYBYTES + 2 * MLKEM_SYMBYTES;  // 3168
    static constexpr unsigned int CIPHERTEXTBYTES = INDCPA_BYTES;  // 1568
};

// ******************** NTT Constants ************************* //

// Primitive 256th root of unity mod q: zeta = 17
static constexpr int16_t MLKEM_ZETA = 17;

// Montgomery parameter: R = 2^16 mod q
static constexpr int32_t MLKEM_MONT_R = 2285;  // 2^16 mod 3329

// q^(-1) mod 2^16 (as int, matching reference)
static constexpr int MLKEM_QINV = -3327;

// Precomputed powers of zeta for NTT (in Montgomery form)
// zetas[i] = zeta^(BitRev7(i)) * R mod q
extern const int16_t MLKEM_ZETAS[128];

// ******************** Deterministic Key Generation ************************* //
// Used by X-Wing for spec-compliant seed expansion

/// \brief Generate ML-KEM key pair deterministically from seed values
/// \param pk output public key buffer
/// \param sk output secret key buffer
/// \param d 32-byte seed for polynomial generation
/// \param z 32-byte implicit rejection seed
template <class PARAMS>
void mlkem_keypair_deterministic(byte *pk, byte *sk, const byte *d, const byte *z);

NAMESPACE_END  // MLKEM_Internal
NAMESPACE_END  // CryptoPP

#endif // CRYPTOPP_MLKEM_PARAMS_H
