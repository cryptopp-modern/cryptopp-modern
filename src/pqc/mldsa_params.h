// mldsa_params.h - written and placed in the public domain by Colin Brown
//                  ML-DSA (FIPS 204) internal parameters
//                  Based on CRYSTALS-Dilithium reference implementation (public domain)

#ifndef CRYPTOPP_MLDSA_PARAMS_H
#define CRYPTOPP_MLDSA_PARAMS_H

#include <cryptopp/config.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(MLDSA_Internal)

// ==================== Common Constants ====================

// Modulus q = 2^23 - 2^13 + 1 = 8380417
static constexpr int32_t MLDSA_Q = 8380417;

// Polynomial degree
static constexpr unsigned int MLDSA_N = 256;

// Root of unity for NTT (primitive 512th root of unity mod q)
static constexpr int32_t MLDSA_ROOT_OF_UNITY = 1753;

// Number of bytes for seed/hash outputs
static constexpr unsigned int SEEDBYTES = 32;
static constexpr unsigned int CRHBYTES = 64;
static constexpr unsigned int TRBYTES = 64;

// Polynomial byte sizes
static constexpr unsigned int POLYT1_PACKEDBYTES = 320;  // t1 with 10 bits
static constexpr unsigned int POLYT0_PACKEDBYTES = 416;  // t0 with 13 bits

// ==================== ML-DSA-44 Parameters ====================

struct Params_44 {
    static constexpr unsigned int k = 4;  // Rows in matrix A
    static constexpr unsigned int l = 4;  // Columns in matrix A
    static constexpr unsigned int eta = 2;  // Secret key coefficient bound
    static constexpr unsigned int tau = 39;  // Number of +/-1's in c
    static constexpr unsigned int beta = 78;  // tau * eta
    static constexpr int32_t gamma1 = (1 << 17);  // y coefficient range: 2^17
    static constexpr int32_t gamma2 = (MLDSA_Q - 1) / 88;  // Low-order rounding range
    static constexpr unsigned int omega = 80;  // Maximum hint weight
    static constexpr unsigned int lambda = 128;  // Security strength
    static constexpr unsigned int CTILDEBYTES = lambda / 4;  // 32 bytes for c_tilde

    // Derived sizes
    static constexpr unsigned int POLYZ_PACKEDBYTES = 576;  // z with gamma1 = 2^17 -> 18 bits
    static constexpr unsigned int POLYW1_PACKEDBYTES = 192;  // w1 with 6 bits (43 coeffs per byte pair)
    static constexpr unsigned int POLYETA_PACKEDBYTES = 96;  // eta=2 -> 3 bits

    // Key and signature sizes
    static constexpr unsigned int PUBLICKEYBYTES = SEEDBYTES + k * POLYT1_PACKEDBYTES;  // 1312
    static constexpr unsigned int SECRETKEYBYTES = 2 * SEEDBYTES + TRBYTES +
                                                    l * POLYETA_PACKEDBYTES +
                                                    k * POLYETA_PACKEDBYTES +
                                                    k * POLYT0_PACKEDBYTES;  // 2560
    static constexpr unsigned int SIGNATUREBYTES = CTILDEBYTES + l * POLYZ_PACKEDBYTES + omega + k;  // 2420

    static constexpr unsigned int SECURITY_LEVEL = 2;
};

// ==================== ML-DSA-65 Parameters ====================

struct Params_65 {
    static constexpr unsigned int k = 6;  // Rows in matrix A
    static constexpr unsigned int l = 5;  // Columns in matrix A
    static constexpr unsigned int eta = 4;  // Secret key coefficient bound
    static constexpr unsigned int tau = 49;  // Number of +/-1's in c
    static constexpr unsigned int beta = 196;  // tau * eta
    static constexpr int32_t gamma1 = (1 << 19);  // y coefficient range: 2^19
    static constexpr int32_t gamma2 = (MLDSA_Q - 1) / 32;  // Low-order rounding range
    static constexpr unsigned int omega = 55;  // Maximum hint weight
    static constexpr unsigned int lambda = 192;  // Security strength
    static constexpr unsigned int CTILDEBYTES = lambda / 4;  // 48 bytes for c_tilde

    // Derived sizes
    static constexpr unsigned int POLYZ_PACKEDBYTES = 640;  // z with gamma1 = 2^19 -> 20 bits
    static constexpr unsigned int POLYW1_PACKEDBYTES = 128;  // w1 with 4 bits
    static constexpr unsigned int POLYETA_PACKEDBYTES = 128;  // eta=4 -> 4 bits

    // Key and signature sizes
    static constexpr unsigned int PUBLICKEYBYTES = SEEDBYTES + k * POLYT1_PACKEDBYTES;  // 32 + 6*320 = 1952
    static constexpr unsigned int SECRETKEYBYTES = 2 * SEEDBYTES + TRBYTES +
                                                    l * POLYETA_PACKEDBYTES +
                                                    k * POLYETA_PACKEDBYTES +
                                                    k * POLYT0_PACKEDBYTES;  // 4032
    static constexpr unsigned int SIGNATUREBYTES = CTILDEBYTES + l * POLYZ_PACKEDBYTES + omega + k;  // 3309

    static constexpr unsigned int SECURITY_LEVEL = 3;
};

// ==================== ML-DSA-87 Parameters ====================

struct Params_87 {
    static constexpr unsigned int k = 8;  // Rows in matrix A
    static constexpr unsigned int l = 7;  // Columns in matrix A
    static constexpr unsigned int eta = 2;  // Secret key coefficient bound
    static constexpr unsigned int tau = 60;  // Number of +/-1's in c
    static constexpr unsigned int beta = 120;  // tau * eta
    static constexpr int32_t gamma1 = (1 << 19);  // y coefficient range: 2^19
    static constexpr int32_t gamma2 = (MLDSA_Q - 1) / 32;  // Low-order rounding range
    static constexpr unsigned int omega = 75;  // Maximum hint weight
    static constexpr unsigned int lambda = 256;  // Security strength
    static constexpr unsigned int CTILDEBYTES = lambda / 4;  // 64 bytes for c_tilde

    // Derived sizes
    static constexpr unsigned int POLYZ_PACKEDBYTES = 640;  // z with gamma1 = 2^19 -> 20 bits
    static constexpr unsigned int POLYW1_PACKEDBYTES = 128;  // w1 with 4 bits
    static constexpr unsigned int POLYETA_PACKEDBYTES = 96;  // eta=2 -> 3 bits

    // Key and signature sizes
    static constexpr unsigned int PUBLICKEYBYTES = SEEDBYTES + k * POLYT1_PACKEDBYTES;  // 32 + 8*320 = 2592
    static constexpr unsigned int SECRETKEYBYTES = 2 * SEEDBYTES + TRBYTES +
                                                    l * POLYETA_PACKEDBYTES +
                                                    k * POLYETA_PACKEDBYTES +
                                                    k * POLYT0_PACKEDBYTES;  // 4896
    static constexpr unsigned int SIGNATUREBYTES = CTILDEBYTES + l * POLYZ_PACKEDBYTES + omega + k;  // 4627

    static constexpr unsigned int SECURITY_LEVEL = 5;
};

// ==================== NTT Constants ====================

// Zetas for forward NTT (precomputed powers of root of unity)
// These are Montgomery representations of powers of the primitive 512th root of unity
extern const int32_t mldsa_zetas[MLDSA_N];

// ==================== Modular Arithmetic ====================

// Montgomery reduction constant: q^{-1} mod 2^32
// Reference Dilithium uses: #define QINV 58728449
#define MLDSA_QINV 58728449

// R = 2^32 mod q (for Montgomery representation)
// Reference Dilithium uses: #define MONT -4186625
#define MLDSA_MONT -4186625

/// \brief Montgomery reduction (matches Dilithium reference exactly)
/// \param a input value
/// \return a * R^{-1} mod q
inline int32_t montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int64_t)(int32_t)a * MLDSA_QINV;
    t = (a - (int64_t)t * MLDSA_Q) >> 32;
    return t;
}

/// \brief Reduce coefficient to centered representation
/// \param a input coefficient
/// \return coefficient in range [-(q-1)/2, (q-1)/2]
inline int32_t reduce32(int32_t a) {
    int32_t t = (a + (1 << 22)) >> 23;
    t = a - t * MLDSA_Q;
    return t;
}

/// \brief Conditionally add q to coefficient
/// \param a input coefficient (may be negative)
/// \return coefficient in range [0, q)
inline int32_t caddq(int32_t a) {
    a += (a >> 31) & MLDSA_Q;
    return a;
}

/// \brief Freeze coefficient to standard representative
/// \param a input coefficient
/// \return coefficient in range [0, q)
inline int32_t freeze(int32_t a) {
    a = reduce32(a);
    a = caddq(a);
    return a;
}

NAMESPACE_END  // MLDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_MLDSA_PARAMS_H
