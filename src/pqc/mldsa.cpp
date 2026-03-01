// mldsa.cpp - written and placed in the public domain by Colin Brown
//             ML-DSA (FIPS 204) Module-Lattice Digital Signature Algorithm
//             Based on CRYSTALS-Dilithium reference implementation (public domain)

#include <cryptopp/pch.h>
#include <cryptopp/mldsa.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>
#include <cryptopp/osrng.h>
#include <cryptopp/misc.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cstring>

#include "mldsa_params.h"
#include "mldsa_poly.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(MLDSA_Internal)

// ==================== Constants ====================

// SHAKE256 block size for challenge generation
static constexpr unsigned int SHAKE256_BLOCKSIZE = 136;

// ==================== NTT Zetas ====================

// Precomputed powers of the primitive 512th root of unity in Montgomery form
// zetas[i] = zeta^{brv(i)} * R mod q where R = 2^32 mod q
const int32_t mldsa_zetas[MLDSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

// ==================== Polynomial Basic Operations ====================

void poly_zero(poly *a) {
    std::memset(a->coeffs, 0, sizeof(a->coeffs));
}

void poly_add(poly *c, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *c, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void poly_neg(poly *b, const poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        b->coeffs[i] = -a->coeffs[i];
}

void poly_shiftl(poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        a->coeffs[i] <<= 13;
}

// ==================== NTT Operations ====================

void poly_ntt(poly *a) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = mldsa_zetas[++k];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce(static_cast<int64_t>(zeta) * a->coeffs[j + len]);
                a->coeffs[j + len] = a->coeffs[j] - t;
                a->coeffs[j] = a->coeffs[j] + t;
            }
        }
    }
}

void poly_invntt(poly *a) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978;  // mont^2/256 as in Dilithium reference

    k = 256;
    for (len = 1; len < MLDSA_N; len <<= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = -mldsa_zetas[--k];
            for (j = start; j < start + len; j++) {
                t = a->coeffs[j];
                a->coeffs[j] = t + a->coeffs[j + len];
                a->coeffs[j + len] = t - a->coeffs[j + len];
                a->coeffs[j + len] = montgomery_reduce(static_cast<int64_t>(zeta) * a->coeffs[j + len]);
            }
        }
    }

    for (j = 0; j < MLDSA_N; j++)
        a->coeffs[j] = montgomery_reduce(static_cast<int64_t>(f) * a->coeffs[j]);
}

void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        c->coeffs[i] = montgomery_reduce(static_cast<int64_t>(a->coeffs[i]) * b->coeffs[i]);
}

// ==================== Reduction ====================

void poly_reduce(poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        a->coeffs[i] = reduce32(a->coeffs[i]);
}

void poly_caddq(poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        a->coeffs[i] = caddq(a->coeffs[i]);
}

void poly_freeze(poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++)
        a->coeffs[i] = freeze(a->coeffs[i]);
}

// ==================== Rounding ====================

// Power2Round: decompose a = a1*2^d + a0 where d = 13
// Per FIPS 204: a1 = floor((a + 2^(d-1) - 1) / 2^d), a0 = a - a1*2^d
// This ensures a0 is in range (-2^(d-1), 2^(d-1)] = (-4096, 4096]
void poly_power2round(poly *a1, poly *a0, const poly *a) {
    for (unsigned int i = 0; i < MLDSA_N; i++) {
        int32_t t = a->coeffs[i];
        // a1 = (a + 2^12 - 1) >> 13 per FIPS 204 Algorithm 35
        a1->coeffs[i] = (t + (1 << 12) - 1) >> 13;
        // a0 = a - a1 * 2^13, centered in range (-4096, 4096]
        a0->coeffs[i] = t - (a1->coeffs[i] << 13);
    }
}

// Decompose: a = a1*alpha + a0 where alpha = 2*gamma2
// Returns a1 and centered a0
static void decompose_internal(int32_t *a0, int32_t *a1, int32_t a, int32_t gamma2) {
    // a1 = ceiling((a + 127) / (2*gamma2))
    *a1 = (a + 127) >> 7;
    if (gamma2 == (MLDSA_Q - 1) / 32) {
        *a1 = (*a1 * 1025 + (1 << 21)) >> 22;
        *a1 &= 15;
    } else {  // gamma2 == (MLDSA_Q - 1) / 88
        *a1 = (*a1 * 11275 + (1 << 23)) >> 24;
        *a1 ^= ((43 - *a1) >> 31) & *a1;  // Set a1 to 0 if a1 >= 43 (wraps around)
    }

    *a0 = a - *a1 * 2 * gamma2;
    *a0 -= ((((MLDSA_Q - 1) / 2 - *a0) >> 31) & MLDSA_Q);
}

// Make hint: h[i] = 1 if high(a0 + a1) != high(a1)
static unsigned int make_hint_internal(int32_t a0, int32_t a1, int32_t gamma2) {
    if (a0 > gamma2 || a0 < -gamma2 ||
        (a0 == -gamma2 && a1 != 0))
        return 1;
    return 0;
}

// Use hint to recover a1
static int32_t use_hint_internal(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;
    decompose_internal(&a0, &a1, a, gamma2);

    if (hint == 0)
        return a1;

    if (gamma2 == (MLDSA_Q - 1) / 32) {
        if (a0 > 0)
            return (a1 + 1) & 15;
        else
            return (a1 - 1) & 15;
    } else {
        if (a0 > 0)
            return (a1 == 43) ? 0 : a1 + 1;
        else
            return (a1 == 0) ? 43 : a1 - 1;
    }
}

// ==================== Norm Check ====================

int poly_chknorm(const poly *a, int32_t bound) {
    // Constant-time: accumulate without early exit
    int32_t fail = 0;
    for (unsigned int i = 0; i < MLDSA_N; i++) {
        int32_t t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);  // abs
        // (t - bound) >> 31 is all-ones when t < bound, zero when t >= bound
        fail |= ~((t - bound) >> 31);
    }
    return (fail & 1);
}

// ==================== Sampling ====================

// Rejection sampling from SHAKE128 output
static unsigned int rej_uniform(int32_t *a, unsigned int len, const byte *buf, unsigned int buflen) {
    unsigned int ctr = 0, pos = 0;

    while (ctr < len && pos + 3 <= buflen) {
        uint32_t t = buf[pos++];
        t |= static_cast<uint32_t>(buf[pos++]) << 8;
        t |= static_cast<uint32_t>(buf[pos++]) << 16;
        t &= 0x7FFFFF;

        if (t < MLDSA_Q)
            a[ctr++] = t;
    }

    return ctr;
}

void poly_uniform(poly *a, const byte *seed, uint16_t nonce) {
    // Each coefficient needs 3 bytes, and rejection rate is ~50%.
    // For 256 coefficients, worst case needs ~1536 bytes.
    // Using 2048 bytes for safety.
    static constexpr unsigned int BUF_SIZE = 2048;
    byte buf[BUF_SIZE];

    SHAKE128 shake(BUF_SIZE);
    shake.Update(seed, SEEDBYTES);
    byte nonce_bytes[2] = { static_cast<byte>(nonce), static_cast<byte>(nonce >> 8) };
    shake.Update(nonce_bytes, 2);
    shake.TruncatedFinal(buf, BUF_SIZE);

    unsigned int ctr = rej_uniform(a->coeffs, MLDSA_N, buf, BUF_SIZE);

    if (ctr < MLDSA_N) {
        throw Exception(Exception::OTHER_ERROR,
            "ML-DSA: poly_uniform ran out of random bytes");
    }
}

// Rejection sampling for eta-bounded coefficients
static unsigned int rej_eta2(int32_t *a, unsigned int len, const byte *buf, unsigned int buflen) {
    unsigned int ctr = 0, pos = 0;

    while (ctr < len && pos < buflen) {
        uint32_t t0 = buf[pos] & 0x0F;
        uint32_t t1 = buf[pos++] >> 4;

        if (t0 < 15) {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr++] = 2 - t0;
        }
        if (t1 < 15 && ctr < len) {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr++] = 2 - t1;
        }
    }
    return ctr;
}

static unsigned int rej_eta4(int32_t *a, unsigned int len, const byte *buf, unsigned int buflen) {
    unsigned int ctr = 0, pos = 0;

    while (ctr < len && pos < buflen) {
        uint32_t t0 = buf[pos] & 0x0F;
        uint32_t t1 = buf[pos++] >> 4;

        if (t0 < 9)
            a[ctr++] = 4 - t0;
        if (t1 < 9 && ctr < len)
            a[ctr++] = 4 - t1;
    }
    return ctr;
}

// Template specializations for eta sampling
template <>
void poly_uniform_eta<Params_44>(poly *a, const byte *seed, uint16_t nonce) {
    // Eta=2: each byte can produce 0-2 coefficients. Use large buffer for safety.
    static constexpr unsigned int BUF_SIZE = 512;
    byte buf[BUF_SIZE];

    SHAKE256 shake(BUF_SIZE);
    shake.Update(seed, CRHBYTES);
    byte nonce_bytes[2] = { static_cast<byte>(nonce), static_cast<byte>(nonce >> 8) };
    shake.Update(nonce_bytes, 2);
    shake.TruncatedFinal(buf, BUF_SIZE);

    unsigned int ctr = rej_eta2(a->coeffs, MLDSA_N, buf, BUF_SIZE);
    if (ctr < MLDSA_N) {
        throw Exception(Exception::OTHER_ERROR,
            "ML-DSA: poly_uniform_eta ran out of random bytes");
    }
}

template <>
void poly_uniform_eta<Params_65>(poly *a, const byte *seed, uint16_t nonce) {
    // Eta=4: each nibble has 9/16 acceptance rate. Use large buffer for safety.
    static constexpr unsigned int BUF_SIZE = 512;
    byte buf[BUF_SIZE];

    SHAKE256 shake(BUF_SIZE);
    shake.Update(seed, CRHBYTES);
    byte nonce_bytes[2] = { static_cast<byte>(nonce), static_cast<byte>(nonce >> 8) };
    shake.Update(nonce_bytes, 2);
    shake.TruncatedFinal(buf, BUF_SIZE);

    unsigned int ctr = rej_eta4(a->coeffs, MLDSA_N, buf, BUF_SIZE);
    if (ctr < MLDSA_N) {
        throw Exception(Exception::OTHER_ERROR,
            "ML-DSA: poly_uniform_eta ran out of random bytes");
    }
}

template <>
void poly_uniform_eta<Params_87>(poly *a, const byte *seed, uint16_t nonce) {
    // Eta=2: each byte can produce 0-2 coefficients. Use large buffer for safety.
    static constexpr unsigned int BUF_SIZE = 512;
    byte buf[BUF_SIZE];

    SHAKE256 shake(BUF_SIZE);
    shake.Update(seed, CRHBYTES);
    byte nonce_bytes[2] = { static_cast<byte>(nonce), static_cast<byte>(nonce >> 8) };
    shake.Update(nonce_bytes, 2);
    shake.TruncatedFinal(buf, BUF_SIZE);

    unsigned int ctr = rej_eta2(a->coeffs, MLDSA_N, buf, BUF_SIZE);
    if (ctr < MLDSA_N) {
        throw Exception(Exception::OTHER_ERROR,
            "ML-DSA: poly_uniform_eta ran out of random bytes");
    }
}

// ==================== C++11 Compatible Template Helpers ====================
// These helpers use template specialization instead of if constexpr for C++11/14 compatibility

// Helper for gamma1-based unpacking (18-bit vs 20-bit)
template <int32_t GAMMA1>
struct UnpackGamma1Impl;

template <>
struct UnpackGamma1Impl<(1 << 17)> {
    static void unpack(poly *a, const byte *buf) {
        const int32_t gamma1 = (1 << 17);
        // 18-bit coefficients
        for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
            a->coeffs[4*i+0]  = buf[9*i+0];
            a->coeffs[4*i+0] |= static_cast<uint32_t>(buf[9*i+1]) << 8;
            a->coeffs[4*i+0] |= static_cast<uint32_t>(buf[9*i+2]) << 16;
            a->coeffs[4*i+0] &= 0x3FFFF;

            a->coeffs[4*i+1]  = buf[9*i+2] >> 2;
            a->coeffs[4*i+1] |= static_cast<uint32_t>(buf[9*i+3]) << 6;
            a->coeffs[4*i+1] |= static_cast<uint32_t>(buf[9*i+4]) << 14;
            a->coeffs[4*i+1] &= 0x3FFFF;

            a->coeffs[4*i+2]  = buf[9*i+4] >> 4;
            a->coeffs[4*i+2] |= static_cast<uint32_t>(buf[9*i+5]) << 4;
            a->coeffs[4*i+2] |= static_cast<uint32_t>(buf[9*i+6]) << 12;
            a->coeffs[4*i+2] &= 0x3FFFF;

            a->coeffs[4*i+3]  = buf[9*i+6] >> 6;
            a->coeffs[4*i+3] |= static_cast<uint32_t>(buf[9*i+7]) << 2;
            a->coeffs[4*i+3] |= static_cast<uint32_t>(buf[9*i+8]) << 10;
            a->coeffs[4*i+3] &= 0x3FFFF;

            a->coeffs[4*i+0] = gamma1 - a->coeffs[4*i+0];
            a->coeffs[4*i+1] = gamma1 - a->coeffs[4*i+1];
            a->coeffs[4*i+2] = gamma1 - a->coeffs[4*i+2];
            a->coeffs[4*i+3] = gamma1 - a->coeffs[4*i+3];
        }
    }
};

template <>
struct UnpackGamma1Impl<(1 << 19)> {
    static void unpack(poly *a, const byte *buf) {
        const int32_t gamma1 = (1 << 19);
        // 20-bit coefficients
        for (unsigned int i = 0; i < MLDSA_N / 2; i++) {
            a->coeffs[2*i+0]  = buf[5*i+0];
            a->coeffs[2*i+0] |= static_cast<uint32_t>(buf[5*i+1]) << 8;
            a->coeffs[2*i+0] |= static_cast<uint32_t>(buf[5*i+2]) << 16;
            a->coeffs[2*i+0] &= 0xFFFFF;

            a->coeffs[2*i+1]  = buf[5*i+2] >> 4;
            a->coeffs[2*i+1] |= static_cast<uint32_t>(buf[5*i+3]) << 4;
            a->coeffs[2*i+1] |= static_cast<uint32_t>(buf[5*i+4]) << 12;
            a->coeffs[2*i+1] &= 0xFFFFF;

            a->coeffs[2*i+0] = gamma1 - a->coeffs[2*i+0];
            a->coeffs[2*i+1] = gamma1 - a->coeffs[2*i+1];
        }
    }
};

// Sample gamma1-bounded polynomial
template <class PARAMS>
void poly_uniform_gamma1(poly *a, const byte *seed, uint16_t nonce) {
    const unsigned int POLYZ_PACKEDBYTES = PARAMS::POLYZ_PACKEDBYTES;
    byte buf[PARAMS::POLYZ_PACKEDBYTES];

    SHAKE256 shake(POLYZ_PACKEDBYTES);
    shake.Update(seed, CRHBYTES);
    byte nonce_bytes[2] = { static_cast<byte>(nonce), static_cast<byte>(nonce >> 8) };
    shake.Update(nonce_bytes, 2);
    shake.TruncatedFinal(buf, POLYZ_PACKEDBYTES);

    // Unpack z from bytes using specialized helper
    UnpackGamma1Impl<PARAMS::gamma1>::unpack(a, buf);
}

// Explicit template instantiations
template void poly_uniform_gamma1<Params_44>(poly *a, const byte *seed, uint16_t nonce);
template void poly_uniform_gamma1<Params_65>(poly *a, const byte *seed, uint16_t nonce);
template void poly_uniform_gamma1<Params_87>(poly *a, const byte *seed, uint16_t nonce);

// Sample challenge polynomial c with tau +/-1's
template <class PARAMS>
void poly_challenge(poly *c, const byte *seed) {
    constexpr unsigned int tau = PARAMS::tau;
    // Allocate enough buffer for 8 sign bytes + up to 256 index bytes
    // This avoids the need for XOF-style incremental squeezing
    static constexpr unsigned int CHALLENGE_BYTES = 8 + 256;
    byte buf[CHALLENGE_BYTES];
    uint64_t signs;

    SHAKE256 shake(CHALLENGE_BYTES);
    shake.Update(seed, PARAMS::CTILDEBYTES);
    shake.TruncatedFinal(buf, CHALLENGE_BYTES);

    signs = 0;
    for (unsigned int i = 0; i < 8; i++)
        signs |= static_cast<uint64_t>(buf[i]) << (8 * i);

    unsigned int pos = 8;
    poly_zero(c);

    for (unsigned int i = MLDSA_N - tau; i < MLDSA_N; i++) {
        unsigned int b;
        do {
            if (pos >= CHALLENGE_BYTES) {
                // This should never happen with 256 bytes for indices
                throw Exception(Exception::OTHER_ERROR,
                    "ML-DSA: poly_challenge ran out of random bytes");
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
}

template void poly_challenge<Params_44>(poly *c, const byte *seed);
template void poly_challenge<Params_65>(poly *c, const byte *seed);
template void poly_challenge<Params_87>(poly *c, const byte *seed);

// ==================== Packing Functions ====================

// Pack t1 (10 bits per coefficient)
void poly_pack_t1(byte *r, const poly *a) {
    for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
        r[5*i+0] = static_cast<byte>(a->coeffs[4*i+0] >> 0);
        r[5*i+1] = static_cast<byte>((a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2));
        r[5*i+2] = static_cast<byte>((a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4));
        r[5*i+3] = static_cast<byte>((a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6));
        r[5*i+4] = static_cast<byte>(a->coeffs[4*i+3] >> 2);
    }
}

void poly_unpack_t1(poly *r, const byte *a) {
    for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
        r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | (static_cast<uint32_t>(a[5*i+1]) << 8)) & 0x3FF;
        r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | (static_cast<uint32_t>(a[5*i+2]) << 6)) & 0x3FF;
        r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | (static_cast<uint32_t>(a[5*i+3]) << 4)) & 0x3FF;
        r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | (static_cast<uint32_t>(a[5*i+4]) << 2)) & 0x3FF;
    }
}

// Pack t0 (13 bits per coefficient, signed)
void poly_pack_t0(byte *r, const poly *a) {
    int32_t t[8];

    for (unsigned int i = 0; i < MLDSA_N / 8; i++) {
        for (unsigned int j = 0; j < 8; j++)
            t[j] = (1 << 12) - a->coeffs[8*i+j];

        r[13*i+ 0] = static_cast<byte>(t[0]);
        r[13*i+ 1] = static_cast<byte>(t[0] >> 8) | static_cast<byte>(t[1] << 5);
        r[13*i+ 2] = static_cast<byte>(t[1] >> 3);
        r[13*i+ 3] = static_cast<byte>(t[1] >> 11) | static_cast<byte>(t[2] << 2);
        r[13*i+ 4] = static_cast<byte>(t[2] >> 6) | static_cast<byte>(t[3] << 7);
        r[13*i+ 5] = static_cast<byte>(t[3] >> 1);
        r[13*i+ 6] = static_cast<byte>(t[3] >> 9) | static_cast<byte>(t[4] << 4);
        r[13*i+ 7] = static_cast<byte>(t[4] >> 4);
        r[13*i+ 8] = static_cast<byte>(t[4] >> 12) | static_cast<byte>(t[5] << 1);
        r[13*i+ 9] = static_cast<byte>(t[5] >> 7) | static_cast<byte>(t[6] << 6);
        r[13*i+10] = static_cast<byte>(t[6] >> 2);
        r[13*i+11] = static_cast<byte>(t[6] >> 10) | static_cast<byte>(t[7] << 3);
        r[13*i+12] = static_cast<byte>(t[7] >> 5);
    }
}

void poly_unpack_t0(poly *r, const byte *a) {
    for (unsigned int i = 0; i < MLDSA_N / 8; i++) {
        r->coeffs[8*i+0]  = a[13*i+0];
        r->coeffs[8*i+0] |= static_cast<uint32_t>(a[13*i+1]) << 8;
        r->coeffs[8*i+0] &= 0x1FFF;

        r->coeffs[8*i+1]  = a[13*i+1] >> 5;
        r->coeffs[8*i+1] |= static_cast<uint32_t>(a[13*i+2]) << 3;
        r->coeffs[8*i+1] |= static_cast<uint32_t>(a[13*i+3]) << 11;
        r->coeffs[8*i+1] &= 0x1FFF;

        r->coeffs[8*i+2]  = a[13*i+3] >> 2;
        r->coeffs[8*i+2] |= static_cast<uint32_t>(a[13*i+4]) << 6;
        r->coeffs[8*i+2] &= 0x1FFF;

        r->coeffs[8*i+3]  = a[13*i+4] >> 7;
        r->coeffs[8*i+3] |= static_cast<uint32_t>(a[13*i+5]) << 1;
        r->coeffs[8*i+3] |= static_cast<uint32_t>(a[13*i+6]) << 9;
        r->coeffs[8*i+3] &= 0x1FFF;

        r->coeffs[8*i+4]  = a[13*i+6] >> 4;
        r->coeffs[8*i+4] |= static_cast<uint32_t>(a[13*i+7]) << 4;
        r->coeffs[8*i+4] |= static_cast<uint32_t>(a[13*i+8]) << 12;
        r->coeffs[8*i+4] &= 0x1FFF;

        r->coeffs[8*i+5]  = a[13*i+8] >> 1;
        r->coeffs[8*i+5] |= static_cast<uint32_t>(a[13*i+9]) << 7;
        r->coeffs[8*i+5] &= 0x1FFF;

        r->coeffs[8*i+6]  = a[13*i+9] >> 6;
        r->coeffs[8*i+6] |= static_cast<uint32_t>(a[13*i+10]) << 2;
        r->coeffs[8*i+6] |= static_cast<uint32_t>(a[13*i+11]) << 10;
        r->coeffs[8*i+6] &= 0x1FFF;

        r->coeffs[8*i+7]  = a[13*i+11] >> 3;
        r->coeffs[8*i+7] |= static_cast<uint32_t>(a[13*i+12]) << 5;
        r->coeffs[8*i+7] &= 0x1FFF;

        for (unsigned int j = 0; j < 8; j++)
            r->coeffs[8*i+j] = (1 << 12) - r->coeffs[8*i+j];
    }
}

// ==================== Eta Packing ====================

// Helper for eta-based packing (3-bit vs 4-bit)
template <unsigned int ETA>
struct PackEtaImpl;

template <>
struct PackEtaImpl<2> {
    static void pack(byte *r, const poly *a) {
        const unsigned int eta = 2;
        // 3 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 8; i++) {
            byte t[8];
            for (unsigned int j = 0; j < 8; j++)
                t[j] = static_cast<byte>(eta - a->coeffs[8*i+j]);

            r[3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    }

    static void unpack(poly *r, const byte *a) {
        const unsigned int eta = 2;
        // 3 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 8; i++) {
            r->coeffs[8*i+0] = (a[3*i+0] >> 0) & 7;
            r->coeffs[8*i+1] = (a[3*i+0] >> 3) & 7;
            r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
            r->coeffs[8*i+3] = (a[3*i+1] >> 1) & 7;
            r->coeffs[8*i+4] = (a[3*i+1] >> 4) & 7;
            r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
            r->coeffs[8*i+6] = (a[3*i+2] >> 2) & 7;
            r->coeffs[8*i+7] = (a[3*i+2] >> 5) & 7;

            for (unsigned int j = 0; j < 8; j++)
                r->coeffs[8*i+j] = eta - r->coeffs[8*i+j];
        }
    }
};

template <>
struct PackEtaImpl<4> {
    static void pack(byte *r, const poly *a) {
        const unsigned int eta = 4;
        // 4 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 2; i++) {
            byte t0 = static_cast<byte>(eta - a->coeffs[2*i+0]);
            byte t1 = static_cast<byte>(eta - a->coeffs[2*i+1]);
            r[i] = t0 | (t1 << 4);
        }
    }

    static void unpack(poly *r, const byte *a) {
        const unsigned int eta = 4;
        // 4 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 2; i++) {
            r->coeffs[2*i+0] = a[i] & 0x0F;
            r->coeffs[2*i+1] = a[i] >> 4;
            r->coeffs[2*i+0] = eta - r->coeffs[2*i+0];
            r->coeffs[2*i+1] = eta - r->coeffs[2*i+1];
        }
    }
};

template <class PARAMS>
void poly_pack_eta(byte *r, const poly *a) {
    PackEtaImpl<PARAMS::eta>::pack(r, a);
}

template <class PARAMS>
void poly_unpack_eta(poly *r, const byte *a) {
    PackEtaImpl<PARAMS::eta>::unpack(r, a);
}

template void poly_pack_eta<Params_44>(byte *r, const poly *a);
template void poly_pack_eta<Params_65>(byte *r, const poly *a);
template void poly_pack_eta<Params_87>(byte *r, const poly *a);
template void poly_unpack_eta<Params_44>(poly *r, const byte *a);
template void poly_unpack_eta<Params_65>(poly *r, const byte *a);
template void poly_unpack_eta<Params_87>(poly *r, const byte *a);

// ==================== Z Packing ====================

// Helper for gamma1-based Z packing (18-bit vs 20-bit)
template <int32_t GAMMA1>
struct PackZImpl;

template <>
struct PackZImpl<(1 << 17)> {
    static void pack(byte *r, const poly *a) {
        const int32_t gamma1 = (1 << 17);
        // 18 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
            int32_t t[4];
            for (unsigned int j = 0; j < 4; j++)
                t[j] = gamma1 - a->coeffs[4*i+j];

            r[9*i+0] = static_cast<byte>(t[0]);
            r[9*i+1] = static_cast<byte>(t[0] >> 8);
            r[9*i+2] = static_cast<byte>(t[0] >> 16) | static_cast<byte>(t[1] << 2);
            r[9*i+3] = static_cast<byte>(t[1] >> 6);
            r[9*i+4] = static_cast<byte>(t[1] >> 14) | static_cast<byte>(t[2] << 4);
            r[9*i+5] = static_cast<byte>(t[2] >> 4);
            r[9*i+6] = static_cast<byte>(t[2] >> 12) | static_cast<byte>(t[3] << 6);
            r[9*i+7] = static_cast<byte>(t[3] >> 2);
            r[9*i+8] = static_cast<byte>(t[3] >> 10);
        }
    }

    static void unpack(poly *r, const byte *a) {
        const int32_t gamma1 = (1 << 17);
        // 18 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
            r->coeffs[4*i+0]  = a[9*i+0];
            r->coeffs[4*i+0] |= static_cast<uint32_t>(a[9*i+1]) << 8;
            r->coeffs[4*i+0] |= static_cast<uint32_t>(a[9*i+2]) << 16;
            r->coeffs[4*i+0] &= 0x3FFFF;

            r->coeffs[4*i+1]  = a[9*i+2] >> 2;
            r->coeffs[4*i+1] |= static_cast<uint32_t>(a[9*i+3]) << 6;
            r->coeffs[4*i+1] |= static_cast<uint32_t>(a[9*i+4]) << 14;
            r->coeffs[4*i+1] &= 0x3FFFF;

            r->coeffs[4*i+2]  = a[9*i+4] >> 4;
            r->coeffs[4*i+2] |= static_cast<uint32_t>(a[9*i+5]) << 4;
            r->coeffs[4*i+2] |= static_cast<uint32_t>(a[9*i+6]) << 12;
            r->coeffs[4*i+2] &= 0x3FFFF;

            r->coeffs[4*i+3]  = a[9*i+6] >> 6;
            r->coeffs[4*i+3] |= static_cast<uint32_t>(a[9*i+7]) << 2;
            r->coeffs[4*i+3] |= static_cast<uint32_t>(a[9*i+8]) << 10;
            r->coeffs[4*i+3] &= 0x3FFFF;

            for (unsigned int j = 0; j < 4; j++)
                r->coeffs[4*i+j] = gamma1 - r->coeffs[4*i+j];
        }
    }
};

template <>
struct PackZImpl<(1 << 19)> {
    static void pack(byte *r, const poly *a) {
        const int32_t gamma1 = (1 << 19);
        // 20 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 2; i++) {
            int32_t t0 = gamma1 - a->coeffs[2*i+0];
            int32_t t1 = gamma1 - a->coeffs[2*i+1];

            r[5*i+0] = static_cast<byte>(t0);
            r[5*i+1] = static_cast<byte>(t0 >> 8);
            r[5*i+2] = static_cast<byte>(t0 >> 16) | static_cast<byte>(t1 << 4);
            r[5*i+3] = static_cast<byte>(t1 >> 4);
            r[5*i+4] = static_cast<byte>(t1 >> 12);
        }
    }

    static void unpack(poly *r, const byte *a) {
        const int32_t gamma1 = (1 << 19);
        // 20 bits per coefficient
        for (unsigned int i = 0; i < MLDSA_N / 2; i++) {
            r->coeffs[2*i+0]  = a[5*i+0];
            r->coeffs[2*i+0] |= static_cast<uint32_t>(a[5*i+1]) << 8;
            r->coeffs[2*i+0] |= static_cast<uint32_t>(a[5*i+2]) << 16;
            r->coeffs[2*i+0] &= 0xFFFFF;

            r->coeffs[2*i+1]  = a[5*i+2] >> 4;
            r->coeffs[2*i+1] |= static_cast<uint32_t>(a[5*i+3]) << 4;
            r->coeffs[2*i+1] |= static_cast<uint32_t>(a[5*i+4]) << 12;
            r->coeffs[2*i+1] &= 0xFFFFF;

            r->coeffs[2*i+0] = gamma1 - r->coeffs[2*i+0];
            r->coeffs[2*i+1] = gamma1 - r->coeffs[2*i+1];
        }
    }
};

template <class PARAMS>
void poly_pack_z(byte *r, const poly *a) {
    PackZImpl<PARAMS::gamma1>::pack(r, a);
}

template <class PARAMS>
void poly_unpack_z(poly *r, const byte *a) {
    PackZImpl<PARAMS::gamma1>::unpack(r, a);
}

template void poly_pack_z<Params_44>(byte *r, const poly *a);
template void poly_pack_z<Params_65>(byte *r, const poly *a);
template void poly_pack_z<Params_87>(byte *r, const poly *a);
template void poly_unpack_z<Params_44>(poly *r, const byte *a);
template void poly_unpack_z<Params_65>(poly *r, const byte *a);
template void poly_unpack_z<Params_87>(poly *r, const byte *a);

// ==================== W1 Packing ====================

// gamma2 values: (MLDSA_Q - 1) / 88 = 95232, (MLDSA_Q - 1) / 32 = 261888
static const int32_t GAMMA2_DIV88 = (MLDSA_Q - 1) / 88;  // 95232
static const int32_t GAMMA2_DIV32 = (MLDSA_Q - 1) / 32;  // 261888

// Helper for gamma2-based W1 packing (6-bit vs 4-bit)
template <int32_t GAMMA2>
struct PackW1Impl;

template <>
struct PackW1Impl<(MLDSA_Q - 1) / 88> {
    static void pack(byte *r, const poly *a) {
        // 6 bits per coefficient (43 values possible)
        for (unsigned int i = 0; i < MLDSA_N / 4; i++) {
            r[3*i+0]  = static_cast<byte>(a->coeffs[4*i+0]);
            r[3*i+0] |= static_cast<byte>(a->coeffs[4*i+1] << 6);
            r[3*i+1]  = static_cast<byte>(a->coeffs[4*i+1] >> 2);
            r[3*i+1] |= static_cast<byte>(a->coeffs[4*i+2] << 4);
            r[3*i+2]  = static_cast<byte>(a->coeffs[4*i+2] >> 4);
            r[3*i+2] |= static_cast<byte>(a->coeffs[4*i+3] << 2);
        }
    }
};

template <>
struct PackW1Impl<(MLDSA_Q - 1) / 32> {
    static void pack(byte *r, const poly *a) {
        // 4 bits per coefficient (15 values possible)
        for (unsigned int i = 0; i < MLDSA_N / 2; i++)
            r[i] = static_cast<byte>(a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4));
    }
};

template <class PARAMS>
void poly_pack_w1(byte *r, const poly *a) {
    PackW1Impl<PARAMS::gamma2>::pack(r, a);
}

template void poly_pack_w1<Params_44>(byte *r, const poly *a);
template void poly_pack_w1<Params_65>(byte *r, const poly *a);
template void poly_pack_w1<Params_87>(byte *r, const poly *a);

// ==================== Decompose ====================

// Helper for gamma2-based decomposition
template <int32_t GAMMA2>
struct DecomposeImpl;

template <>
struct DecomposeImpl<(MLDSA_Q - 1) / 88> {
    static void decompose(poly *a1, poly *a0, const poly *a) {
        const int32_t gamma2 = (MLDSA_Q - 1) / 88;
        for (unsigned int i = 0; i < MLDSA_N; i++) {
            int32_t r = a->coeffs[i];
            int32_t r1, r0;

            r1 = (r + 127) >> 7;
            r1 = (r1 * 11275 + (1 << 23)) >> 24;
            r1 ^= ((43 - r1) >> 31) & r1;  // Set r1 to 0 if r1 >= 43 (wraps around)

            r0 = r - r1 * 2 * gamma2;
            r0 -= (((MLDSA_Q - 1) / 2 - r0) >> 31) & MLDSA_Q;

            a1->coeffs[i] = r1;
            a0->coeffs[i] = r0;
        }
    }
};

template <>
struct DecomposeImpl<(MLDSA_Q - 1) / 32> {
    static void decompose(poly *a1, poly *a0, const poly *a) {
        const int32_t gamma2 = (MLDSA_Q - 1) / 32;
        for (unsigned int i = 0; i < MLDSA_N; i++) {
            int32_t r = a->coeffs[i];
            int32_t r1, r0;

            r1 = (r + 127) >> 7;
            r1 = (r1 * 1025 + (1 << 21)) >> 22;
            r1 &= 15;

            r0 = r - r1 * 2 * gamma2;
            r0 -= (((MLDSA_Q - 1) / 2 - r0) >> 31) & MLDSA_Q;

            a1->coeffs[i] = r1;
            a0->coeffs[i] = r0;
        }
    }
};

template <class PARAMS>
void poly_decompose(poly *a1, poly *a0, const poly *a) {
    DecomposeImpl<PARAMS::gamma2>::decompose(a1, a0, a);
}

template void poly_decompose<Params_44>(poly *a1, poly *a0, const poly *a);
template void poly_decompose<Params_65>(poly *a1, poly *a0, const poly *a);
template void poly_decompose<Params_87>(poly *a1, poly *a0, const poly *a);

// ==================== Hints ====================

template <class PARAMS>
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1) {
    constexpr int32_t gamma2 = PARAMS::gamma2;
    unsigned int s = 0;

    for (unsigned int i = 0; i < MLDSA_N; i++) {
        h->coeffs[i] = make_hint_internal(a0->coeffs[i], a1->coeffs[i], gamma2);
        s += h->coeffs[i];
    }

    return s;
}

template <class PARAMS>
void poly_use_hint(poly *b, const poly *a, const poly *h) {
    constexpr int32_t gamma2 = PARAMS::gamma2;

    for (unsigned int i = 0; i < MLDSA_N; i++)
        b->coeffs[i] = use_hint_internal(a->coeffs[i], h->coeffs[i], gamma2);
}

template unsigned int poly_make_hint<Params_44>(poly *h, const poly *a0, const poly *a1);
template unsigned int poly_make_hint<Params_65>(poly *h, const poly *a0, const poly *a1);
template unsigned int poly_make_hint<Params_87>(poly *h, const poly *a0, const poly *a1);
template void poly_use_hint<Params_44>(poly *b, const poly *a, const poly *h);
template void poly_use_hint<Params_65>(poly *b, const poly *a, const poly *h);
template void poly_use_hint<Params_87>(poly *b, const poly *a, const poly *h);

// ==================== Vector Operations ====================

template <unsigned int K>
void polyveck_zero(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_zero(&v->vec[i]);
}

template <unsigned int L>
void polyvecl_zero(polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_zero(&v->vec[i]);
}

template <unsigned int K>
void polyveck_add(polyveck<K> *w, const polyveck<K> *u, const polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

template <unsigned int L>
void polyvecl_add(polyvecl<L> *w, const polyvecl<L> *u, const polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

template <unsigned int K>
void polyveck_sub(polyveck<K> *w, const polyveck<K> *u, const polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

template <unsigned int L>
void polyvecl_sub(polyvecl<L> *w, const polyvecl<L> *u, const polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

template <unsigned int K>
void polyveck_ntt(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_ntt(&v->vec[i]);
}

template <unsigned int L>
void polyvecl_ntt(polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_ntt(&v->vec[i]);
}

template <unsigned int K>
void polyveck_invntt(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_invntt(&v->vec[i]);
}

template <unsigned int L>
void polyvecl_invntt(polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_invntt(&v->vec[i]);
}

template <unsigned int K>
void polyveck_reduce(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_reduce(&v->vec[i]);
}

template <unsigned int L>
void polyvecl_reduce(polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_reduce(&v->vec[i]);
}

template <unsigned int K>
void polyveck_caddq(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_caddq(&v->vec[i]);
}

template <unsigned int L>
void polyvecl_caddq(polyvecl<L> *v) {
    for (unsigned int i = 0; i < L; i++)
        poly_caddq(&v->vec[i]);
}

template <unsigned int K>
void polyveck_freeze(polyveck<K> *v) {
    for (unsigned int i = 0; i < K; i++)
        poly_freeze(&v->vec[i]);
}

template <unsigned int K>
int polyveck_chknorm(const polyveck<K> *v, int32_t bound) {
    int result = 0;
    for (unsigned int i = 0; i < K; i++)
        result |= poly_chknorm(&v->vec[i], bound);
    return result;
}

template <unsigned int L>
int polyvecl_chknorm(const polyvecl<L> *v, int32_t bound) {
    int result = 0;
    for (unsigned int i = 0; i < L; i++)
        result |= poly_chknorm(&v->vec[i], bound);
    return result;
}

// Explicit instantiations for vector operations
template void polyveck_zero<4>(polyveck<4> *v);
template void polyveck_zero<6>(polyveck<6> *v);
template void polyveck_zero<8>(polyveck<8> *v);
template void polyvecl_zero<4>(polyvecl<4> *v);
template void polyvecl_zero<5>(polyvecl<5> *v);
template void polyvecl_zero<7>(polyvecl<7> *v);
template void polyveck_add<4>(polyveck<4> *w, const polyveck<4> *u, const polyveck<4> *v);
template void polyveck_add<6>(polyveck<6> *w, const polyveck<6> *u, const polyveck<6> *v);
template void polyveck_add<8>(polyveck<8> *w, const polyveck<8> *u, const polyveck<8> *v);
template void polyvecl_add<4>(polyvecl<4> *w, const polyvecl<4> *u, const polyvecl<4> *v);
template void polyvecl_add<5>(polyvecl<5> *w, const polyvecl<5> *u, const polyvecl<5> *v);
template void polyvecl_add<7>(polyvecl<7> *w, const polyvecl<7> *u, const polyvecl<7> *v);
template void polyveck_sub<4>(polyveck<4> *w, const polyveck<4> *u, const polyveck<4> *v);
template void polyveck_sub<6>(polyveck<6> *w, const polyveck<6> *u, const polyveck<6> *v);
template void polyveck_sub<8>(polyveck<8> *w, const polyveck<8> *u, const polyveck<8> *v);
template void polyveck_ntt<4>(polyveck<4> *v);
template void polyveck_ntt<6>(polyveck<6> *v);
template void polyveck_ntt<8>(polyveck<8> *v);
template void polyvecl_ntt<4>(polyvecl<4> *v);
template void polyvecl_ntt<5>(polyvecl<5> *v);
template void polyvecl_ntt<7>(polyvecl<7> *v);
template void polyveck_invntt<4>(polyveck<4> *v);
template void polyveck_invntt<6>(polyveck<6> *v);
template void polyveck_invntt<8>(polyveck<8> *v);
template void polyvecl_invntt<4>(polyvecl<4> *v);
template void polyvecl_invntt<5>(polyvecl<5> *v);
template void polyvecl_invntt<7>(polyvecl<7> *v);
template void polyveck_reduce<4>(polyveck<4> *v);
template void polyveck_reduce<6>(polyveck<6> *v);
template void polyveck_reduce<8>(polyveck<8> *v);
template void polyvecl_reduce<4>(polyvecl<4> *v);
template void polyvecl_reduce<5>(polyvecl<5> *v);
template void polyvecl_reduce<7>(polyvecl<7> *v);
template void polyveck_caddq<4>(polyveck<4> *v);
template void polyveck_caddq<6>(polyveck<6> *v);
template void polyveck_caddq<8>(polyveck<8> *v);
template void polyveck_freeze<4>(polyveck<4> *v);
template void polyveck_freeze<6>(polyveck<6> *v);
template void polyveck_freeze<8>(polyveck<8> *v);
template int polyveck_chknorm<4>(const polyveck<4> *v, int32_t bound);
template int polyveck_chknorm<6>(const polyveck<6> *v, int32_t bound);
template int polyveck_chknorm<8>(const polyveck<8> *v, int32_t bound);
template int polyvecl_chknorm<4>(const polyvecl<4> *v, int32_t bound);
template int polyvecl_chknorm<5>(const polyvecl<5> *v, int32_t bound);
template int polyvecl_chknorm<7>(const polyvecl<7> *v, int32_t bound);

// ==================== Matrix Operations ====================

// Expand matrix A from seed rho (result is in NTT domain)
template <class PARAMS>
void expand_matrix(poly A[PARAMS::k][PARAMS::l], const byte *rho) {
    for (unsigned int i = 0; i < PARAMS::k; i++) {
        for (unsigned int j = 0; j < PARAMS::l; j++) {
            // RejNTTPoly produces NTT-domain coefficients directly
            poly_uniform(&A[i][j], rho, static_cast<uint16_t>((i << 8) + j));
        }
    }
}

// Matrix-vector multiply: t = A * s (A in NTT domain)
template <class PARAMS>
void polyvec_matrix_pointwise_montgomery(
    polyveck<PARAMS::k> *t,
    const poly A[PARAMS::k][PARAMS::l],
    const polyvecl<PARAMS::l> *s)
{
    poly tmp;

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_pointwise_montgomery(&t->vec[i], &A[i][0], &s->vec[0]);
        for (unsigned int j = 1; j < PARAMS::l; j++) {
            poly_pointwise_montgomery(&tmp, &A[i][j], &s->vec[j]);
            poly_add(&t->vec[i], &t->vec[i], &tmp);
        }
    }
}

template void expand_matrix<Params_44>(poly A[Params_44::k][Params_44::l], const byte *rho);
template void expand_matrix<Params_65>(poly A[Params_65::k][Params_65::l], const byte *rho);
template void expand_matrix<Params_87>(poly A[Params_87::k][Params_87::l], const byte *rho);
template void polyvec_matrix_pointwise_montgomery<Params_44>(
    polyveck<Params_44::k> *t, const poly A[Params_44::k][Params_44::l], const polyvecl<Params_44::l> *s);
template void polyvec_matrix_pointwise_montgomery<Params_65>(
    polyveck<Params_65::k> *t, const poly A[Params_65::k][Params_65::l], const polyvecl<Params_65::l> *s);
template void polyvec_matrix_pointwise_montgomery<Params_87>(
    polyveck<Params_87::k> *t, const poly A[Params_87::k][Params_87::l], const polyvecl<Params_87::l> *s);

// ==================== Key/Signature Packing ====================

// Pack public key: pk = rho || t1
template <class PARAMS>
void pack_pk(byte *pk, const byte *rho, const polyveck<PARAMS::k> *t1) {
    std::memcpy(pk, rho, SEEDBYTES);
    pk += SEEDBYTES;
    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_pack_t1(pk, &t1->vec[i]);
        pk += POLYT1_PACKEDBYTES;
    }
}

// Unpack public key
template <class PARAMS>
void unpack_pk(byte *rho, polyveck<PARAMS::k> *t1, const byte *pk) {
    std::memcpy(rho, pk, SEEDBYTES);
    pk += SEEDBYTES;
    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_unpack_t1(&t1->vec[i], pk);
        pk += POLYT1_PACKEDBYTES;
    }
}

// Pack secret key: sk = rho || K || tr || s1 || s2 || t0
template <class PARAMS>
void pack_sk(byte *sk, const byte *rho, const byte *tr, const byte *key,
             const polyveck<PARAMS::k> *t0,
             const polyvecl<PARAMS::l> *s1,
             const polyveck<PARAMS::k> *s2)
{
    std::memcpy(sk, rho, SEEDBYTES);
    sk += SEEDBYTES;
    std::memcpy(sk, key, SEEDBYTES);
    sk += SEEDBYTES;
    std::memcpy(sk, tr, TRBYTES);
    sk += TRBYTES;

    for (unsigned int i = 0; i < PARAMS::l; i++) {
        poly_pack_eta<PARAMS>(sk, &s1->vec[i]);
        sk += PARAMS::POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_pack_eta<PARAMS>(sk, &s2->vec[i]);
        sk += PARAMS::POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_pack_t0(sk, &t0->vec[i]);
        sk += POLYT0_PACKEDBYTES;
    }
}

// Unpack secret key
template <class PARAMS>
void unpack_sk(byte *rho, byte *tr, byte *key,
               polyveck<PARAMS::k> *t0,
               polyvecl<PARAMS::l> *s1,
               polyveck<PARAMS::k> *s2,
               const byte *sk)
{
    std::memcpy(rho, sk, SEEDBYTES);
    sk += SEEDBYTES;
    std::memcpy(key, sk, SEEDBYTES);
    sk += SEEDBYTES;
    std::memcpy(tr, sk, TRBYTES);
    sk += TRBYTES;

    for (unsigned int i = 0; i < PARAMS::l; i++) {
        poly_unpack_eta<PARAMS>(&s1->vec[i], sk);
        sk += PARAMS::POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_unpack_eta<PARAMS>(&s2->vec[i], sk);
        sk += PARAMS::POLYETA_PACKEDBYTES;
    }

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_unpack_t0(&t0->vec[i], sk);
        sk += POLYT0_PACKEDBYTES;
    }
}

// Pack signature: sig = c_tilde || z || h
template <class PARAMS>
void pack_sig(byte *sig,
              const byte *c_tilde,
              const polyvecl<PARAMS::l> *z,
              const polyveck<PARAMS::k> *h)
{
    std::memcpy(sig, c_tilde, PARAMS::CTILDEBYTES);
    sig += PARAMS::CTILDEBYTES;

    for (unsigned int i = 0; i < PARAMS::l; i++) {
        poly_pack_z<PARAMS>(sig, &z->vec[i]);
        sig += PARAMS::POLYZ_PACKEDBYTES;
    }

    // Encode hints
    unsigned int k = 0;
    for (unsigned int i = 0; i < PARAMS::k; i++) {
        for (unsigned int j = 0; j < MLDSA_N; j++)
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = static_cast<byte>(j);
        sig[PARAMS::omega + i] = static_cast<byte>(k);
    }

    while (k < PARAMS::omega)
        sig[k++] = 0;
}

// Unpack signature: returns 1 on failure
template <class PARAMS>
int unpack_sig(byte *c_tilde,
               polyvecl<PARAMS::l> *z,
               polyveck<PARAMS::k> *h,
               const byte *sig)
{
    std::memcpy(c_tilde, sig, PARAMS::CTILDEBYTES);
    sig += PARAMS::CTILDEBYTES;

    for (unsigned int i = 0; i < PARAMS::l; i++) {
        poly_unpack_z<PARAMS>(&z->vec[i], sig);
        sig += PARAMS::POLYZ_PACKEDBYTES;
    }

    // Decode hints
    unsigned int k = 0;
    for (unsigned int i = 0; i < PARAMS::k; i++) {
        poly_zero(&h->vec[i]);

        if (sig[PARAMS::omega + i] < k || sig[PARAMS::omega + i] > PARAMS::omega)
            return 1;

        for (unsigned int j = k; j < sig[PARAMS::omega + i]; j++) {
            // Indices need to be increasing
            if (j > k && sig[j] <= sig[j-1])
                return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[PARAMS::omega + i];
    }

    // Remaining indices must be zero
    for (unsigned int j = k; j < PARAMS::omega; j++)
        if (sig[j] != 0)
            return 1;

    return 0;
}

template void pack_pk<Params_44>(byte *pk, const byte *rho, const polyveck<Params_44::k> *t1);
template void pack_pk<Params_65>(byte *pk, const byte *rho, const polyveck<Params_65::k> *t1);
template void pack_pk<Params_87>(byte *pk, const byte *rho, const polyveck<Params_87::k> *t1);
template void unpack_pk<Params_44>(byte *rho, polyveck<Params_44::k> *t1, const byte *pk);
template void unpack_pk<Params_65>(byte *rho, polyveck<Params_65::k> *t1, const byte *pk);
template void unpack_pk<Params_87>(byte *rho, polyveck<Params_87::k> *t1, const byte *pk);
template void pack_sk<Params_44>(byte *sk, const byte *rho, const byte *tr, const byte *key,
    const polyveck<Params_44::k> *t0, const polyvecl<Params_44::l> *s1, const polyveck<Params_44::k> *s2);
template void pack_sk<Params_65>(byte *sk, const byte *rho, const byte *tr, const byte *key,
    const polyveck<Params_65::k> *t0, const polyvecl<Params_65::l> *s1, const polyveck<Params_65::k> *s2);
template void pack_sk<Params_87>(byte *sk, const byte *rho, const byte *tr, const byte *key,
    const polyveck<Params_87::k> *t0, const polyvecl<Params_87::l> *s1, const polyveck<Params_87::k> *s2);
template void unpack_sk<Params_44>(byte *rho, byte *tr, byte *key,
    polyveck<Params_44::k> *t0, polyvecl<Params_44::l> *s1, polyveck<Params_44::k> *s2, const byte *sk);
template void unpack_sk<Params_65>(byte *rho, byte *tr, byte *key,
    polyveck<Params_65::k> *t0, polyvecl<Params_65::l> *s1, polyveck<Params_65::k> *s2, const byte *sk);
template void unpack_sk<Params_87>(byte *rho, byte *tr, byte *key,
    polyveck<Params_87::k> *t0, polyvecl<Params_87::l> *s1, polyveck<Params_87::k> *s2, const byte *sk);
template void pack_sig<Params_44>(byte *sig, const byte *c_tilde,
    const polyvecl<Params_44::l> *z, const polyveck<Params_44::k> *h);
template void pack_sig<Params_65>(byte *sig, const byte *c_tilde,
    const polyvecl<Params_65::l> *z, const polyveck<Params_65::k> *h);
template void pack_sig<Params_87>(byte *sig, const byte *c_tilde,
    const polyvecl<Params_87::l> *z, const polyveck<Params_87::k> *h);
template int unpack_sig<Params_44>(byte *c_tilde,
    polyvecl<Params_44::l> *z, polyveck<Params_44::k> *h, const byte *sig);
template int unpack_sig<Params_65>(byte *c_tilde,
    polyvecl<Params_65::l> *z, polyveck<Params_65::k> *h, const byte *sig);
template int unpack_sig<Params_87>(byte *c_tilde,
    polyvecl<Params_87::l> *z, polyveck<Params_87::k> *h, const byte *sig);

// ==================== Core Algorithm Traits ====================

// Internal params to external params mapping
template <class PARAMS>
struct InternalParams;

template <>
struct InternalParams<MLDSA_44> {
    using type = Params_44;
};

template <>
struct InternalParams<MLDSA_65> {
    using type = Params_65;
};

template <>
struct InternalParams<MLDSA_87> {
    using type = Params_87;
};

NAMESPACE_END  // MLDSA_Internal
NAMESPACE_END  // CryptoPP

// ==================== Public API Implementation ====================

NAMESPACE_BEGIN(CryptoPP)

// MLDSAPrivateKey implementation
template <class PARAMS>
bool MLDSAPrivateKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const {
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    return m_sk.size() == SECRET_KEYLENGTH && m_pk.size() == PUBLIC_KEYLENGTH;
}

template <class PARAMS>
bool MLDSAPrivateKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const {
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void MLDSAPrivateKey<PARAMS>::AssignFrom(const NameValuePairs &source) {
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void MLDSAPrivateKey<PARAMS>::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params) {
    CRYPTOPP_UNUSED(params);
    using namespace MLDSA_Internal;
    using IntParams = typename InternalParams<PARAMS>::type;

    // Allocate output buffers
    m_sk.resize(SECRET_KEYLENGTH);
    m_pk.resize(PUBLIC_KEYLENGTH);

    // Step 1: Generate random seed xi (32 bytes)
    byte seedbuf[2 * SEEDBYTES + CRHBYTES];
    rng.GenerateBlock(seedbuf, SEEDBYTES);

    // Step 2: Expand seed into (rho, rho', K) using SHAKE256
    // FIPS 204 Algorithm 1: H(xi || k || l, 128)
    byte domain[2] = { static_cast<byte>(IntParams::k), static_cast<byte>(IntParams::l) };
    SHAKE256 shake(2 * SEEDBYTES + CRHBYTES);
    shake.Update(seedbuf, SEEDBYTES);
    shake.Update(domain, 2);
    shake.TruncatedFinal(seedbuf, 2 * SEEDBYTES + CRHBYTES);

    byte* rho = seedbuf;                    // Public seed for A (32 bytes)
    byte* rhoprime = seedbuf + SEEDBYTES;   // Private seed for s1, s2 (64 bytes = CRHBYTES)
    byte* key = seedbuf + SEEDBYTES + CRHBYTES;    // Private key K (32 bytes)

    // Step 3: Expand matrix A from rho
    poly A[IntParams::k][IntParams::l];
    expand_matrix<IntParams>(A, rho);

    // Step 4: Sample secret vectors s1 and s2 from rhoprime
    polyvecl<IntParams::l> s1;
    polyveck<IntParams::k> s2;

    for (unsigned int i = 0; i < IntParams::l; i++)
        poly_uniform_eta<IntParams>(&s1.vec[i], rhoprime, static_cast<uint16_t>(i));

    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_uniform_eta<IntParams>(&s2.vec[i], rhoprime, static_cast<uint16_t>(IntParams::l + i));

    // Step 5: Compute t = A * s1 + s2
    polyvecl<IntParams::l> s1hat = s1;
    polyvecl_ntt<IntParams::l>(&s1hat);

    polyveck<IntParams::k> t;
    polyvec_matrix_pointwise_montgomery<IntParams>(&t, A, &s1hat);
    polyveck_reduce<IntParams::k>(&t);
    polyveck_invntt<IntParams::k>(&t);

    // Add s2
    polyveck_add<IntParams::k>(&t, &t, &s2);
    polyveck_caddq<IntParams::k>(&t);

    // Step 6: Power2Round to get t1 and t0
    polyveck<IntParams::k> t1, t0;
    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_power2round(&t1.vec[i], &t0.vec[i], &t.vec[i]);

    // Step 7: Pack public key
    pack_pk<IntParams>(m_pk.begin(), rho, &t1);

    // Step 8: Compute tr = H(pk)
    byte tr[TRBYTES];
    SHAKE256 shake_tr(TRBYTES);
    shake_tr.Update(m_pk.begin(), PUBLIC_KEYLENGTH);
    shake_tr.TruncatedFinal(tr, TRBYTES);

    // Step 9: Pack secret key
    pack_sk<IntParams>(m_sk.begin(), rho, tr, key, &t0, &s1, &s2);

    // Zeroize secret data on stack
    SecureWipeBuffer(seedbuf, sizeof(seedbuf));
    SecureWipeBuffer(tr, sizeof(tr));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1), sizeof(s1));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s2), sizeof(s2));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1hat), sizeof(s1hat));
    SecureWipeBuffer(reinterpret_cast<byte*>(&t0), sizeof(t0));
}

template <class PARAMS>
void MLDSAPrivateKey<PARAMS>::SetPrivateKey(const byte *key, size_t len) {
    if (len != SECRET_KEYLENGTH)
        throw InvalidArgument("ML-DSA: Invalid private key length");
    using namespace MLDSA_Internal;
    using IntParams = typename InternalParams<PARAMS>::type;

    m_sk.Assign(key, len);

    // Extract components from secret key and regenerate public key
    byte rho[SEEDBYTES];
    byte tr[TRBYTES];
    byte keyK[SEEDBYTES];
    polyveck<IntParams::k> t0;
    polyvecl<IntParams::l> s1;
    polyveck<IntParams::k> s2;

    unpack_sk<IntParams>(rho, tr, keyK, &t0, &s1, &s2, key);

    // Regenerate t1 from s1, s2, and A
    poly A[IntParams::k][IntParams::l];
    expand_matrix<IntParams>(A, rho);

    polyvecl<IntParams::l> s1hat = s1;
    polyvecl_ntt<IntParams::l>(&s1hat);

    polyveck<IntParams::k> t;
    polyvec_matrix_pointwise_montgomery<IntParams>(&t, A, &s1hat);
    polyveck_reduce<IntParams::k>(&t);
    polyveck_invntt<IntParams::k>(&t);

    polyveck_add<IntParams::k>(&t, &t, &s2);
    polyveck_caddq<IntParams::k>(&t);

    polyveck<IntParams::k> t1;
    polyveck<IntParams::k> t0_temp;  // Not needed but required by power2round
    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_power2round(&t1.vec[i], &t0_temp.vec[i], &t.vec[i]);

    // Pack public key
    m_pk.resize(PUBLIC_KEYLENGTH);
    pack_pk<IntParams>(m_pk.begin(), rho, &t1);

    // Zeroize secret data on stack
    SecureWipeBuffer(keyK, sizeof(keyK));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1), sizeof(s1));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s2), sizeof(s2));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1hat), sizeof(s1hat));
    SecureWipeBuffer(reinterpret_cast<byte*>(&t0), sizeof(t0));
}

template <class PARAMS>
void MLDSAPrivateKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // PKCS#8 OneAsymmetricKey format (RFC 5958)
    DERSequenceEncoder privateKeyInfo(bt);
        DEREncodeUnsigned<word32>(privateKeyInfo, 0);  // version

        DERSequenceEncoder algorithm(privateKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
            DERGeneralEncoder privateKey(octetString, OCTET_STRING);
                privateKey.Put(m_sk.begin(), SECRET_KEYLENGTH);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

template <class PARAMS>
void MLDSAPrivateKey<PARAMS>::BERDecode(BufferedTransformation &bt)
{
    // PKCS#8 OneAsymmetricKey format (RFC 5958)
    BERSequenceDecoder privateKeyInfo(bt);
        word32 version;
        BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 1);

        BERSequenceDecoder algorithm(privateKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
            BERGeneralDecoder privateKey(octetString, OCTET_STRING);
                if (!privateKey.IsDefiniteLength() ||
                    privateKey.RemainingLength() != SECRET_KEYLENGTH)
                    BERDecodeError();
                SecByteBlock sk(SECRET_KEYLENGTH);
                privateKey.Get(sk.begin(), SECRET_KEYLENGTH);
                SetPrivateKey(sk.begin(), SECRET_KEYLENGTH);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

// MLDSAPublicKey implementation
template <class PARAMS>
bool MLDSAPublicKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const {
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    return m_pk.size() == PUBLIC_KEYLENGTH;
}

template <class PARAMS>
bool MLDSAPublicKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const {
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void MLDSAPublicKey<PARAMS>::AssignFrom(const NameValuePairs &source) {
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void MLDSAPublicKey<PARAMS>::SetPublicKey(const byte *key, size_t len) {
    if (len != PUBLIC_KEYLENGTH)
        throw InvalidArgument("ML-DSA: Invalid public key length");

    m_pk.Assign(key, len);
}

template <class PARAMS>
void MLDSAPublicKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // X.509 SubjectPublicKeyInfo format (RFC 5280)
    DERSequenceEncoder publicKeyInfo(bt);
        DERSequenceEncoder algorithm(publicKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DEREncodeBitString(publicKeyInfo, m_pk.begin(), PUBLIC_KEYLENGTH);
    publicKeyInfo.MessageEnd();
}

template <class PARAMS>
void MLDSAPublicKey<PARAMS>::BERDecode(BufferedTransformation &bt)
{
    // X.509 SubjectPublicKeyInfo format (RFC 5280)
    BERSequenceDecoder publicKeyInfo(bt);
        BERSequenceDecoder algorithm(publicKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        SecByteBlock subjectPublicKey;
        unsigned int unusedBits;
        BERDecodeBitString(publicKeyInfo, subjectPublicKey, unusedBits);
        if (unusedBits != 0 || subjectPublicKey.size() != PUBLIC_KEYLENGTH)
            BERDecodeError();
        SetPublicKey(subjectPublicKey.begin(), PUBLIC_KEYLENGTH);

    publicKeyInfo.MessageEnd();
}

// MLDSASigner implementation
template <class PARAMS>
MLDSASigner<PARAMS>::MLDSASigner(RandomNumberGenerator &rng) {
    m_key.GenerateRandom(rng, g_nullNameValuePairs);
}

template <class PARAMS>
MLDSASigner<PARAMS>::MLDSASigner(const byte *privateKey, size_t privateKeyLen) {
    m_key.SetPrivateKey(privateKey, privateKeyLen);
}

template <class PARAMS>
size_t MLDSASigner<PARAMS>::SignAndRestart(RandomNumberGenerator &rng,
    PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const {
    using namespace MLDSA_Internal;
    using IntParams = typename InternalParams<PARAMS>::type;

    MessageAccumulatorType& accum = static_cast<MessageAccumulatorType&>(messageAccumulator);
    const byte* message = accum.data();
    size_t messageLen = accum.size();

    // Unpack secret key
    byte rho[SEEDBYTES];
    byte tr[TRBYTES];
    byte key[SEEDBYTES];
    polyveck<IntParams::k> t0;
    polyvecl<IntParams::l> s1;
    polyveck<IntParams::k> s2;

    unpack_sk<IntParams>(rho, tr, key, &t0, &s1, &s2, m_key.GetPrivateKeyBytePtr());

    // Expand A from rho
    poly A[IntParams::k][IntParams::l];
    expand_matrix<IntParams>(A, rho);

    // Compute mu = H(tr || M') where M' = 0x00 || len(ctx) || ctx || M (FIPS 204, pure signing)
    byte mu[CRHBYTES];
    byte msg_prefix[2] = { 0x00, static_cast<byte>(accum.contextSize()) };
    SHAKE256 shake_mu(CRHBYTES);
    shake_mu.Update(tr, TRBYTES);
    shake_mu.Update(msg_prefix, 2);
    if (accum.contextSize() > 0)
        shake_mu.Update(accum.context(), accum.contextSize());
    shake_mu.Update(message, messageLen);
    shake_mu.TruncatedFinal(mu, CRHBYTES);

    // Generate random rho'' for signing
    byte rhoprime[CRHBYTES];
    SHAKE256 shake_rnd(CRHBYTES);
    shake_rnd.Update(key, SEEDBYTES);
    byte rnd[SEEDBYTES];
    rng.GenerateBlock(rnd, SEEDBYTES);
    shake_rnd.Update(rnd, SEEDBYTES);
    shake_rnd.Update(mu, CRHBYTES);
    shake_rnd.TruncatedFinal(rhoprime, CRHBYTES);

    // Convert s1, s2, t0 to NTT domain for faster computation
    polyvecl<IntParams::l> s1hat = s1;
    polyveck<IntParams::k> s2hat = s2;
    polyveck<IntParams::k> t0hat = t0;

    polyvecl_ntt<IntParams::l>(&s1hat);
    polyveck_ntt<IntParams::k>(&s2hat);
    polyveck_ntt<IntParams::k>(&t0hat);

    // Rejection sampling loop
    polyvecl<IntParams::l> y, z;
    polyveck<IntParams::k> w, w1, w0, h;
    poly cp;
    unsigned int nonce = 0;

    while (true) {
        if (nonce > 10000) {
            SecureWipeBuffer(key, sizeof(key));
            SecureWipeBuffer(rhoprime, sizeof(rhoprime));
            SecureWipeBuffer(rnd, sizeof(rnd));
            SecureWipeBuffer(mu, sizeof(mu));
            SecureWipeBuffer(reinterpret_cast<byte*>(&s1), sizeof(s1));
            SecureWipeBuffer(reinterpret_cast<byte*>(&s2), sizeof(s2));
            SecureWipeBuffer(reinterpret_cast<byte*>(&t0), sizeof(t0));
            SecureWipeBuffer(reinterpret_cast<byte*>(&s1hat), sizeof(s1hat));
            SecureWipeBuffer(reinterpret_cast<byte*>(&s2hat), sizeof(s2hat));
            SecureWipeBuffer(reinterpret_cast<byte*>(&t0hat), sizeof(t0hat));
            SecureWipeBuffer(reinterpret_cast<byte*>(&y), sizeof(y));
            SecureWipeBuffer(reinterpret_cast<byte*>(&z), sizeof(z));
            SecureWipeBuffer(reinterpret_cast<byte*>(&w), sizeof(w));
            SecureWipeBuffer(reinterpret_cast<byte*>(&w1), sizeof(w1));
            SecureWipeBuffer(reinterpret_cast<byte*>(&w0), sizeof(w0));
            SecureWipeBuffer(reinterpret_cast<byte*>(&h), sizeof(h));
            SecureWipeBuffer(reinterpret_cast<byte*>(&cp), sizeof(cp));
            throw Exception(Exception::OTHER_ERROR, "ML-DSA: Too many rejection samples in signing");
        }

        // Sample y from rhoprime
        for (unsigned int i = 0; i < IntParams::l; i++)
            poly_uniform_gamma1<IntParams>(&y.vec[i], rhoprime, static_cast<uint16_t>(IntParams::l * nonce + i));
        nonce++;

        // w = A * y
        polyvecl<IntParams::l> yhat = y;
        polyvecl_ntt<IntParams::l>(&yhat);
        polyvec_matrix_pointwise_montgomery<IntParams>(&w, A, &yhat);
        polyveck_reduce<IntParams::k>(&w);
        polyveck_invntt<IntParams::k>(&w);
        polyveck_caddq<IntParams::k>(&w);

        // Decompose w into w1, w0
        for (unsigned int i = 0; i < IntParams::k; i++)
            poly_decompose<IntParams>(&w1.vec[i], &w0.vec[i], &w.vec[i]);

        // Pack w1 and compute challenge hash
        byte w1_packed[IntParams::k * IntParams::POLYW1_PACKEDBYTES];
        for (unsigned int i = 0; i < IntParams::k; i++)
            poly_pack_w1<IntParams>(w1_packed + i * IntParams::POLYW1_PACKEDBYTES, &w1.vec[i]);

        byte c_tilde[IntParams::CTILDEBYTES];
        SHAKE256 shake_c(IntParams::CTILDEBYTES);
        shake_c.Update(mu, CRHBYTES);
        shake_c.Update(w1_packed, sizeof(w1_packed));
        shake_c.TruncatedFinal(c_tilde, IntParams::CTILDEBYTES);

        // Sample challenge polynomial c
        poly_challenge<IntParams>(&cp, c_tilde);

        // NTT of c
        poly chat = cp;
        poly_ntt(&chat);

        // z = y + c * s1
        for (unsigned int i = 0; i < IntParams::l; i++) {
            poly_pointwise_montgomery(&z.vec[i], &chat, &s1hat.vec[i]);
            poly_invntt(&z.vec[i]);
            poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
            poly_reduce(&z.vec[i]);
        }

        // Check norm of z
        if (polyvecl_chknorm<IntParams::l>(&z, IntParams::gamma1 - IntParams::beta))
            continue;

        // cs2 = c * s2
        polyveck<IntParams::k> cs2;
        for (unsigned int i = 0; i < IntParams::k; i++) {
            poly_pointwise_montgomery(&cs2.vec[i], &chat, &s2hat.vec[i]);
            poly_invntt(&cs2.vec[i]);
        }

        // w0 - cs2
        polyveck_sub<IntParams::k>(&w0, &w0, &cs2);
        polyveck_reduce<IntParams::k>(&w0);

        // Check norm of w0 - cs2
        if (polyveck_chknorm<IntParams::k>(&w0, IntParams::gamma2 - IntParams::beta))
            continue;

        // ct0 = c * t0
        polyveck<IntParams::k> ct0;
        for (unsigned int i = 0; i < IntParams::k; i++) {
            poly_pointwise_montgomery(&ct0.vec[i], &chat, &t0hat.vec[i]);
            poly_invntt(&ct0.vec[i]);
            poly_reduce(&ct0.vec[i]);
        }

        // Check norm of ct0
        if (polyveck_chknorm<IntParams::k>(&ct0, IntParams::gamma2))
            continue;

        // Add ct0 to w0
        polyveck_add<IntParams::k>(&w0, &w0, &ct0);

        // Make hints
        unsigned int n = 0;
        for (unsigned int i = 0; i < IntParams::k; i++)
            n += poly_make_hint<IntParams>(&h.vec[i], &w0.vec[i], &w1.vec[i]);

        if (n > IntParams::omega)
            continue;

        // Pack signature
        pack_sig<IntParams>(signature, c_tilde, &z, &h);
        break;
    }

    // Zeroize secret data on stack
    SecureWipeBuffer(key, sizeof(key));
    SecureWipeBuffer(rhoprime, sizeof(rhoprime));
    SecureWipeBuffer(rnd, sizeof(rnd));
    SecureWipeBuffer(mu, sizeof(mu));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1), sizeof(s1));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s2), sizeof(s2));
    SecureWipeBuffer(reinterpret_cast<byte*>(&t0), sizeof(t0));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s1hat), sizeof(s1hat));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s2hat), sizeof(s2hat));
    SecureWipeBuffer(reinterpret_cast<byte*>(&t0hat), sizeof(t0hat));
    SecureWipeBuffer(reinterpret_cast<byte*>(&y), sizeof(y));
    SecureWipeBuffer(reinterpret_cast<byte*>(&z), sizeof(z));
    SecureWipeBuffer(reinterpret_cast<byte*>(&w), sizeof(w));
    SecureWipeBuffer(reinterpret_cast<byte*>(&w1), sizeof(w1));
    SecureWipeBuffer(reinterpret_cast<byte*>(&w0), sizeof(w0));
    SecureWipeBuffer(reinterpret_cast<byte*>(&h), sizeof(h));
    SecureWipeBuffer(reinterpret_cast<byte*>(&cp), sizeof(cp));

    if (restart)
        accum.Restart();

    return SIGNATURE_LENGTH;
}

// MLDSAVerifier implementation
template <class PARAMS>
MLDSAVerifier<PARAMS>::MLDSAVerifier(const MLDSASigner<PARAMS> &signer) {
    m_key.SetPublicKey(signer.GetKey().GetPublicKeyBytePtr(),
                       signer.GetKey().GetPublicKeySize());
}

template <class PARAMS>
MLDSAVerifier<PARAMS>::MLDSAVerifier(const byte *publicKey, size_t publicKeyLen) {
    m_key.SetPublicKey(publicKey, publicKeyLen);
}

template <class PARAMS>
bool MLDSAVerifier<PARAMS>::VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const {
    using namespace MLDSA_Internal;
    using IntParams = typename InternalParams<PARAMS>::type;

    MessageAccumulatorType& accum = static_cast<MessageAccumulatorType&>(messageAccumulator);

    const byte* message = accum.data();
    size_t messageLen = accum.size();
    const byte* sig = accum.signature();

    // Unpack public key
    byte rho[SEEDBYTES];
    polyveck<IntParams::k> t1;
    unpack_pk<IntParams>(rho, &t1, m_key.GetPublicKeyBytePtr());

    // Unpack signature
    byte c_tilde[IntParams::CTILDEBYTES];
    polyvecl<IntParams::l> z;
    polyveck<IntParams::k> h;

    if (unpack_sig<IntParams>(c_tilde, &z, &h, sig)) {
        accum.Restart();
        return false;  // Invalid signature encoding
    }

    // Check norm of z
    if (polyvecl_chknorm<IntParams::l>(&z, IntParams::gamma1 - IntParams::beta)) {
        accum.Restart();
        return false;
    }

    // Compute tr = H(pk)
    byte tr[TRBYTES];
    SHAKE256 shake_tr(TRBYTES);
    shake_tr.Update(m_key.GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);
    shake_tr.TruncatedFinal(tr, TRBYTES);

    // Compute mu = H(tr || M') where M' = 0x00 || len(ctx) || ctx || M (FIPS 204, pure signing)
    byte mu[CRHBYTES];
    byte msg_prefix[2] = { 0x00, static_cast<byte>(accum.contextSize()) };
    SHAKE256 shake_mu(CRHBYTES);
    shake_mu.Update(tr, TRBYTES);
    shake_mu.Update(msg_prefix, 2);
    if (accum.contextSize() > 0)
        shake_mu.Update(accum.context(), accum.contextSize());
    shake_mu.Update(message, messageLen);
    shake_mu.TruncatedFinal(mu, CRHBYTES);

    // Expand A from rho
    poly A[IntParams::k][IntParams::l];
    expand_matrix<IntParams>(A, rho);

    // Sample challenge polynomial c from c_tilde
    poly cp;
    poly_challenge<IntParams>(&cp, c_tilde);
    poly_ntt(&cp);

    // Convert z to NTT domain
    polyvecl<IntParams::l> zhat = z;
    polyvecl_ntt<IntParams::l>(&zhat);

    // w' = Az - ct1*2^d
    polyveck<IntParams::k> w1prime;
    polyvec_matrix_pointwise_montgomery<IntParams>(&w1prime, A, &zhat);

    // Compute c*t1*2^d (need t1 shifted by 2^d = 2^13)
    polyveck<IntParams::k> t1hat = t1;
    // Shift t1 left by d=13 bits (multiply by 2^13)
    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_shiftl(&t1hat.vec[i]);
    polyveck_ntt<IntParams::k>(&t1hat);

    polyveck<IntParams::k> ct1;
    for (unsigned int i = 0; i < IntParams::k; i++) {
        poly_pointwise_montgomery(&ct1.vec[i], &cp, &t1hat.vec[i]);
    }

    // w' = Az - ct1 * 2^d (in NTT domain, then convert back)
    polyveck_sub<IntParams::k>(&w1prime, &w1prime, &ct1);
    polyveck_reduce<IntParams::k>(&w1prime);
    polyveck_invntt<IntParams::k>(&w1prime);

    // Shift ct1 back and add
    polyveck_caddq<IntParams::k>(&w1prime);

    // Use hints to recover w1
    polyveck<IntParams::k> w1;
    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_use_hint<IntParams>(&w1.vec[i], &w1prime.vec[i], &h.vec[i]);

    // Pack w1 and recompute challenge
    byte w1_packed[IntParams::k * IntParams::POLYW1_PACKEDBYTES];
    for (unsigned int i = 0; i < IntParams::k; i++)
        poly_pack_w1<IntParams>(w1_packed + i * IntParams::POLYW1_PACKEDBYTES, &w1.vec[i]);

    byte c_tilde_prime[IntParams::CTILDEBYTES];
    SHAKE256 shake_c(IntParams::CTILDEBYTES);
    shake_c.Update(mu, CRHBYTES);
    shake_c.Update(w1_packed, sizeof(w1_packed));
    shake_c.TruncatedFinal(c_tilde_prime, IntParams::CTILDEBYTES);

    // Compare c_tilde with c_tilde_prime (constant-time)
    bool valid = VerifyBufsEqual(c_tilde, c_tilde_prime, IntParams::CTILDEBYTES);

    accum.Restart();
    return valid;
}

// Explicit template instantiations
template struct MLDSAPrivateKey<MLDSA_44>;
template struct MLDSAPrivateKey<MLDSA_65>;
template struct MLDSAPrivateKey<MLDSA_87>;

template struct MLDSAPublicKey<MLDSA_44>;
template struct MLDSAPublicKey<MLDSA_65>;
template struct MLDSAPublicKey<MLDSA_87>;

template struct MLDSASigner<MLDSA_44>;
template struct MLDSASigner<MLDSA_65>;
template struct MLDSASigner<MLDSA_87>;

template struct MLDSAVerifier<MLDSA_44>;
template struct MLDSAVerifier<MLDSA_65>;
template struct MLDSAVerifier<MLDSA_87>;

NAMESPACE_END  // CryptoPP
