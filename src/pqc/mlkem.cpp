// mlkem.cpp - written and placed in the public domain by Colin Brown
//             ML-KEM (FIPS 203) implementation
//             Based on CRYSTALS-Kyber reference implementation (public domain)

#include <cryptopp/pch.h>
#include <cryptopp/mlkem.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>
#include <cryptopp/misc.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include "mlkem_params.h"
#include "mlkem_poly.h"

#include <cstring>
#include <stdexcept>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Internal Implementation ************************* //

namespace MLKEM_Internal {

// ******************** NTT Zetas Table ************************* //
// Precomputed powers of zeta in Montgomery form for NTT
// From CRYSTALS-Kyber reference implementation (public domain)
// zetas[i] = zeta^(BitRev7(i)) * 2^16 mod q, represented as signed int16

const int16_t MLKEM_ZETAS[128] = {
   -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
     573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
     516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
   -1103,   430,   555,   843, -1251,   871,  1550,   105,
     422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
   -1590,   644,  -872,   349,   418,   329,  -156,   -75,
     817,  1097,   603,   610,  1322, -1285, -1465,   384,
   -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
   -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

// ******************** NTT Implementation ************************* //

void ntt(Poly &p)
{
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = MLKEM_ZETAS[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce(static_cast<int32_t>(zeta) * p.coeffs[j + len]);
                p.coeffs[j + len] = p.coeffs[j] - t;
                p.coeffs[j] = p.coeffs[j] + t;
            }
        }
    }
}

void invntt(Poly &p)
{
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441;  // mont^2/128

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = MLKEM_ZETAS[k--];
            for (j = start; j < start + len; j++) {
                t = p.coeffs[j];
                p.coeffs[j] = barrett_reduce(t + p.coeffs[j + len]);
                // Match reference exactly: store difference first, then multiply
                p.coeffs[j + len] = static_cast<int16_t>(p.coeffs[j + len] - t);
                p.coeffs[j + len] = montgomery_reduce(
                    static_cast<int32_t>(zeta) * p.coeffs[j + len]);
            }
        }
    }

    for (j = 0; j < 256; j++)
        p.coeffs[j] = montgomery_reduce(static_cast<int32_t>(f) * p.coeffs[j]);
}

// ******************** Polynomial Base Multiplication ************************* //
// Multiplication of two polynomials in NTT domain
// Uses the fact that we're in a product of degree-2 extension fields

static int16_t fqmul(int16_t a, int16_t b)
{
    return montgomery_reduce(static_cast<int32_t>(a) * b);
}

static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

void poly_basemul(Poly &c, const Poly &a, const Poly &b)
{
    for (unsigned int i = 0; i < MLKEM_N / 4; i++) {
        basemul(&c.coeffs[4 * i], &a.coeffs[4 * i], &b.coeffs[4 * i],
                MLKEM_ZETAS[64 + i]);
        basemul(&c.coeffs[4 * i + 2], &a.coeffs[4 * i + 2], &b.coeffs[4 * i + 2],
                -MLKEM_ZETAS[64 + i]);
    }
}

// ******************** Polynomial Conversion ************************* //

void poly_tomont(Poly &p)
{
    // f = R^2 mod q = 2^32 mod 3329 = 1353
    // Note: (R mod q)^2 mod q = R^2 mod q = 1353
    const int16_t f = static_cast<int16_t>((1ULL << 32) % MLKEM_Q);
    for (unsigned int i = 0; i < MLKEM_N; i++)
        p.coeffs[i] = montgomery_reduce(static_cast<int32_t>(p.coeffs[i]) * f);
}

// ******************** Sampling ************************* //

// Rejection sampling from uniform distribution
// SHAKE-128 XOF: seed || x || y -> uniform polynomial
void poly_uniform(Poly &p, const byte *seed, byte x, byte y)
{
    // Generate enough bytes for rejection sampling
    // With q=3329 and 12-bit samples, rejection rate is ~19%
    // 256 coefficients need ~315 samples on average (256 / 0.813)
    // Each sample is 1.5 bytes (3 bytes gives 2 samples)
    // Need ~473 bytes on average; use 840 bytes (5 SHAKE blocks) for safety
    // Probability of needing more than 840 bytes is ~2^-128 (negligible)
    const unsigned int GEN_BYTES = 840;
    byte buf[GEN_BYTES];

    // XOF: SHAKE-128(seed || x || y)
    SHAKE128 shake(GEN_BYTES);
    shake.Update(seed, MLKEM_SYMBYTES);
    shake.Update(&x, 1);
    shake.Update(&y, 1);
    shake.TruncatedFinal(buf, GEN_BYTES);

    unsigned int ctr = 0;
    unsigned int pos = 0;

    while (ctr < MLKEM_N && pos + 3 <= GEN_BYTES) {
        // Parse 3 bytes into 2 12-bit values
        uint16_t val0 = (buf[pos] | (static_cast<uint16_t>(buf[pos + 1]) << 8)) & 0xFFF;
        uint16_t val1 = ((buf[pos + 1] >> 4) | (static_cast<uint16_t>(buf[pos + 2]) << 4)) & 0xFFF;
        pos += 3;

        if (val0 < MLKEM_Q)
            p.coeffs[ctr++] = static_cast<int16_t>(val0);
        if (val1 < MLKEM_Q && ctr < MLKEM_N)
            p.coeffs[ctr++] = static_cast<int16_t>(val1);
    }

    // Should never happen with 840 bytes (probability < 2^-128), but enforce
    if (ctr != MLKEM_N)
        throw Exception(Exception::OTHER_ERROR, "ML-KEM: poly_uniform rejection sampling exhausted buffer");
}

// CBD(eta) - Centered Binomial Distribution
// Sample from {-eta, ..., eta} with binomial distribution

static void cbd2(Poly &p, const byte *buf)
{
    for (unsigned int i = 0; i < MLKEM_N / 8; i++) {
        uint32_t t = buf[4 * i] | (static_cast<uint32_t>(buf[4 * i + 1]) << 8) |
                     (static_cast<uint32_t>(buf[4 * i + 2]) << 16) |
                     (static_cast<uint32_t>(buf[4 * i + 3]) << 24);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (unsigned int j = 0; j < 8; j++) {
            int16_t a = (d >> (4 * j)) & 0x3;
            int16_t b = (d >> (4 * j + 2)) & 0x3;
            p.coeffs[8 * i + j] = a - b;
        }
    }
}

static void cbd3(Poly &p, const byte *buf)
{
    for (unsigned int i = 0; i < MLKEM_N / 4; i++) {
        uint32_t t = buf[3 * i] | (static_cast<uint32_t>(buf[3 * i + 1]) << 8) |
                     (static_cast<uint32_t>(buf[3 * i + 2]) << 16);
        uint32_t d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (unsigned int j = 0; j < 4; j++) {
            int16_t a = (d >> (6 * j)) & 0x7;
            int16_t b = (d >> (6 * j + 3)) & 0x7;
            p.coeffs[4 * i + j] = a - b;
        }
    }
}

void poly_cbd_eta1(Poly &p, const byte *buf, unsigned int eta)
{
    if (eta == 2)
        cbd2(p, buf);
    else if (eta == 3)
        cbd3(p, buf);
}

void poly_cbd_eta2(Poly &p, const byte *buf, unsigned int eta)
{
    if (eta == 2)
        cbd2(p, buf);
    else if (eta == 3)
        cbd3(p, buf);
}

// ******************** Serialization ************************* //

void poly_tobytes(byte *buf, const Poly &p)
{
    for (unsigned int i = 0; i < MLKEM_N / 2; i++) {
        // Map negative to positive (matching reference: only add q if negative)
        // Reference does NOT reduce values >= q to [0, q) - allows [0, 4095]
        uint16_t t0 = static_cast<uint16_t>(p.coeffs[2 * i]);
        uint16_t t1 = static_cast<uint16_t>(p.coeffs[2 * i + 1]);
        t0 += (static_cast<int16_t>(t0) >> 15) & MLKEM_Q;
        t1 += (static_cast<int16_t>(t1) >> 15) & MLKEM_Q;

        buf[3 * i] = static_cast<byte>(t0);
        buf[3 * i + 1] = static_cast<byte>((t0 >> 8) | (t1 << 4));
        buf[3 * i + 2] = static_cast<byte>(t1 >> 4);
    }
}

void poly_frombytes(Poly &p, const byte *buf)
{
    for (unsigned int i = 0; i < MLKEM_N / 2; i++) {
        p.coeffs[2 * i] = (static_cast<uint16_t>(buf[3 * i]) |
                          (static_cast<uint16_t>(buf[3 * i + 1] & 0x0F) << 8));
        p.coeffs[2 * i + 1] = (static_cast<uint16_t>(buf[3 * i + 1] >> 4) |
                              (static_cast<uint16_t>(buf[3 * i + 2]) << 4));
    }
}

void poly_compress(byte *buf, const Poly &p, unsigned int d)
{
    if (d == 4) {
        for (unsigned int i = 0; i < MLKEM_N / 2; i++) {
            // Reduce to [0, q)
            int16_t u0 = p.coeffs[2 * i];
            int16_t u1 = p.coeffs[2 * i + 1];
            u0 += (u0 >> 15) & MLKEM_Q;  // Map negative to positive
            u1 += (u1 >> 15) & MLKEM_Q;
            buf[i] = static_cast<byte>(
                ((((static_cast<uint32_t>(u0) << 4) + MLKEM_Q / 2) / MLKEM_Q) & 0x0F) |
                ((((static_cast<uint32_t>(u1) << 4) + MLKEM_Q / 2) / MLKEM_Q) << 4));
        }
    } else if (d == 5) {
        for (unsigned int i = 0; i < MLKEM_N / 8; i++) {
            uint8_t c[8];
            for (unsigned int j = 0; j < 8; j++) {
                int16_t u = p.coeffs[8 * i + j];
                u += (u >> 15) & MLKEM_Q;  // Map negative to positive
                c[j] = static_cast<uint8_t>(
                    ((static_cast<uint32_t>(u) << 5) + MLKEM_Q / 2) / MLKEM_Q & 0x1F);
            }
            buf[5 * i] = c[0] | (c[1] << 5);
            buf[5 * i + 1] = (c[1] >> 3) | (c[2] << 2) | (c[3] << 7);
            buf[5 * i + 2] = (c[3] >> 1) | (c[4] << 4);
            buf[5 * i + 3] = (c[4] >> 4) | (c[5] << 1) | (c[6] << 6);
            buf[5 * i + 4] = (c[6] >> 2) | (c[7] << 3);
        }
    }
}

void poly_decompress(Poly &p, const byte *buf, unsigned int d)
{
    if (d == 4) {
        for (unsigned int i = 0; i < MLKEM_N / 2; i++) {
            p.coeffs[2 * i] = static_cast<int16_t>(
                (static_cast<uint32_t>(buf[i] & 0x0F) * MLKEM_Q + 8) >> 4);
            p.coeffs[2 * i + 1] = static_cast<int16_t>(
                (static_cast<uint32_t>(buf[i] >> 4) * MLKEM_Q + 8) >> 4);
        }
    } else if (d == 5) {
        for (unsigned int i = 0; i < MLKEM_N / 8; i++) {
            uint8_t c[8];
            c[0] = buf[5 * i] & 0x1F;
            c[1] = (buf[5 * i] >> 5) | ((buf[5 * i + 1] << 3) & 0x1F);
            c[2] = (buf[5 * i + 1] >> 2) & 0x1F;
            c[3] = (buf[5 * i + 1] >> 7) | ((buf[5 * i + 2] << 1) & 0x1F);
            c[4] = (buf[5 * i + 2] >> 4) | ((buf[5 * i + 3] << 4) & 0x1F);
            c[5] = (buf[5 * i + 3] >> 1) & 0x1F;
            c[6] = (buf[5 * i + 3] >> 6) | ((buf[5 * i + 4] << 2) & 0x1F);
            c[7] = buf[5 * i + 4] >> 3;
            for (unsigned int j = 0; j < 8; j++)
                p.coeffs[8 * i + j] = static_cast<int16_t>(
                    (static_cast<uint32_t>(c[j]) * MLKEM_Q + 16) >> 5);
        }
    }
}

void poly_frommsg(Poly &p, const byte *msg)
{
    for (unsigned int i = 0; i < MLKEM_N / 8; i++) {
        for (unsigned int j = 0; j < 8; j++) {
            int16_t mask = -static_cast<int16_t>((msg[i] >> j) & 1);
            p.coeffs[8 * i + j] = mask & ((MLKEM_Q + 1) / 2);
        }
    }
}

void poly_tomsg(byte *msg, const Poly &p)
{
    for (unsigned int i = 0; i < MLKEM_N / 8; i++) {
        msg[i] = 0;
        for (unsigned int j = 0; j < 8; j++) {
            // Reduce to [0, q)
            int16_t t = p.coeffs[8 * i + j];
            t += (t >> 15) & MLKEM_Q;  // Map negative to positive
            // Compress to 1 bit: round((2 * coeff) / q) mod 2
            msg[i] |= static_cast<byte>(
                ((((static_cast<uint32_t>(t) << 1) + MLKEM_Q / 2) / MLKEM_Q) & 1) << j);
        }
    }
}

// ******************** Polyvec Compression ************************* //

template <class PARAMS>
void polyvec_compress(byte *buf, const PolyVec<PARAMS::k> &pv)
{
    const unsigned int du = PARAMS::du;

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        if (du == 10) {
            for (unsigned int j = 0; j < MLKEM_N / 4; j++) {
                uint16_t c[4];
                for (unsigned int k = 0; k < 4; k++) {
                    // Reduce to [0, q)
                    int16_t u = pv.vec[i].coeffs[4 * j + k];
                    u += (u >> 15) & MLKEM_Q;
                    // Use fixed-point arithmetic matching reference: ((u << 10) + 1665) * 1290167 >> 32
                    uint64_t d0 = static_cast<uint64_t>(u) << 10;
                    d0 += 1665;
                    d0 *= 1290167;
                    d0 >>= 32;
                    c[k] = static_cast<uint16_t>(d0 & 0x3FF);
                }
                buf[5 * j] = static_cast<byte>(c[0]);
                buf[5 * j + 1] = static_cast<byte>((c[0] >> 8) | (c[1] << 2));
                buf[5 * j + 2] = static_cast<byte>((c[1] >> 6) | (c[2] << 4));
                buf[5 * j + 3] = static_cast<byte>((c[2] >> 4) | (c[3] << 6));
                buf[5 * j + 4] = static_cast<byte>(c[3] >> 2);
            }
            buf += 320;
        } else if (du == 11) {
            for (unsigned int j = 0; j < MLKEM_N / 8; j++) {
                uint16_t c[8];
                for (unsigned int k = 0; k < 8; k++) {
                    // Reduce to [0, q)
                    int16_t u = pv.vec[i].coeffs[8 * j + k];
                    u += (u >> 15) & MLKEM_Q;
                    // Use fixed-point arithmetic matching reference: ((u << 11) + 1664) * 645084 >> 31
                    uint64_t d0 = static_cast<uint64_t>(u) << 11;
                    d0 += 1664;
                    d0 *= 645084;
                    d0 >>= 31;
                    c[k] = static_cast<uint16_t>(d0 & 0x7FF);
                }
                buf[11 * j] = static_cast<byte>(c[0]);
                buf[11 * j + 1] = static_cast<byte>((c[0] >> 8) | (c[1] << 3));
                buf[11 * j + 2] = static_cast<byte>((c[1] >> 5) | (c[2] << 6));
                buf[11 * j + 3] = static_cast<byte>(c[2] >> 2);
                buf[11 * j + 4] = static_cast<byte>((c[2] >> 10) | (c[3] << 1));
                buf[11 * j + 5] = static_cast<byte>((c[3] >> 7) | (c[4] << 4));
                buf[11 * j + 6] = static_cast<byte>((c[4] >> 4) | (c[5] << 7));
                buf[11 * j + 7] = static_cast<byte>(c[5] >> 1);
                buf[11 * j + 8] = static_cast<byte>((c[5] >> 9) | (c[6] << 2));
                buf[11 * j + 9] = static_cast<byte>((c[6] >> 6) | (c[7] << 5));
                buf[11 * j + 10] = static_cast<byte>(c[7] >> 3);
            }
            buf += 352;
        }
    }
}

template <class PARAMS>
void polyvec_decompress(PolyVec<PARAMS::k> &pv, const byte *buf)
{
    const unsigned int du = PARAMS::du;

    for (unsigned int i = 0; i < PARAMS::k; i++) {
        if (du == 10) {
            for (unsigned int j = 0; j < MLKEM_N / 4; j++) {
                uint16_t c[4];
                c[0] = (buf[5 * j] | (static_cast<uint16_t>(buf[5 * j + 1]) << 8)) & 0x3FF;
                c[1] = ((buf[5 * j + 1] >> 2) | (static_cast<uint16_t>(buf[5 * j + 2]) << 6)) & 0x3FF;
                c[2] = ((buf[5 * j + 2] >> 4) | (static_cast<uint16_t>(buf[5 * j + 3]) << 4)) & 0x3FF;
                c[3] = ((buf[5 * j + 3] >> 6) | (static_cast<uint16_t>(buf[5 * j + 4]) << 2)) & 0x3FF;
                for (unsigned int k = 0; k < 4; k++)
                    pv.vec[i].coeffs[4 * j + k] = static_cast<int16_t>(
                        (static_cast<uint32_t>(c[k]) * MLKEM_Q + 512) >> 10);
            }
            buf += 320;
        } else if (du == 11) {
            for (unsigned int j = 0; j < MLKEM_N / 8; j++) {
                uint16_t c[8];
                c[0] = (buf[11 * j] | (static_cast<uint16_t>(buf[11 * j + 1]) << 8)) & 0x7FF;
                c[1] = ((buf[11 * j + 1] >> 3) | (static_cast<uint16_t>(buf[11 * j + 2]) << 5)) & 0x7FF;
                c[2] = ((buf[11 * j + 2] >> 6) | (static_cast<uint16_t>(buf[11 * j + 3]) << 2) |
                        (static_cast<uint16_t>(buf[11 * j + 4]) << 10)) & 0x7FF;
                c[3] = ((buf[11 * j + 4] >> 1) | (static_cast<uint16_t>(buf[11 * j + 5]) << 7)) & 0x7FF;
                c[4] = ((buf[11 * j + 5] >> 4) | (static_cast<uint16_t>(buf[11 * j + 6]) << 4)) & 0x7FF;
                c[5] = ((buf[11 * j + 6] >> 7) | (static_cast<uint16_t>(buf[11 * j + 7]) << 1) |
                        (static_cast<uint16_t>(buf[11 * j + 8]) << 9)) & 0x7FF;
                c[6] = ((buf[11 * j + 8] >> 2) | (static_cast<uint16_t>(buf[11 * j + 9]) << 6)) & 0x7FF;
                c[7] = ((buf[11 * j + 9] >> 5) | (static_cast<uint16_t>(buf[11 * j + 10]) << 3)) & 0x7FF;
                for (unsigned int k = 0; k < 8; k++)
                    pv.vec[i].coeffs[8 * j + k] = static_cast<int16_t>(
                        (static_cast<uint32_t>(c[k]) * MLKEM_Q + 1024) >> 11);
            }
            buf += 352;
        }
    }
}

// Explicit instantiations
template void polyvec_compress<Params_512>(byte*, const PolyVec<2>&);
template void polyvec_compress<Params_768>(byte*, const PolyVec<3>&);
template void polyvec_compress<Params_1024>(byte*, const PolyVec<4>&);
template void polyvec_decompress<Params_512>(PolyVec<2>&, const byte*);
template void polyvec_decompress<Params_768>(PolyVec<3>&, const byte*);
template void polyvec_decompress<Params_1024>(PolyVec<4>&, const byte*);

// ******************** Matrix Generation ************************* //

template <unsigned int K>
void gen_matrix(PolyVec<K> A[K], const byte *seed, bool transpose)
{
    for (unsigned int i = 0; i < K; i++) {
        for (unsigned int j = 0; j < K; j++) {
            // Reference uses (j, i) for A and (i, j) for A^T
            if (transpose)
                poly_uniform(A[i].vec[j], seed, static_cast<byte>(i), static_cast<byte>(j));
            else
                poly_uniform(A[i].vec[j], seed, static_cast<byte>(j), static_cast<byte>(i));
        }
    }
}

// Explicit instantiations
template void gen_matrix<2>(PolyVec<2>[2], const byte*, bool);
template void gen_matrix<3>(PolyVec<3>[3], const byte*, bool);
template void gen_matrix<4>(PolyVec<4>[4], const byte*, bool);

// ******************** IND-CPA Encryption ************************* //

template <class PARAMS>
void indcpa_keypair(byte *pk, byte *sk, RandomNumberGenerator &rng)
{
    const unsigned int k = PARAMS::k;
    byte buf[2 * MLKEM_SYMBYTES];
    byte *publicseed = buf;
    byte *noiseseed = buf + MLKEM_SYMBYTES;

    // Generate random seed d and derive (rho, sigma) = G(d || k)
    // FIPS 203 Algorithm 16: uses k as domain separator
    rng.GenerateBlock(buf, MLKEM_SYMBYTES);
    SHA3_512 sha3;
    sha3.Update(buf, MLKEM_SYMBYTES);
    byte domain_sep = static_cast<byte>(k);
    sha3.Update(&domain_sep, 1);
    sha3.TruncatedFinal(buf, 2 * MLKEM_SYMBYTES);

    // Generate matrix A
    PolyVec<k> A[k];
    gen_matrix<k>(A, publicseed, false);

    // Generate secret vector s
    PolyVec<k> s;
    byte prf_input[MLKEM_SYMBYTES + 1];
    std::memcpy(prf_input, noiseseed, MLKEM_SYMBYTES);
    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(i);
        byte cbd_buf[PARAMS::eta1 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta1(s.vec[i], cbd_buf, PARAMS::eta1);
    }

    // Generate error vector e
    PolyVec<k> e;
    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(k + i);
        byte cbd_buf[PARAMS::eta1 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta1(e.vec[i], cbd_buf, PARAMS::eta1);
    }

    // NTT(s) and NTT(e)
    polyvec_ntt<k>(s);
    polyvec_reduce<k>(s);  // Reduce before serialization
    polyvec_ntt<k>(e);

    // Compute t = A * s + e
    PolyVec<k> t;
    for (unsigned int i = 0; i < k; i++) {
        polyvec_pointwise_acc<k>(t.vec[i], A[i], s);
        poly_tomont(t.vec[i]);
        poly_add(t.vec[i], t.vec[i], e.vec[i]);
        poly_reduce(t.vec[i]);
    }

    // Pack public key: t || rho
    polyvec_tobytes<k>(pk, t);
    std::memcpy(pk + k * 384, publicseed, MLKEM_SYMBYTES);

    // Pack secret key
    polyvec_tobytes<k>(sk, s);

    // Zeroize secret data on stack
    SecureWipeBuffer(buf, sizeof(buf));
    SecureWipeBuffer(prf_input, sizeof(prf_input));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s), sizeof(s));
    SecureWipeBuffer(reinterpret_cast<byte*>(&e), sizeof(e));
}

// Deterministic version for X-Wing seed expansion
template <class PARAMS>
void indcpa_keypair_deterministic(byte *pk, byte *sk, const byte *d)
{
    const unsigned int k = PARAMS::k;
    byte buf[2 * MLKEM_SYMBYTES];
    byte *publicseed = buf;
    byte *noiseseed = buf + MLKEM_SYMBYTES;

    // Derive (rho, sigma) = G(d || k) using provided d
    // FIPS 203 Algorithm 16: uses k as domain separator
    SHA3_512 sha3;
    sha3.Update(d, MLKEM_SYMBYTES);
    byte domain_sep = static_cast<byte>(k);
    sha3.Update(&domain_sep, 1);
    sha3.TruncatedFinal(buf, 2 * MLKEM_SYMBYTES);

    // Generate matrix A
    PolyVec<k> A[k];
    gen_matrix<k>(A, publicseed, false);

    // Generate secret vector s
    PolyVec<k> s;
    byte prf_input[MLKEM_SYMBYTES + 1];
    std::memcpy(prf_input, noiseseed, MLKEM_SYMBYTES);
    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(i);
        byte cbd_buf[PARAMS::eta1 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta1(s.vec[i], cbd_buf, PARAMS::eta1);
    }

    // Generate error vector e
    PolyVec<k> e;
    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(k + i);
        byte cbd_buf[PARAMS::eta1 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta1(e.vec[i], cbd_buf, PARAMS::eta1);
    }

    // NTT(s) and NTT(e)
    polyvec_ntt<k>(s);
    polyvec_reduce<k>(s);  // Reduce before serialization
    polyvec_ntt<k>(e);

    // Compute t = A * s + e
    PolyVec<k> t;
    for (unsigned int i = 0; i < k; i++) {
        polyvec_pointwise_acc<k>(t.vec[i], A[i], s);
        poly_tomont(t.vec[i]);
        poly_add(t.vec[i], t.vec[i], e.vec[i]);
        poly_reduce(t.vec[i]);
    }

    // Pack public key: t || rho
    polyvec_tobytes<k>(pk, t);
    std::memcpy(pk + k * 384, publicseed, MLKEM_SYMBYTES);

    // Pack secret key
    polyvec_tobytes<k>(sk, s);

    // Zeroize secret data on stack
    SecureWipeBuffer(buf, sizeof(buf));
    SecureWipeBuffer(prf_input, sizeof(prf_input));
    SecureWipeBuffer(reinterpret_cast<byte*>(&s), sizeof(s));
    SecureWipeBuffer(reinterpret_cast<byte*>(&e), sizeof(e));
}

template <class PARAMS>
void indcpa_enc(byte *ct, const byte *m, const byte *pk, const byte *coins)
{
    const unsigned int k = PARAMS::k;
    byte publicseed[MLKEM_SYMBYTES];
    std::memcpy(publicseed, pk + k * 384, MLKEM_SYMBYTES);

    // Unpack public key
    PolyVec<k> t;
    polyvec_frombytes<k>(t, pk);

    // Generate matrix A^T
    PolyVec<k> AT[k];
    gen_matrix<k>(AT, publicseed, true);

    // Generate r, e1, e2 from coins
    PolyVec<k> r, e1;
    Poly e2;
    byte prf_input[MLKEM_SYMBYTES + 1];
    std::memcpy(prf_input, coins, MLKEM_SYMBYTES);

    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(i);
        byte cbd_buf[PARAMS::eta1 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta1(r.vec[i], cbd_buf, PARAMS::eta1);
    }

    for (unsigned int i = 0; i < k; i++) {
        prf_input[MLKEM_SYMBYTES] = static_cast<byte>(k + i);
        byte cbd_buf[PARAMS::eta2 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta2(e1.vec[i], cbd_buf, PARAMS::eta2);
    }

    prf_input[MLKEM_SYMBYTES] = static_cast<byte>(2 * k);
    {
        byte cbd_buf[PARAMS::eta2 * MLKEM_N / 4];
        SHAKE256 prf(sizeof(cbd_buf));
        prf.Update(prf_input, sizeof(prf_input));
        prf.TruncatedFinal(cbd_buf, sizeof(cbd_buf));
        poly_cbd_eta2(e2, cbd_buf, PARAMS::eta2);
    }

    // NTT(r)
    polyvec_ntt<k>(r);

    // Compute u = A^T * r + e1
    PolyVec<k> u;
    for (unsigned int i = 0; i < k; i++) {
        polyvec_pointwise_acc<k>(u.vec[i], AT[i], r);
        invntt(u.vec[i]);
        poly_add(u.vec[i], u.vec[i], e1.vec[i]);
        poly_reduce(u.vec[i]);
    }

    // Compute v = t^T * r + e2 + Decompress(m)
    Poly v;
    polyvec_pointwise_acc<k>(v, t, r);
    invntt(v);
    Poly mp;
    poly_frommsg(mp, m);
    poly_add(v, v, e2);
    poly_add(v, v, mp);
    poly_reduce(v);

    // Compress and pack ciphertext
    polyvec_compress<PARAMS>(ct, u);
    poly_compress(ct + PARAMS::POLYVECCOMPRESSEDBYTES, v, PARAMS::dv);

    // Zeroize secret randomness on stack
    SecureWipeBuffer(prf_input, sizeof(prf_input));
    SecureWipeBuffer(reinterpret_cast<byte*>(&r), sizeof(r));
    SecureWipeBuffer(reinterpret_cast<byte*>(&e1), sizeof(e1));
    SecureWipeBuffer(reinterpret_cast<byte*>(&e2), sizeof(e2));
}

template <class PARAMS>
void indcpa_dec(byte *m, const byte *ct, const byte *sk)
{
    const unsigned int k = PARAMS::k;

    // Unpack ciphertext
    PolyVec<k> u;
    Poly v;
    polyvec_decompress<PARAMS>(u, ct);
    poly_decompress(v, ct + PARAMS::POLYVECCOMPRESSEDBYTES, PARAMS::dv);

    // Unpack secret key
    PolyVec<k> s;
    polyvec_frombytes<k>(s, sk);

    // NTT(u)
    polyvec_ntt<k>(u);

    // Compute m = v - s^T * u
    Poly mp;
    polyvec_pointwise_acc<k>(mp, s, u);
    invntt(mp);
    poly_sub(mp, v, mp);
    poly_reduce(mp);

    poly_tomsg(m, mp);

    // Zeroize secret key and message polynomial on stack
    SecureWipeBuffer(reinterpret_cast<byte*>(&s), sizeof(s));
    SecureWipeBuffer(reinterpret_cast<byte*>(&mp), sizeof(mp));
}

// ******************** Parameter Traits ************************* //

template <class PARAMS> struct ParamTraits;

template <> struct ParamTraits<MLKEM_512> {
    typedef Params_512 Internal;
};
template <> struct ParamTraits<MLKEM_768> {
    typedef Params_768 Internal;
};
template <> struct ParamTraits<MLKEM_1024> {
    typedef Params_1024 Internal;
};

// ******************** Full ML-KEM ************************* //

template <class PARAMS>
void mlkem_keypair(byte *pk, byte *sk, RandomNumberGenerator &rng)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;

    // Generate IND-CPA key pair
    indcpa_keypair<InternalParams>(pk, sk, rng);

    // Append public key to secret key
    std::memcpy(sk + InternalParams::INDCPA_SECRETKEYBYTES, pk, InternalParams::PUBLICKEYBYTES);

    // Append H(pk) to secret key
    SHA3_256 sha3;
    sha3.Update(pk, InternalParams::PUBLICKEYBYTES);
    sha3.TruncatedFinal(sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES,
                        MLKEM_SYMBYTES);

    // Append z (random bytes for implicit rejection)
    rng.GenerateBlock(sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES + MLKEM_SYMBYTES,
                      MLKEM_SYMBYTES);
}

// Deterministic version for X-Wing seed expansion
// Takes d (32 bytes) and z (32 bytes) directly instead of generating from RNG
template <class PARAMS>
void mlkem_keypair_deterministic(byte *pk, byte *sk, const byte *d, const byte *z)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;

    // Generate IND-CPA key pair deterministically using d
    indcpa_keypair_deterministic<InternalParams>(pk, sk, d);

    // Append public key to secret key
    std::memcpy(sk + InternalParams::INDCPA_SECRETKEYBYTES, pk, InternalParams::PUBLICKEYBYTES);

    // Append H(pk) to secret key
    SHA3_256 sha3;
    sha3.Update(pk, InternalParams::PUBLICKEYBYTES);
    sha3.TruncatedFinal(sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES,
                        MLKEM_SYMBYTES);

    // Append provided z (implicit rejection seed)
    std::memcpy(sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES + MLKEM_SYMBYTES,
                z, MLKEM_SYMBYTES);
}

template <class PARAMS>
void mlkem_encaps(byte *ct, byte *ss, const byte *pk, RandomNumberGenerator &rng)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    byte buf[2 * MLKEM_SYMBYTES];
    byte kr[2 * MLKEM_SYMBYTES];

    // Generate random message m
    // FIPS 203 Algorithm 20: m is used directly (no H(m) step in final spec)
    rng.GenerateBlock(buf, MLKEM_SYMBYTES);

    // Compute H(ek) - store in second half of buf
    SHA3_256 sha3_256;
    sha3_256.Update(pk, InternalParams::PUBLICKEYBYTES);
    sha3_256.TruncatedFinal(buf + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

    // (K_bar, r) = G(m || H(ek)) - FIPS 203 uses m directly
    SHA3_512 sha3_512;
    sha3_512.Update(buf, 2 * MLKEM_SYMBYTES);
    sha3_512.TruncatedFinal(kr, 2 * MLKEM_SYMBYTES);

    // c = K-PKE.Encrypt(ek, m, r) - encrypt m directly
    indcpa_enc<InternalParams>(ct, buf, pk, kr + MLKEM_SYMBYTES);

    // FIPS 203: K is the first 32 bytes of G(m || H(ek)) directly
    std::memcpy(ss, kr, MLKEM_SYMBYTES);

    // Zeroize secret data on stack
    SecureWipeBuffer(buf, sizeof(buf));
    SecureWipeBuffer(kr, sizeof(kr));
}

template <class PARAMS>
void mlkem_decaps(byte *ss, const byte *ct, const byte *sk)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    byte buf[2 * MLKEM_SYMBYTES];
    byte kr[2 * MLKEM_SYMBYTES];
    byte cmp[InternalParams::CIPHERTEXTBYTES];

    // Unpack public key and z from secret key
    const byte *pk = sk + InternalParams::INDCPA_SECRETKEYBYTES;
    const byte *h_pk = sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES;
    const byte *z = sk + InternalParams::INDCPA_SECRETKEYBYTES + InternalParams::PUBLICKEYBYTES + MLKEM_SYMBYTES;

    // Decrypt to get m'
    indcpa_dec<InternalParams>(buf, ct, sk);

    // Copy H(pk)
    std::memcpy(buf + MLKEM_SYMBYTES, h_pk, MLKEM_SYMBYTES);

    // (K', r') = G(m' || H(pk))
    SHA3_512 sha3_512;
    sha3_512.Update(buf, 2 * MLKEM_SYMBYTES);
    sha3_512.TruncatedFinal(kr, 2 * MLKEM_SYMBYTES);

    // Re-encrypt
    indcpa_enc<InternalParams>(cmp, buf, pk, kr + MLKEM_SYMBYTES);

    // Compare ciphertexts (constant time, branchless)
    unsigned int fail = 0;
    for (unsigned int i = 0; i < InternalParams::CIPHERTEXTBYTES; i++)
        fail |= ct[i] ^ cmp[i];
    // Branchless normalization: 0 stays 0, non-zero becomes 1
    fail = (fail | (-fail)) >> 31;

    // FIPS 203: Implicit rejection K_bar = J(z || c) = SHAKE-256(z || c)
    byte k_bar[MLKEM_SYMBYTES];
    SHAKE256 j_hash(MLKEM_SYMBYTES);
    j_hash.Update(z, MLKEM_SYMBYTES);
    j_hash.Update(ct, InternalParams::CIPHERTEXTBYTES);
    j_hash.TruncatedFinal(k_bar, MLKEM_SYMBYTES);

    // FIPS 203: Select K' (success) or K_bar (failure) in constant time
    for (unsigned int i = 0; i < MLKEM_SYMBYTES; i++)
        ss[i] = kr[i] ^ ((-fail) & (kr[i] ^ k_bar[i]));

    // Zeroize secret data on stack
    SecureWipeBuffer(buf, sizeof(buf));
    SecureWipeBuffer(kr, sizeof(kr));
    SecureWipeBuffer(cmp, sizeof(cmp));
    SecureWipeBuffer(k_bar, sizeof(k_bar));
}

}  // namespace MLKEM_Internal

// ******************** Public API Implementation ************************* //

using namespace MLKEM_Internal;

// ******************** MLKEMPrivateKey ************************* //

template <class PARAMS>
bool MLKEMPrivateKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    // Basic validation: key data exists and has correct size
    return m_sk.size() == SECRET_KEYLENGTH;
}

template <class PARAMS>
bool MLKEMPrivateKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void MLKEMPrivateKey<PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void MLKEMPrivateKey<PARAMS>::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    byte pk[PUBLIC_KEYLENGTH];
    mlkem_keypair<PARAMS>(pk, m_sk.begin(), rng);
}

template <class PARAMS>
void MLKEMPrivateKey<PARAMS>::SetPrivateKey(const byte *key, size_t len)
{
    if (len != SECRET_KEYLENGTH)
        throw InvalidKeyLength(PARAMS::StaticAlgorithmName(), len);
    std::memcpy(m_sk.begin(), key, SECRET_KEYLENGTH);
}

template <class PARAMS>
const byte* MLKEMPrivateKey<PARAMS>::GetPublicKeyBytePtr() const
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    return m_sk.begin() + InternalParams::INDCPA_SECRETKEYBYTES;
}

template <class PARAMS>
void MLKEMPrivateKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // PKCS#8 OneAsymmetricKey format (RFC 5958)
    // OneAsymmetricKey ::= SEQUENCE {
    //   version                   Version,
    //   privateKeyAlgorithm       AlgorithmIdentifier,
    //   privateKey                OCTET STRING,
    //   attributes            [0] IMPLICIT Attributes OPTIONAL,
    //   publicKey             [1] IMPLICIT PublicKey OPTIONAL }
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
void MLKEMPrivateKey<PARAMS>::BERDecode(BufferedTransformation &bt)
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
                privateKey.Get(m_sk.begin(), SECRET_KEYLENGTH);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

// Explicit instantiations
template struct MLKEMPrivateKey<MLKEM_512>;
template struct MLKEMPrivateKey<MLKEM_768>;
template struct MLKEMPrivateKey<MLKEM_1024>;

// ******************** MLKEMPublicKey ************************* //

template <class PARAMS>
bool MLKEMPublicKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);

    if (m_pk.size() != PUBLIC_KEYLENGTH)
        return false;

    // FIPS 203 Section 7.2: Encapsulation key type check
    // Verify all 12-bit encoded polynomial coefficients are < q (3329)
    if (level >= 1)
    {
        // Public key = polyvec_bytes || rho(32), each 3 bytes encode 2 coefficients
        const size_t polyBytes = PUBLIC_KEYLENGTH - MLKEM_Internal::MLKEM_SYMBYTES;
        const byte *pk = m_pk.begin();
        for (size_t i = 0; i + 2 < polyBytes; i += 3)
        {
            uint16_t c0 = (uint16_t(pk[i]) | (uint16_t(pk[i+1]) << 8)) & 0xFFF;
            uint16_t c1 = (uint16_t(pk[i+1]) >> 4) | (uint16_t(pk[i+2]) << 4);
            if (c0 >= MLKEM_Internal::MLKEM_Q || c1 >= MLKEM_Internal::MLKEM_Q)
                return false;
        }
    }

    return true;
}

template <class PARAMS>
bool MLKEMPublicKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void MLKEMPublicKey<PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void MLKEMPublicKey<PARAMS>::SetPublicKey(const byte *key, size_t len)
{
    if (len != PUBLIC_KEYLENGTH)
        throw InvalidKeyLength(PARAMS::StaticAlgorithmName(), len);
    std::memcpy(m_pk.begin(), key, PUBLIC_KEYLENGTH);
}

template <class PARAMS>
void MLKEMPublicKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // X.509 SubjectPublicKeyInfo format (RFC 5280)
    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //   algorithm            AlgorithmIdentifier,
    //   subjectPublicKey     BIT STRING  }
    DERSequenceEncoder publicKeyInfo(bt);
        DERSequenceEncoder algorithm(publicKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DEREncodeBitString(publicKeyInfo, m_pk.begin(), PUBLIC_KEYLENGTH);
    publicKeyInfo.MessageEnd();
}

template <class PARAMS>
void MLKEMPublicKey<PARAMS>::BERDecode(BufferedTransformation &bt)
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
        std::memcpy(m_pk.begin(), subjectPublicKey.begin(), PUBLIC_KEYLENGTH);

    publicKeyInfo.MessageEnd();
}

// Explicit instantiations
template struct MLKEMPublicKey<MLKEM_512>;
template struct MLKEMPublicKey<MLKEM_768>;
template struct MLKEMPublicKey<MLKEM_1024>;

// ******************** MLKEMEncapsulator ************************* //

template <class PARAMS>
MLKEMEncapsulator<PARAMS>::MLKEMEncapsulator(const byte *publicKey, size_t publicKeyLen)
{
    m_key.SetPublicKey(publicKey, publicKeyLen);
}

template <class PARAMS>
void MLKEMEncapsulator<PARAMS>::Encapsulate(RandomNumberGenerator &rng, byte *ciphertext, byte *sharedSecret) const
{
    // FIPS 203 Section 7.2: Encapsulation key modulus check is mandatory
    if (!m_key.Validate(rng, 1))
        throw InvalidArgument(PARAMS::StaticAlgorithmName() + ": encapsulation key fails type check");

    mlkem_encaps<PARAMS>(ciphertext, sharedSecret, m_key.GetPublicKeyBytePtr(), rng);
}

// Explicit instantiations
template struct MLKEMEncapsulator<MLKEM_512>;
template struct MLKEMEncapsulator<MLKEM_768>;
template struct MLKEMEncapsulator<MLKEM_1024>;

// ******************** MLKEMDecapsulator ************************* //

template <class PARAMS>
MLKEMDecapsulator<PARAMS>::MLKEMDecapsulator(RandomNumberGenerator &rng)
{
    m_key.GenerateRandom(rng, g_nullNameValuePairs);
}

template <class PARAMS>
MLKEMDecapsulator<PARAMS>::MLKEMDecapsulator(const byte *privateKey, size_t privateKeyLen)
{
    m_key.SetPrivateKey(privateKey, privateKeyLen);
}

template <class PARAMS>
bool MLKEMDecapsulator<PARAMS>::Decapsulate(const byte *ciphertext, byte *sharedSecret) const
{
    CRYPTOPP_ASSERT(ciphertext != NULLPTR);
    CRYPTOPP_ASSERT(sharedSecret != NULLPTR);

    mlkem_decaps<PARAMS>(sharedSecret, ciphertext, m_key.GetPrivateKeyBytePtr());
    return true;  // ML-KEM uses implicit rejection, always "succeeds"
}

// Explicit instantiations
template struct MLKEMDecapsulator<MLKEM_512>;
template struct MLKEMDecapsulator<MLKEM_768>;
template struct MLKEMDecapsulator<MLKEM_1024>;

// Explicit instantiation for deterministic keygen (used by X-Wing)
template void MLKEM_Internal::mlkem_keypair_deterministic<MLKEM_768>(byte*, byte*, const byte*, const byte*);

NAMESPACE_END
