// mlkem_poly.h - written and placed in the public domain by Colin Brown
//                ML-KEM polynomial operations
//                Based on CRYSTALS-Kyber reference implementation (public domain)

#ifndef CRYPTOPP_MLKEM_POLY_H
#define CRYPTOPP_MLKEM_POLY_H

#include "mlkem_params.h"
#include <cryptopp/secblock.h>
#include <cstring>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(MLKEM_Internal)

// ******************** Polynomial Type ************************* //

/// Polynomial in R_q = Z_q[X]/(X^256 + 1)
/// Coefficients are 16-bit signed integers
struct Poly
{
    int16_t coeffs[MLKEM_N];

    Poly() { std::memset(coeffs, 0, sizeof(coeffs)); }
};

// ******************** Montgomery Reduction ************************* //

/// Montgomery reduction
/// Given a 32-bit integer a, returns a * R^(-1) mod q
/// where R = 2^16
inline int16_t montgomery_reduce(int32_t a)
{
    // Match reference: t = (int16_t)a * QINV
    // (int16_t)a takes low 16 bits, multiply by QINV (int), truncate to int16
    int16_t t = static_cast<int16_t>(static_cast<int16_t>(a) * MLKEM_QINV);
    t = static_cast<int16_t>((a - static_cast<int32_t>(t) * MLKEM_Q) >> 16);
    return t;
}

/// Barrett reduction
/// Given a 16-bit integer a, returns a mod q in [0, q)
inline int16_t barrett_reduce(int16_t a)
{
    // v = round(2^26 / q) = 20159
    const int32_t v = 20159;
    int16_t t;
    t = static_cast<int16_t>((static_cast<int32_t>(v) * a + (1 << 25)) >> 26);
    t *= MLKEM_Q;
    return a - t;
}

/// Conditional subtraction of q
inline int16_t csubq(int16_t a)
{
    a -= MLKEM_Q;
    a += (a >> 15) & MLKEM_Q;
    return a;
}

// ******************** NTT Operations ************************* //

/// Forward NTT (Number Theoretic Transform)
/// Input: polynomial in standard domain
/// Output: polynomial in NTT domain
void ntt(Poly &p);

/// Inverse NTT
/// Input: polynomial in NTT domain
/// Output: polynomial in standard domain
void invntt(Poly &p);

/// Pointwise multiplication in NTT domain
/// c = a * b (coefficient-wise in NTT domain)
void poly_basemul(Poly &c, const Poly &a, const Poly &b);

// ******************** Polynomial Arithmetic ************************* //

/// Add two polynomials: c = a + b
inline void poly_add(Poly &c, const Poly &a, const Poly &b)
{
    for (unsigned int i = 0; i < MLKEM_N; i++)
        c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
}

/// Subtract two polynomials: c = a - b
inline void poly_sub(Poly &c, const Poly &a, const Poly &b)
{
    for (unsigned int i = 0; i < MLKEM_N; i++)
        c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
}

/// Reduce all coefficients mod q
inline void poly_reduce(Poly &p)
{
    for (unsigned int i = 0; i < MLKEM_N; i++)
        p.coeffs[i] = barrett_reduce(p.coeffs[i]);
}

/// Convert polynomial to Montgomery form
void poly_tomont(Poly &p);

// ******************** Sampling ************************* //

/// Sample polynomial from seed using SHAKE-128 (matrix A generation)
/// Uses rejection sampling to get uniform distribution in [0, q)
void poly_uniform(Poly &p, const byte *seed, byte x, byte y);

/// Sample polynomial from centered binomial distribution CBD(eta)
/// For eta=2: coefficients in {-2,-1,0,1,2}
/// For eta=3: coefficients in {-3,-2,-1,0,1,2,3}
void poly_cbd_eta1(Poly &p, const byte *buf, unsigned int eta);
void poly_cbd_eta2(Poly &p, const byte *buf, unsigned int eta);

/// Sample noise polynomial using PRF
template <class PARAMS>
void poly_getnoise_eta1(Poly &p, const byte *seed, byte nonce);

template <class PARAMS>
void poly_getnoise_eta2(Poly &p, const byte *seed, byte nonce);

// ******************** Serialization ************************* //

/// Serialize polynomial to bytes (12 bits per coefficient)
void poly_tobytes(byte *buf, const Poly &p);

/// Deserialize polynomial from bytes
void poly_frombytes(Poly &p, const byte *buf);

/// Compress polynomial with d bits per coefficient
void poly_compress(byte *buf, const Poly &p, unsigned int d);

/// Decompress polynomial from d bits per coefficient
void poly_decompress(Poly &p, const byte *buf, unsigned int d);

/// Encode/decode message as polynomial
void poly_frommsg(Poly &p, const byte *msg);
void poly_tomsg(byte *msg, const Poly &p);

// ******************** Polynomial Vector Operations ************************* //

/// Polynomial vector (array of k polynomials)
template <unsigned int K>
struct PolyVec
{
    Poly vec[K];
};

/// NTT on polynomial vector
template <unsigned int K>
inline void polyvec_ntt(PolyVec<K> &pv)
{
    for (unsigned int i = 0; i < K; i++)
        ntt(pv.vec[i]);
}

/// Inverse NTT on polynomial vector
template <unsigned int K>
inline void polyvec_invntt(PolyVec<K> &pv)
{
    for (unsigned int i = 0; i < K; i++)
        invntt(pv.vec[i]);
}

/// Inner product of two polynomial vectors in NTT domain
template <unsigned int K>
inline void polyvec_pointwise_acc(Poly &c, const PolyVec<K> &a, const PolyVec<K> &b)
{
    Poly t;
    poly_basemul(c, a.vec[0], b.vec[0]);
    for (unsigned int i = 1; i < K; i++) {
        poly_basemul(t, a.vec[i], b.vec[i]);
        poly_add(c, c, t);
    }
    poly_reduce(c);
}

/// Add two polynomial vectors
template <unsigned int K>
inline void polyvec_add(PolyVec<K> &c, const PolyVec<K> &a, const PolyVec<K> &b)
{
    for (unsigned int i = 0; i < K; i++)
        poly_add(c.vec[i], a.vec[i], b.vec[i]);
}

/// Reduce all coefficients in polynomial vector
template <unsigned int K>
inline void polyvec_reduce(PolyVec<K> &pv)
{
    for (unsigned int i = 0; i < K; i++)
        poly_reduce(pv.vec[i]);
}

/// Serialize polynomial vector
template <unsigned int K>
inline void polyvec_tobytes(byte *buf, const PolyVec<K> &pv)
{
    for (unsigned int i = 0; i < K; i++)
        poly_tobytes(buf + i * 384, pv.vec[i]);
}

/// Deserialize polynomial vector
template <unsigned int K>
inline void polyvec_frombytes(PolyVec<K> &pv, const byte *buf)
{
    for (unsigned int i = 0; i < K; i++)
        poly_frombytes(pv.vec[i], buf + i * 384);
}

/// Compress polynomial vector
template <class PARAMS>
void polyvec_compress(byte *buf, const PolyVec<PARAMS::k> &pv);

/// Decompress polynomial vector
template <class PARAMS>
void polyvec_decompress(PolyVec<PARAMS::k> &pv, const byte *buf);

// ******************** Matrix Generation ************************* //

/// Generate matrix A from seed (each element is a polynomial)
/// transpose = false: A
/// transpose = true: A^T
template <unsigned int K>
void gen_matrix(PolyVec<K> A[K], const byte *seed, bool transpose);

NAMESPACE_END  // MLKEM_Internal
NAMESPACE_END  // CryptoPP

#endif // CRYPTOPP_MLKEM_POLY_H
