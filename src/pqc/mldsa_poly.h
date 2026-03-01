// mldsa_poly.h - written and placed in the public domain by Colin Brown
//                ML-DSA polynomial operations
//                Based on CRYSTALS-Dilithium reference implementation (public domain)

#ifndef CRYPTOPP_MLDSA_POLY_H
#define CRYPTOPP_MLDSA_POLY_H

#include "mldsa_params.h"
#include <cryptopp/secblock.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(MLDSA_Internal)

// ==================== Polynomial Type ====================

/// \brief Polynomial with coefficients in Z_q
struct poly {
    int32_t coeffs[MLDSA_N];
};

// ==================== Basic Operations ====================

/// \brief Set all coefficients to zero
void poly_zero(poly *a);

/// \brief Add two polynomials: c = a + b
void poly_add(poly *c, const poly *a, const poly *b);

/// \brief Subtract polynomials: c = a - b
void poly_sub(poly *c, const poly *a, const poly *b);

/// \brief Negate polynomial: b = -a
void poly_neg(poly *b, const poly *a);

/// \brief Shift coefficients left: a = a << d
void poly_shiftl(poly *a);

// ==================== NTT Operations ====================

/// \brief Forward NTT
void poly_ntt(poly *a);

/// \brief Inverse NTT
void poly_invntt(poly *a);

/// \brief Pointwise multiplication in NTT domain: c = a * b
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

// ==================== Reduction ====================

/// \brief Reduce all coefficients mod q
void poly_reduce(poly *a);

/// \brief Add q to negative coefficients
void poly_caddq(poly *a);

/// \brief Freeze coefficients to [0, q)
void poly_freeze(poly *a);

// ==================== Rounding ====================

/// \brief Power2Round: decompose a into a0 + a1*2^d
/// \details For d=13: a1 = (a + 2^12) >> 13, a0 = a - a1*2^13
void poly_power2round(poly *a1, poly *a0, const poly *a);

/// \brief Decompose a into high and low parts for signature
/// \details a = a1*alpha + a0 where alpha = 2*gamma2
template <class PARAMS>
void poly_decompose(poly *a1, poly *a0, const poly *a);

/// \brief Make hint for decomposition
/// \details Returns number of hints and sets h
template <class PARAMS>
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);

/// \brief Use hint to recover high bits
template <class PARAMS>
void poly_use_hint(poly *b, const poly *a, const poly *h);

// ==================== Norm Checks ====================

/// \brief Check infinity norm
/// \return 1 if any coefficient exceeds bound, 0 otherwise
int poly_chknorm(const poly *a, int32_t bound);

// ==================== Sampling ====================

/// \brief Sample uniform polynomial from seed using SHAKE128
void poly_uniform(poly *a, const byte *seed, uint16_t nonce);

/// \brief Sample polynomial with coefficients in [-eta, eta] from SHAKE256
template <class PARAMS>
void poly_uniform_eta(poly *a, const byte *seed, uint16_t nonce);

/// \brief Sample polynomial with coefficients in [-gamma1+1, gamma1] from SHAKE256
template <class PARAMS>
void poly_uniform_gamma1(poly *a, const byte *seed, uint16_t nonce);

/// \brief Sample challenge polynomial with tau +/-1's from seed
template <class PARAMS>
void poly_challenge(poly *c, const byte *seed);

// ==================== Packing ====================

/// \brief Pack polynomial with coefficients in [0, q) to bytes
void poly_pack_t1(byte *r, const poly *a);

/// \brief Unpack t1 polynomial from bytes
void poly_unpack_t1(poly *r, const byte *a);

/// \brief Pack polynomial t0 (low 13 bits of t) to bytes
void poly_pack_t0(byte *r, const poly *a);

/// \brief Unpack t0 polynomial from bytes
void poly_unpack_t0(poly *r, const byte *a);

/// \brief Pack polynomial with coefficients in [-eta, eta]
template <class PARAMS>
void poly_pack_eta(byte *r, const poly *a);

/// \brief Unpack polynomial with coefficients in [-eta, eta]
template <class PARAMS>
void poly_unpack_eta(poly *r, const byte *a);

/// \brief Pack polynomial z with coefficients in [-gamma1+1, gamma1]
template <class PARAMS>
void poly_pack_z(byte *r, const poly *a);

/// \brief Unpack polynomial z
template <class PARAMS>
void poly_unpack_z(poly *r, const byte *a);

/// \brief Pack w1 polynomial
template <class PARAMS>
void poly_pack_w1(byte *r, const poly *a);

// ==================== Polynomial Vectors ====================

/// \brief Vector of k polynomials (for matrix columns / public key)
template <unsigned int K>
struct polyveck {
    poly vec[K];
};

/// \brief Vector of l polynomials (for matrix rows / signature)
template <unsigned int L>
struct polyvecl {
    poly vec[L];
};

// ==================== Vector Operations ====================

template <unsigned int K>
void polyveck_zero(polyveck<K> *v);

template <unsigned int L>
void polyvecl_zero(polyvecl<L> *v);

template <unsigned int K>
void polyveck_add(polyveck<K> *w, const polyveck<K> *u, const polyveck<K> *v);

template <unsigned int L>
void polyvecl_add(polyvecl<L> *w, const polyvecl<L> *u, const polyvecl<L> *v);

template <unsigned int K>
void polyveck_sub(polyveck<K> *w, const polyveck<K> *u, const polyveck<K> *v);

template <unsigned int L>
void polyvecl_sub(polyvecl<L> *w, const polyvecl<L> *u, const polyvecl<L> *v);

template <unsigned int K>
void polyveck_ntt(polyveck<K> *v);

template <unsigned int L>
void polyvecl_ntt(polyvecl<L> *v);

template <unsigned int K>
void polyveck_invntt(polyveck<K> *v);

template <unsigned int L>
void polyvecl_invntt(polyvecl<L> *v);

template <unsigned int K>
void polyveck_reduce(polyveck<K> *v);

template <unsigned int L>
void polyvecl_reduce(polyvecl<L> *v);

template <unsigned int K>
void polyveck_caddq(polyveck<K> *v);

template <unsigned int L>
void polyvecl_caddq(polyvecl<L> *v);

template <unsigned int K>
void polyveck_freeze(polyveck<K> *v);

/// \brief Pointwise multiply and accumulate: w = sum(u[i] * v[i])
template <unsigned int K>
void polyveck_pointwise_acc_montgomery(poly *w, const polyveck<K> *u, const polyveck<K> *v);

template <unsigned int L>
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl<L> *u, const polyvecl<L> *v);

/// \brief Check infinity norm of all polynomials in vector
template <unsigned int K>
int polyveck_chknorm(const polyveck<K> *v, int32_t bound);

template <unsigned int L>
int polyvecl_chknorm(const polyvecl<L> *v, int32_t bound);

/// \brief Matrix-vector multiply: t = A * s (A in NTT domain)
/// \details A is stored as k vectors of l polynomials
template <class PARAMS>
void polyvec_matrix_pointwise_montgomery(
    polyveck<PARAMS::k> *t,
    const poly A[PARAMS::k][PARAMS::l],
    const polyvecl<PARAMS::l> *s);

/// \brief Expand matrix A from seed using SHAKE128
template <class PARAMS>
void expand_matrix(poly A[PARAMS::k][PARAMS::l], const byte *rho);

// ==================== Vector Packing ====================

template <class PARAMS>
void pack_pk(byte *pk, const byte *rho, const polyveck<PARAMS::k> *t1);

template <class PARAMS>
void unpack_pk(byte *rho, polyveck<PARAMS::k> *t1, const byte *pk);

template <class PARAMS>
void pack_sk(byte *sk, const byte *rho, const byte *tr, const byte *key,
             const polyveck<PARAMS::k> *t0,
             const polyvecl<PARAMS::l> *s1,
             const polyveck<PARAMS::k> *s2);

template <class PARAMS>
void unpack_sk(byte *rho, byte *tr, byte *key,
               polyveck<PARAMS::k> *t0,
               polyvecl<PARAMS::l> *s1,
               polyveck<PARAMS::k> *s2,
               const byte *sk);

template <class PARAMS>
void pack_sig(byte *sig,
              const byte *c_tilde,
              const polyvecl<PARAMS::l> *z,
              const polyveck<PARAMS::k> *h);

template <class PARAMS>
int unpack_sig(byte *c_tilde,
               polyvecl<PARAMS::l> *z,
               polyveck<PARAMS::k> *h,
               const byte *sig);

NAMESPACE_END  // MLDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_MLDSA_POLY_H
