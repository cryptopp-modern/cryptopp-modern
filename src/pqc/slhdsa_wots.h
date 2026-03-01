// slhdsa_wots.h - written and placed in the public domain by Colin Brown
//                 WOTS+ one-time signature for SLH-DSA (FIPS 205 Section 5)
//                 Based on SPHINCS+ reference implementation (public domain)

#ifndef CRYPTOPP_SLHDSA_WOTS_H
#define CRYPTOPP_SLHDSA_WOTS_H

#include "slhdsa_internal.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(SLHDSA_Internal)

// ******************** WOTS+ Implementation ************************* //
// Per FIPS 205 Section 5

/// Compute the chaining function
/// chain(X, i, s, PK.seed, ADRS) iterates F s times starting from X
/// Per FIPS 205 Algorithm 4
template <class HASH_CTX, unsigned int N>
static void wots_gen_chain(byte *out, const byte *in,
                           unsigned int start, unsigned int steps,
                           const byte *pub_seed, byte *addr)
{
    std::memcpy(out, in, N);

    for (unsigned int i = start; i < start + steps && i < WOTS_W; i++) {
        set_hash_addr(addr, i);
        HASH_CTX::thash_f(out, out, pub_seed, addr);
    }
}

/// Compute the base-w representation of a message
/// Per FIPS 205 Algorithm 5 (base_2^b)
template <unsigned int W, unsigned int LOGW>
static void base_w(unsigned int *output, size_t out_len,
                   const byte *input)
{
    size_t in_idx = 0;
    size_t out_idx = 0;
    unsigned int bits = 0;
    unsigned int total = 0;

    for (out_idx = 0; out_idx < out_len; out_idx++) {
        if (bits == 0) {
            total = input[in_idx];
            in_idx++;
            bits = 8;
        }
        bits -= LOGW;
        output[out_idx] = (total >> bits) & (W - 1);
    }
}

/// Compute WOTS+ checksum
/// Per FIPS 205 Algorithm 6
template <unsigned int W, unsigned int LEN1, unsigned int LEN2>
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w)
{
    unsigned int csum = 0;

    // Sum of (w - 1 - msg[i])
    for (unsigned int i = 0; i < LEN1; i++) {
        csum += (W - 1) - msg_base_w[i];
    }

    // Left shift checksum
    // csum <<= (8 - ((LEN2 * LOGW) % 8)) % 8
    // For w=16: LEN2=3, LOGW=4, so shift = (8 - 12%8) % 8 = (8-4)%8 = 4
    constexpr unsigned int LOGW = (W == 16) ? 4 : (W == 256) ? 8 : 4;
    constexpr unsigned int shift = (8 - ((LEN2 * LOGW) % 8)) % 8;
    csum <<= shift;

    // Convert checksum to base w
    byte csum_bytes[(LEN2 * LOGW + 7) / 8];
    unsigned int csum_len = (LEN2 * LOGW + 7) / 8;

    // Store checksum in big-endian
    for (int i = static_cast<int>(csum_len) - 1; i >= 0; i--) {
        csum_bytes[i] = static_cast<byte>(csum);
        csum >>= 8;
    }

    base_w<W, LOGW>(csum_base_w, LEN2, csum_bytes);
}

/// Generate WOTS+ public key from secret seed
/// Per FIPS 205 Algorithm 7 (wots_PKgen)
template <class HASH_CTX, class PARAMS>
void wots_pk_gen(byte *pk, const byte *sk_seed,
                 const byte *pub_seed, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int LEN = PARAMS::wots_len;

    byte tmp[N];
    byte sk_addr[ADDR_BYTES];
    std::memcpy(sk_addr, addr, ADDR_BYTES);
    set_type(sk_addr, ADDR_TYPE_WOTSPRF);
    copy_keypair_addr(sk_addr, addr);

    for (unsigned int i = 0; i < LEN; i++) {
        set_chain_addr(sk_addr, i);
        // Generate secret key element: PRF(PK.seed, SK.seed, ADRS)
        HASH_CTX::prf(tmp, pub_seed, sk_seed, sk_addr);

        set_chain_addr(addr, i);
        // Chain to get public key element
        wots_gen_chain<HASH_CTX, N>(pk + i * N, tmp, 0, WOTS_W - 1, pub_seed, addr);
    }

    SecureWipeBuffer(tmp, N);
}

/// Generate WOTS+ signature
/// Per FIPS 205 Algorithm 8 (wots_sign)
template <class HASH_CTX, class PARAMS>
void wots_sign(byte *sig, const byte *msg,
               const byte *sk_seed, const byte *pub_seed, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int LEN = PARAMS::wots_len;
    constexpr unsigned int LEN1 = PARAMS::wots_len1;
    constexpr unsigned int LEN2 = PARAMS::wots_len2;
    constexpr unsigned int W = WOTS_W;
    constexpr unsigned int LOGW = (W == 16) ? 4 : 8;

    unsigned int lengths[LEN];
    byte tmp[N];
    byte sk_addr[ADDR_BYTES];

    std::memcpy(sk_addr, addr, ADDR_BYTES);
    set_type(sk_addr, ADDR_TYPE_WOTSPRF);
    copy_keypair_addr(sk_addr, addr);

    // Convert message to base w
    base_w<W, LOGW>(lengths, LEN1, msg);

    // Compute and append checksum
    wots_checksum<W, LEN1, LEN2>(lengths + LEN1, lengths);

    for (unsigned int i = 0; i < LEN; i++) {
        set_chain_addr(sk_addr, i);
        HASH_CTX::prf(tmp, pub_seed, sk_seed, sk_addr);

        set_chain_addr(addr, i);
        wots_gen_chain<HASH_CTX, N>(sig + i * N, tmp, 0, lengths[i], pub_seed, addr);
    }

    SecureWipeBuffer(tmp, N);
}

/// Compute WOTS+ public key from signature
/// Per FIPS 205 Algorithm 9 (wots_PKFromSig)
template <class HASH_CTX, class PARAMS>
void wots_pk_from_sig(byte *pk, const byte *sig, const byte *msg,
                      const byte *pub_seed, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int LEN = PARAMS::wots_len;
    constexpr unsigned int LEN1 = PARAMS::wots_len1;
    constexpr unsigned int LEN2 = PARAMS::wots_len2;
    constexpr unsigned int W = WOTS_W;
    constexpr unsigned int LOGW = (W == 16) ? 4 : 8;

    unsigned int lengths[LEN];

    // Convert message to base w
    base_w<W, LOGW>(lengths, LEN1, msg);

    // Compute and append checksum
    wots_checksum<W, LEN1, LEN2>(lengths + LEN1, lengths);

    for (unsigned int i = 0; i < LEN; i++) {
        set_chain_addr(addr, i);
        // Chain from signature value to complete the chain
        wots_gen_chain<HASH_CTX, N>(pk + i * N, sig + i * N,
                                     lengths[i], (W - 1) - lengths[i],
                                     pub_seed, addr);
    }
}

// ******************** Explicit Template Instantiations ************************* //

// We need to instantiate for each parameter set
// These will be called from the main slhdsa.cpp

#define INSTANTIATE_WOTS(PARAMS, HASH_CTX) \
    template void wots_pk_gen<HASH_CTX, PARAMS>( \
        byte*, const byte*, const byte*, byte*); \
    template void wots_sign<HASH_CTX, PARAMS>( \
        byte*, const byte*, const byte*, const byte*, byte*); \
    template void wots_pk_from_sig<HASH_CTX, PARAMS>( \
        byte*, const byte*, const byte*, const byte*, byte*);

// Note: Actual instantiations will be done when we have the full
// HashContext types available. For now, these are internal functions
// that will be called from the main implementation.

NAMESPACE_END  // SLHDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_SLHDSA_WOTS_H
