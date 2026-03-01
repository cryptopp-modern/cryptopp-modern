// slhdsa_internal.h - written and placed in the public domain by Colin Brown
//                     SLH-DSA (FIPS 205) internal declarations
//                     Based on SPHINCS+ reference implementation (public domain)

#ifndef CRYPTOPP_SLHDSA_INTERNAL_H
#define CRYPTOPP_SLHDSA_INTERNAL_H

#include <cryptopp/config.h>
#include "slhdsa_params.h"
#include <cstdint>
#include <cstring>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(SLHDSA_Internal)

// ******************** Constants ************************* //

/// WOTS+ Winternitz parameter (w = 16 for all SLH-DSA variants)
static constexpr unsigned int WOTS_W = 16;
static constexpr unsigned int WOTS_LOGW = 4;

// ******************** Address Types ************************* //
// Per FIPS 205 Section 4.2 (use consistent naming with params.h)

static constexpr uint32_t ADDR_TYPE_WOTS = ADDR_TYPE_WOTS_HASH;
static constexpr uint32_t ADDR_TYPE_WOTSPK = ADDR_TYPE_WOTS_PK;
static constexpr uint32_t ADDR_TYPE_HASHTREE = ADDR_TYPE_TREE;
static constexpr uint32_t ADDR_TYPE_FORSTREE = ADDR_TYPE_FORS_TREE;
static constexpr uint32_t ADDR_TYPE_FORSPK = ADDR_TYPE_FORS_PK;
static constexpr uint32_t ADDR_TYPE_WOTSPRF = ADDR_TYPE_WOTS_PRF;
static constexpr uint32_t ADDR_TYPE_FORSPRF = ADDR_TYPE_FORS_PRF;

// ******************** Address Manipulation Functions ************************* //
// Per FIPS 205 Section 4.2 - word-aligned 32-byte ADRS

inline void set_layer_addr(byte *addr, uint32_t layer)
{
    // Word 0 (bytes 0-3), big-endian
    addr[0] = 0;
    addr[1] = 0;
    addr[2] = 0;
    addr[3] = static_cast<byte>(layer);
}

inline void set_tree_addr(byte *addr, uint64_t tree)
{
    // Words 1-3 (bytes 4-15), 12 bytes big-endian
    // Upper 4 bytes (word 1) always 0 for current parameter sets
    addr[4] = 0;
    addr[5] = 0;
    addr[6] = 0;
    addr[7] = 0;
    // Lower 8 bytes (words 2-3)
    for (int i = 7; i >= 0; i--) {
        addr[8 + i] = static_cast<byte>(tree);
        tree >>= 8;
    }
}

inline void set_type(byte *addr, uint32_t type)
{
    // Word 4 (bytes 16-19), big-endian
    addr[16] = 0;
    addr[17] = 0;
    addr[18] = 0;
    addr[19] = static_cast<byte>(type);
    // Zero words 5-7 (bytes 20-31)
    std::memset(addr + 20, 0, 12);
}

inline void set_keypair_addr(byte *addr, uint32_t keypair)
{
    // Word 5 (bytes 20-23), big-endian
    addr[ADDR_KEYPAIR_OFFSET] = static_cast<byte>(keypair >> 24);
    addr[ADDR_KEYPAIR_OFFSET + 1] = static_cast<byte>(keypair >> 16);
    addr[ADDR_KEYPAIR_OFFSET + 2] = static_cast<byte>(keypair >> 8);
    addr[ADDR_KEYPAIR_OFFSET + 3] = static_cast<byte>(keypair);
}

inline void copy_keypair_addr(byte *out, const byte *in)
{
    // Copy words 0-3 (bytes 0-15: layer + tree), skip word 4 (type)
    // Copy word 5 (bytes 20-23: keypair)
    std::memcpy(out, in, 16);
    std::memcpy(out + ADDR_KEYPAIR_OFFSET, in + ADDR_KEYPAIR_OFFSET, 4);
}

inline void set_chain_addr(byte *addr, uint32_t chain)
{
    // Word 6 (bytes 24-27), big-endian
    addr[ADDR_CHAIN_OFFSET] = static_cast<byte>(chain >> 24);
    addr[ADDR_CHAIN_OFFSET + 1] = static_cast<byte>(chain >> 16);
    addr[ADDR_CHAIN_OFFSET + 2] = static_cast<byte>(chain >> 8);
    addr[ADDR_CHAIN_OFFSET + 3] = static_cast<byte>(chain);
}

inline void set_hash_addr(byte *addr, uint32_t hash)
{
    // Word 7 (bytes 28-31), big-endian
    addr[ADDR_HASH_OFFSET] = static_cast<byte>(hash >> 24);
    addr[ADDR_HASH_OFFSET + 1] = static_cast<byte>(hash >> 16);
    addr[ADDR_HASH_OFFSET + 2] = static_cast<byte>(hash >> 8);
    addr[ADDR_HASH_OFFSET + 3] = static_cast<byte>(hash);
}

inline void set_tree_height(byte *addr, uint32_t height)
{
    // Word 6 (bytes 24-27), big-endian
    addr[ADDR_TREE_HEIGHT_OFFSET] = 0;
    addr[ADDR_TREE_HEIGHT_OFFSET + 1] = 0;
    addr[ADDR_TREE_HEIGHT_OFFSET + 2] = 0;
    addr[ADDR_TREE_HEIGHT_OFFSET + 3] = static_cast<byte>(height);
}

inline void set_tree_index(byte *addr, uint32_t index)
{
    // Word 7 (bytes 28-31), big-endian
    addr[ADDR_TREE_INDEX_OFFSET] = static_cast<byte>(index >> 24);
    addr[ADDR_TREE_INDEX_OFFSET + 1] = static_cast<byte>(index >> 16);
    addr[ADDR_TREE_INDEX_OFFSET + 2] = static_cast<byte>(index >> 8);
    addr[ADDR_TREE_INDEX_OFFSET + 3] = static_cast<byte>(index);
}

inline uint32_t get_tree_index(const byte *addr)
{
    return (static_cast<uint32_t>(addr[ADDR_TREE_INDEX_OFFSET]) << 24) |
           (static_cast<uint32_t>(addr[ADDR_TREE_INDEX_OFFSET + 1]) << 16) |
           (static_cast<uint32_t>(addr[ADDR_TREE_INDEX_OFFSET + 2]) << 8) |
           static_cast<uint32_t>(addr[ADDR_TREE_INDEX_OFFSET + 3]);
}

// ******************** WOTS+ Function Declarations ************************* //

template <class HASH_CTX, class PARAMS>
void wots_pk_gen(byte *pk, const byte *sk_seed,
                 const byte *pub_seed, byte *addr);

template <class HASH_CTX, class PARAMS>
void wots_sign(byte *sig, const byte *msg,
               const byte *sk_seed, const byte *pub_seed, byte *addr);

template <class HASH_CTX, class PARAMS>
void wots_pk_from_sig(byte *pk, const byte *sig, const byte *msg,
                      const byte *pub_seed, byte *addr);

// ******************** FORS Function Declarations ************************* //

template <class HASH_CTX, class PARAMS>
void fors_sk_gen(byte *sk, const byte *sk_seed,
                 const byte *pub_seed, byte *addr, uint32_t idx);

template <class HASH_CTX, class PARAMS>
void fors_sign(byte *sig, byte *pk, const byte *msg,
               const byte *sk_seed, const byte *pub_seed, byte *addr);

template <class HASH_CTX, class PARAMS>
void fors_pk_from_sig(byte *pk, const byte *sig, const byte *msg,
                      const byte *pub_seed, byte *addr);

// ******************** Merkle Tree Function Declarations ************************* //

template <class HASH_CTX, class PARAMS>
void treehash(byte *root, byte *auth_path,
              const byte *sk_seed, const byte *pub_seed,
              uint32_t leaf_idx, uint32_t subtree_addr,
              byte *addr);

template <class HASH_CTX, class PARAMS>
void compute_root(byte *root, const byte *leaf, uint32_t leaf_idx,
                  const byte *auth_path, uint32_t tree_height,
                  const byte *pub_seed, byte *addr);

NAMESPACE_END  // SLHDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_SLHDSA_INTERNAL_H
