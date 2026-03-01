// slhdsa_params.h - written and placed in the public domain by Colin Brown
//                   SLH-DSA (FIPS 205) internal parameter definitions
//                   Based on SPHINCS+ reference implementation (public domain)

#ifndef CRYPTOPP_SLHDSA_PARAMS_H
#define CRYPTOPP_SLHDSA_PARAMS_H

#include <cryptopp/config.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(SLHDSA_Internal)

// SLH-DSA internal parameters per FIPS 205 Table 1
// These define the tree structure, WOTS+, and FORS parameters

// ******************** SHA2-128f ************************* //
struct Params_SHA2_128f {
    static constexpr unsigned int n = 16;           // Security parameter (hash output size)
    static constexpr unsigned int h = 66;           // Total tree height
    static constexpr unsigned int d = 22;           // Number of layers
    static constexpr unsigned int hp = 3;           // Height of each tree (h/d)
    static constexpr unsigned int a = 6;            // FORS trees height
    static constexpr unsigned int k = 33;           // FORS trees count
    static constexpr unsigned int w = 16;           // WOTS+ Winternitz parameter
    static constexpr unsigned int len1 = 32;        // ceil(8*16/4) = 32
    static constexpr unsigned int len2 = 3;         // floor(lg(32*15)/4) + 1 = 3
    static constexpr unsigned int len = 35;         // len1 + len2

    static constexpr unsigned int lg_w = 4;         // log2(w)
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHA2-128s ************************* //
struct Params_SHA2_128s {
    static constexpr unsigned int n = 16;
    static constexpr unsigned int h = 63;
    static constexpr unsigned int d = 7;
    static constexpr unsigned int hp = 9;
    static constexpr unsigned int a = 12;
    static constexpr unsigned int k = 14;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 32;        // ceil(8*16/4) = 32
    static constexpr unsigned int len2 = 3;         // floor(lg(32*15)/4) + 1 = 3
    static constexpr unsigned int len = 35;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHA2-192f ************************* //
struct Params_SHA2_192f {
    static constexpr unsigned int n = 24;
    static constexpr unsigned int h = 66;
    static constexpr unsigned int d = 22;
    static constexpr unsigned int hp = 3;
    static constexpr unsigned int a = 8;
    static constexpr unsigned int k = 33;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 48;        // ceil(8*24/4) = 48
    static constexpr unsigned int len2 = 3;         // floor(lg(48*15)/4) + 1 = 3
    static constexpr unsigned int len = 51;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHA2-192s ************************* //
struct Params_SHA2_192s {
    static constexpr unsigned int n = 24;
    static constexpr unsigned int h = 63;
    static constexpr unsigned int d = 7;
    static constexpr unsigned int hp = 9;
    static constexpr unsigned int a = 14;
    static constexpr unsigned int k = 17;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 48;        // ceil(8*24/4) = 48
    static constexpr unsigned int len2 = 3;         // floor(lg(48*15)/4) + 1 = 3
    static constexpr unsigned int len = 51;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHA2-256f ************************* //
struct Params_SHA2_256f {
    static constexpr unsigned int n = 32;
    static constexpr unsigned int h = 68;
    static constexpr unsigned int d = 17;
    static constexpr unsigned int hp = 4;
    static constexpr unsigned int a = 9;
    static constexpr unsigned int k = 35;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 64;  // ceil(8*32/4) = 64
    static constexpr unsigned int len2 = 3;   // floor(lg(64*15)/4) + 1 = 3
    static constexpr unsigned int len = 67;   // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHA2-256s ************************* //
struct Params_SHA2_256s {
    static constexpr unsigned int n = 32;
    static constexpr unsigned int h = 64;
    static constexpr unsigned int d = 8;
    static constexpr unsigned int hp = 8;
    static constexpr unsigned int a = 14;
    static constexpr unsigned int k = 22;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 64;  // ceil(8*32/4) = 64
    static constexpr unsigned int len2 = 3;   // floor(lg(64*15)/4) + 1 = 3
    static constexpr unsigned int len = 67;   // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = true;
    static constexpr bool use_shake = false;
    static constexpr bool robust = true;
};

// ******************** SHAKE-128f ************************* //
struct Params_SHAKE_128f {
    static constexpr unsigned int n = 16;
    static constexpr unsigned int h = 66;
    static constexpr unsigned int d = 22;
    static constexpr unsigned int hp = 3;
    static constexpr unsigned int a = 6;
    static constexpr unsigned int k = 33;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 32;        // ceil(8*16/4) = 32
    static constexpr unsigned int len2 = 3;         // floor(lg(32*15)/4) + 1 = 3
    static constexpr unsigned int len = 35;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** SHAKE-128s ************************* //
struct Params_SHAKE_128s {
    static constexpr unsigned int n = 16;
    static constexpr unsigned int h = 63;
    static constexpr unsigned int d = 7;
    static constexpr unsigned int hp = 9;
    static constexpr unsigned int a = 12;
    static constexpr unsigned int k = 14;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 32;        // ceil(8*16/4) = 32
    static constexpr unsigned int len2 = 3;         // floor(lg(32*15)/4) + 1 = 3
    static constexpr unsigned int len = 35;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** SHAKE-192f ************************* //
struct Params_SHAKE_192f {
    static constexpr unsigned int n = 24;
    static constexpr unsigned int h = 66;
    static constexpr unsigned int d = 22;
    static constexpr unsigned int hp = 3;
    static constexpr unsigned int a = 8;
    static constexpr unsigned int k = 33;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 48;        // ceil(8*24/4) = 48
    static constexpr unsigned int len2 = 3;         // floor(lg(48*15)/4) + 1 = 3
    static constexpr unsigned int len = 51;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** SHAKE-192s ************************* //
struct Params_SHAKE_192s {
    static constexpr unsigned int n = 24;
    static constexpr unsigned int h = 63;
    static constexpr unsigned int d = 7;
    static constexpr unsigned int hp = 9;
    static constexpr unsigned int a = 14;
    static constexpr unsigned int k = 17;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 48;        // ceil(8*24/4) = 48
    static constexpr unsigned int len2 = 3;         // floor(lg(48*15)/4) + 1 = 3
    static constexpr unsigned int len = 51;         // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** SHAKE-256f ************************* //
struct Params_SHAKE_256f {
    static constexpr unsigned int n = 32;
    static constexpr unsigned int h = 68;
    static constexpr unsigned int d = 17;
    static constexpr unsigned int hp = 4;
    static constexpr unsigned int a = 9;
    static constexpr unsigned int k = 35;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 64;  // ceil(8*32/4) = 64
    static constexpr unsigned int len2 = 3;   // floor(lg(64*15)/4) + 1 = 3
    static constexpr unsigned int len = 67;   // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** SHAKE-256s ************************* //
struct Params_SHAKE_256s {
    static constexpr unsigned int n = 32;
    static constexpr unsigned int h = 64;
    static constexpr unsigned int d = 8;
    static constexpr unsigned int hp = 8;
    static constexpr unsigned int a = 14;
    static constexpr unsigned int k = 22;
    static constexpr unsigned int w = 16;
    static constexpr unsigned int len1 = 64;  // ceil(8*32/4) = 64
    static constexpr unsigned int len2 = 3;   // floor(lg(64*15)/4) + 1 = 3
    static constexpr unsigned int len = 67;   // len1 + len2

    static constexpr unsigned int lg_w = 4;
    static constexpr unsigned int tree_height = hp;
    static constexpr unsigned int fors_height = a;
    static constexpr unsigned int fors_trees = k;

    // WOTS+ parameter aliases
    static constexpr unsigned int wots_w = w;
    static constexpr unsigned int wots_logw = lg_w;
    static constexpr unsigned int wots_len = len;
    static constexpr unsigned int wots_len1 = len1;
    static constexpr unsigned int wots_len2 = len2;
    static constexpr unsigned int wots_sig_bytes = len * n;

    static constexpr unsigned int pk_bytes = 2 * n;
    static constexpr unsigned int sk_bytes = 4 * n;
    static constexpr unsigned int sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

    static constexpr bool use_sha2 = false;
    static constexpr bool use_shake = true;
    static constexpr bool robust = true;
};

// ******************** Address Offsets ************************* //
// FIPS 205 Section 4.2 - ADRS structure (word-aligned, 8 x 4 bytes)
//
// Word 0 (bytes  0- 3): layer address
// Word 1 (bytes  4- 7): tree address (high)
// Word 2 (bytes  8-11): tree address (mid)
// Word 3 (bytes 12-15): tree address (low)
// Word 4 (bytes 16-19): type
// Word 5 (bytes 20-23): key pair address
// Word 6 (bytes 24-27): chain address / tree height
// Word 7 (bytes 28-31): hash address / tree index

static constexpr unsigned int ADDR_BYTES = 32;

// Address type constants
static constexpr unsigned int ADDR_TYPE_WOTS_HASH = 0;
static constexpr unsigned int ADDR_TYPE_WOTS_PK = 1;
static constexpr unsigned int ADDR_TYPE_TREE = 2;
static constexpr unsigned int ADDR_TYPE_FORS_TREE = 3;
static constexpr unsigned int ADDR_TYPE_FORS_PK = 4;
static constexpr unsigned int ADDR_TYPE_WOTS_PRF = 5;
static constexpr unsigned int ADDR_TYPE_FORS_PRF = 6;

// Address field offsets (FIPS 205 word-aligned layout)
static constexpr unsigned int ADDR_KEYPAIR_OFFSET = 20;
static constexpr unsigned int ADDR_CHAIN_OFFSET = 24;
static constexpr unsigned int ADDR_HASH_OFFSET = 28;
static constexpr unsigned int ADDR_TREE_HEIGHT_OFFSET = 24;
static constexpr unsigned int ADDR_TREE_INDEX_OFFSET = 28;

NAMESPACE_END  // SLHDSA_Internal
NAMESPACE_END  // CryptoPP

#endif // CRYPTOPP_SLHDSA_PARAMS_H
