// slhdsa.cpp - written and placed in the public domain by Colin Brown
//              SLH-DSA (FIPS 205) implementation
//              Based on SPHINCS+ reference implementation (public domain)

#include <cryptopp/pch.h>
#include <cryptopp/slhdsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/shake.h>
#include <cryptopp/hmac.h>
#include <cryptopp/misc.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include "slhdsa_params.h"
#include "slhdsa_internal.h"
#include "slhdsa_wots.h"
#include "slhdsa_fors.h"
#include "slhdsa_hypertree.h"

#include <cstring>
#include <stdexcept>
#include <type_traits>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Internal Implementation ************************* //

namespace {

using namespace SLHDSA_Internal;

// ******************** Parameter Traits ************************* //
// Maps public parameter structs to internal parameter structs

template <class PARAMS> struct ParamTraits;

template <> struct ParamTraits<SLHDSA_SHA2_128f> {
    typedef Params_SHA2_128f Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHA2_128s> {
    typedef Params_SHA2_128s Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHA2_192f> {
    typedef Params_SHA2_192f Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHA2_192s> {
    typedef Params_SHA2_192s Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHA2_256f> {
    typedef Params_SHA2_256f Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHA2_256s> {
    typedef Params_SHA2_256s Internal;
    static constexpr bool use_sha2 = true;
};
template <> struct ParamTraits<SLHDSA_SHAKE_128f> {
    typedef Params_SHAKE_128f Internal;
    static constexpr bool use_sha2 = false;
};
template <> struct ParamTraits<SLHDSA_SHAKE_128s> {
    typedef Params_SHAKE_128s Internal;
    static constexpr bool use_sha2 = false;
};
template <> struct ParamTraits<SLHDSA_SHAKE_192f> {
    typedef Params_SHAKE_192f Internal;
    static constexpr bool use_sha2 = false;
};
template <> struct ParamTraits<SLHDSA_SHAKE_192s> {
    typedef Params_SHAKE_192s Internal;
    static constexpr bool use_sha2 = false;
};
template <> struct ParamTraits<SLHDSA_SHAKE_256f> {
    typedef Params_SHAKE_256f Internal;
    static constexpr bool use_sha2 = false;
};
template <> struct ParamTraits<SLHDSA_SHAKE_256s> {
    typedef Params_SHAKE_256s Internal;
    static constexpr bool use_sha2 = false;
};

// ******************** SHAKE-based Hash Functions ************************* //
// Per FIPS 205 Section 10.1

template <class INTERNAL_PARAMS>
class ShakeHashContext
{
public:
    static constexpr unsigned int n = INTERNAL_PARAMS::n;

    static void prf(byte *out, const byte *pub_seed, const byte *sk_seed,
                    const byte *addr)
    {
        SHAKE256 shake(n);
        shake.Update(pub_seed, n);
        shake.Update(addr, ADDR_BYTES);
        shake.Update(sk_seed, n);
        shake.TruncatedFinal(out, n);
    }

    static void prf_msg(byte *out, const byte *sk_prf, const byte *opt_rand,
                        const byte *msg, size_t msg_len)
    {
        SHAKE256 shake(n);
        shake.Update(sk_prf, n);
        shake.Update(opt_rand, n);
        shake.Update(msg, msg_len);
        shake.TruncatedFinal(out, n);
    }

    static void h_msg(byte *out, size_t out_len,
                      const byte *r, const byte *pub_seed, const byte *pub_root,
                      const byte *msg, size_t msg_len)
    {
        SHAKE256 shake(static_cast<unsigned int>(out_len));
        shake.Update(r, n);
        shake.Update(pub_seed, n);
        shake.Update(pub_root, n);
        shake.Update(msg, msg_len);
        shake.TruncatedFinal(out, out_len);
    }

    static void thash_f(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        SHAKE256 shake(n);
        shake.Update(pub_seed, n);
        shake.Update(addr, ADDR_BYTES);
        shake.Update(in, n);
        shake.TruncatedFinal(out, n);
    }

    static void thash_h(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        SHAKE256 shake(n);
        shake.Update(pub_seed, n);
        shake.Update(addr, ADDR_BYTES);
        shake.Update(in, 2 * n);
        shake.TruncatedFinal(out, n);
    }

    static void thash_tl(byte *out, const byte *in, unsigned int in_blocks,
                         const byte *pub_seed, const byte *addr)
    {
        SHAKE256 shake(n);
        shake.Update(pub_seed, n);
        shake.Update(addr, ADDR_BYTES);
        shake.Update(in, in_blocks * n);
        shake.TruncatedFinal(out, n);
    }
};

// ******************** SHA2-based Hash Functions ************************* //
// Per FIPS 205 Section 10.2

static constexpr unsigned int SHA2_ADDR_BYTES = 22;

// ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
// Per FIPS 205 Section 10.2
inline void compress_address(byte *out, const byte *addr)
{
    out[0] = addr[3];                       // 1 byte: layer
    std::memcpy(out + 1, addr + 8, 8);      // 8 bytes: tree address (low 8 of 12)
    out[9] = addr[19];                      // 1 byte: type
    std::memcpy(out + 10, addr + 20, 12);   // 12 bytes: keypair + chain/height + hash/index
}

template <class INTERNAL_PARAMS>
class Sha2HashContext
{
public:
    static constexpr unsigned int n = INTERNAL_PARAMS::n;
    // SHA-256 constants (used by PRF, F, and as base for all categories)
    static constexpr unsigned int BLOCK_SIZE = 64;   // SHA-256 block size
    static constexpr unsigned int HASH_SIZE = 32;    // SHA-256 output size

    // FIPS 205 Section 10.2: categories 3,5 (n>16) use SHA-512 for prf_msg, h_msg inner,
    // and for H (thash_h) and T_l (thash_tl with l>1)
    using MsgHashType = typename std::conditional<(n > 16), SHA512, SHA256>::type;
    using MsgHmacType = typename std::conditional<(n > 16), HMAC<SHA512>, HMAC<SHA256>>::type;
    static constexpr unsigned int MSG_HASH_SIZE = (n > 16) ? 64 : 32;

    // FIPS 205 Section 10.2: H and T_l use SHA-512/128-byte block for n>16, SHA-256/64-byte for n=16
    using ThashBigType = typename std::conditional<(n > 16), SHA512, SHA256>::type;
    static constexpr unsigned int BIG_BLOCK_SIZE = (n > 16) ? 128 : 64;
    static constexpr unsigned int BIG_HASH_SIZE = (n > 16) ? 64 : 32;

    static void prf(byte *out, const byte *pub_seed, const byte *sk_seed,
                    const byte *addr)
    {
        byte buf[BLOCK_SIZE + SHA2_ADDR_BYTES + 32];
        byte hash[HASH_SIZE];
        byte addr_c[SHA2_ADDR_BYTES];

        compress_address(addr_c, addr);

        std::memcpy(buf, pub_seed, n);
        std::memset(buf + n, 0, BLOCK_SIZE - n);
        std::memcpy(buf + BLOCK_SIZE, addr_c, SHA2_ADDR_BYTES);
        std::memcpy(buf + BLOCK_SIZE + SHA2_ADDR_BYTES, sk_seed, n);

        SHA256 sha;
        sha.Update(buf, BLOCK_SIZE + SHA2_ADDR_BYTES + n);
        sha.Final(hash);

        std::memcpy(out, hash, n);

        SecureWipeBuffer(buf, sizeof(buf));
        SecureWipeBuffer(hash, sizeof(hash));
    }

    static void prf_msg(byte *out, const byte *sk_prf, const byte *opt_rand,
                        const byte *msg, size_t msg_len)
    {
        // FIPS 205 Section 10.2: HMAC-SHA-256 for n=16, HMAC-SHA-512 for n=24,32
        byte hash[MSG_HASH_SIZE];

        MsgHmacType hmac(sk_prf, n);
        hmac.Update(opt_rand, n);
        hmac.Update(msg, msg_len);
        hmac.Final(hash);

        std::memcpy(out, hash, n);
    }

    static void h_msg(byte *out, size_t out_len,
                      const byte *r, const byte *pub_seed, const byte *pub_root,
                      const byte *msg, size_t msg_len)
    {
        // FIPS 205 Section 10.2:
        // seed = SHA-X(R || PK.seed || PK.root || M)
        // H_msg = MGF1-SHA-X(R || PK.seed || seed, m)
        // where SHA-X = SHA-256 for n<24, SHA-512 for n>=24
        byte seed[MSG_HASH_SIZE];

        MsgHashType sha;
        sha.Update(r, n);
        sha.Update(pub_seed, n);
        sha.Update(pub_root, n);
        sha.Update(msg, msg_len);
        sha.Final(seed);

        // MGF1 input: R || PK.seed || seed
        byte mgf_input[2 * n + MSG_HASH_SIZE];
        std::memcpy(mgf_input, r, n);
        std::memcpy(mgf_input + n, pub_seed, n);
        std::memcpy(mgf_input + 2 * n, seed, MSG_HASH_SIZE);

        if (n > 16) {
            mgf1_sha512(out, out_len, mgf_input, 2 * n + MSG_HASH_SIZE);
        } else {
            mgf1_sha256(out, out_len, mgf_input, 2 * n + MSG_HASH_SIZE);
        }
    }

    static void thash_f(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        byte buf[BLOCK_SIZE + SHA2_ADDR_BYTES + 32];
        byte hash[HASH_SIZE];
        byte addr_c[SHA2_ADDR_BYTES];

        compress_address(addr_c, addr);

        std::memcpy(buf, pub_seed, n);
        std::memset(buf + n, 0, BLOCK_SIZE - n);
        std::memcpy(buf + BLOCK_SIZE, addr_c, SHA2_ADDR_BYTES);
        std::memcpy(buf + BLOCK_SIZE + SHA2_ADDR_BYTES, in, n);

        SHA256 sha;
        sha.Update(buf, BLOCK_SIZE + SHA2_ADDR_BYTES + n);
        sha.Final(hash);

        std::memcpy(out, hash, n);
    }

    static void thash_h(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        // FIPS 205 Section 10.2: H uses SHA-512 with 128-byte block for n>16
        byte buf[BIG_BLOCK_SIZE + SHA2_ADDR_BYTES + 2 * n];
        byte hash[BIG_HASH_SIZE];
        byte addr_c[SHA2_ADDR_BYTES];

        compress_address(addr_c, addr);

        std::memcpy(buf, pub_seed, n);
        std::memset(buf + n, 0, BIG_BLOCK_SIZE - n);
        std::memcpy(buf + BIG_BLOCK_SIZE, addr_c, SHA2_ADDR_BYTES);
        std::memcpy(buf + BIG_BLOCK_SIZE + SHA2_ADDR_BYTES, in, 2 * n);

        ThashBigType sha;
        sha.Update(buf, BIG_BLOCK_SIZE + SHA2_ADDR_BYTES + 2 * n);
        sha.Final(hash);

        std::memcpy(out, hash, n);
    }

    static void thash_tl(byte *out, const byte *in, unsigned int in_blocks,
                         const byte *pub_seed, const byte *addr)
    {
        byte addr_c[SHA2_ADDR_BYTES];
        compress_address(addr_c, addr);

        if (in_blocks == 1) {
            thash_f(out, in, pub_seed, addr);
            return;
        }

        // FIPS 205 Section 10.2: T_l (l>1) uses SHA-512 with 128-byte block for n>16
        byte buf[BIG_BLOCK_SIZE + SHA2_ADDR_BYTES];
        byte hash[BIG_HASH_SIZE];

        std::memcpy(buf, pub_seed, n);
        std::memset(buf + n, 0, BIG_BLOCK_SIZE - n);
        std::memcpy(buf + BIG_BLOCK_SIZE, addr_c, SHA2_ADDR_BYTES);

        ThashBigType sha;
        sha.Update(buf, BIG_BLOCK_SIZE + SHA2_ADDR_BYTES);
        sha.Update(in, in_blocks * n);
        sha.Final(hash);

        std::memcpy(out, hash, n);
    }

private:
    static void mgf1_sha256(byte *out, size_t out_len,
                            const byte *seed, size_t seed_len)
    {
        byte counter[4] = {0, 0, 0, 0};
        byte hash[HASH_SIZE];
        size_t offset = 0;

        while (offset < out_len) {
            SHA256 sha;
            sha.Update(seed, seed_len);
            sha.Update(counter, 4);
            sha.Final(hash);

            size_t to_copy = std::min<size_t>(HASH_SIZE, out_len - offset);
            std::memcpy(out + offset, hash, to_copy);
            offset += to_copy;

            for (int i = 3; i >= 0; i--) {
                if (++counter[i] != 0) break;
            }
        }
    }

    static void mgf1_sha512(byte *out, size_t out_len,
                            const byte *seed, size_t seed_len)
    {
        byte counter[4] = {0, 0, 0, 0};
        byte hash[64];
        size_t offset = 0;

        while (offset < out_len) {
            SHA512 sha;
            sha.Update(seed, seed_len);
            sha.Update(counter, 4);
            sha.Final(hash);

            size_t to_copy = std::min<size_t>(64, out_len - offset);
            std::memcpy(out + offset, hash, to_copy);
            offset += to_copy;

            for (int i = 3; i >= 0; i--) {
                if (++counter[i] != 0) break;
            }
        }
    }
};

// ******************** Unified Hash Context ************************* //

template <class PARAMS, bool USE_SHA2 = ParamTraits<PARAMS>::use_sha2>
struct HashContextSelector;

template <class PARAMS>
struct HashContextSelector<PARAMS, false> {
    typedef ShakeHashContext<typename ParamTraits<PARAMS>::Internal> Type;
};

template <class PARAMS>
struct HashContextSelector<PARAMS, true> {
    typedef Sha2HashContext<typename ParamTraits<PARAMS>::Internal> Type;
};

template <class PARAMS>
class HashContext
{
public:
    typedef typename HashContextSelector<PARAMS>::Type Impl;
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;

    static constexpr unsigned int n = InternalParams::n;

    static void prf(byte *out, const byte *pub_seed, const byte *sk_seed,
                    const byte *addr)
    {
        Impl::prf(out, pub_seed, sk_seed, addr);
    }

    static void prf_msg(byte *out, const byte *sk_prf, const byte *opt_rand,
                        const byte *msg, size_t msg_len)
    {
        Impl::prf_msg(out, sk_prf, opt_rand, msg, msg_len);
    }

    static void h_msg(byte *out, size_t out_len,
                      const byte *r, const byte *pub_seed, const byte *pub_root,
                      const byte *msg, size_t msg_len)
    {
        Impl::h_msg(out, out_len, r, pub_seed, pub_root, msg, msg_len);
    }

    static void thash_f(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        Impl::thash_f(out, in, pub_seed, addr);
    }

    static void thash_h(byte *out, const byte *in,
                        const byte *pub_seed, const byte *addr)
    {
        Impl::thash_h(out, in, pub_seed, addr);
    }

    static void thash_tl(byte *out, const byte *in, unsigned int in_blocks,
                         const byte *pub_seed, const byte *addr)
    {
        Impl::thash_tl(out, in, in_blocks, pub_seed, addr);
    }
};

// ******************** SLH-DSA Core Algorithms ************************* //
// Per FIPS 205 Section 9

/// Extract indices from message digest
/// Per FIPS 205 Algorithm 22 steps 9-10: byte-level toInt then mod 2^bits
template <class PARAMS>
static void extract_indices(uint64_t &idx_tree, uint32_t &idx_leaf,
                            const byte *digest)
{
    constexpr unsigned int H = PARAMS::h;
    constexpr unsigned int D = PARAMS::d;
    constexpr unsigned int HP = H / D;  // Tree height per layer

    constexpr unsigned int TREE_BITS = H - HP;
    constexpr unsigned int LEAF_BITS = HP;
    constexpr size_t TREE_BYTES = (TREE_BITS + 7) / 8;
    constexpr size_t LEAF_BYTES = (LEAF_BITS + 7) / 8;

    // idx_tree = toInt(tmp_idx_tree, TREE_BYTES) mod 2^TREE_BITS
    idx_tree = 0;
    for (size_t i = 0; i < TREE_BYTES; i++)
        idx_tree = (idx_tree << 8) | digest[i];
    if (TREE_BITS < 64)
        idx_tree &= (static_cast<uint64_t>(1) << (TREE_BITS % 64)) - 1;

    // idx_leaf = toInt(tmp_idx_leaf, LEAF_BYTES) mod 2^LEAF_BITS
    idx_leaf = 0;
    for (size_t i = 0; i < LEAF_BYTES; i++)
        idx_leaf = (idx_leaf << 8) | digest[TREE_BYTES + i];
    idx_leaf &= (static_cast<uint32_t>(1) << LEAF_BITS) - 1;
}

/// SLH-DSA Key Generation
/// Per FIPS 205 Algorithm 21 (slh_keygen)
template <class PARAMS>
static void slh_keygen(byte *sk, byte *pk, RandomNumberGenerator &rng)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    typedef HashContext<PARAMS> Hash;

    constexpr unsigned int N = InternalParams::n;

    // Generate random seeds
    // SK = (SK.seed || SK.prf || PK.seed || PK.root)
    // PK = (PK.seed || PK.root)

    byte sk_seed[N];
    byte sk_prf[N];
    byte pub_seed[N];

    rng.GenerateBlock(sk_seed, N);
    rng.GenerateBlock(sk_prf, N);
    rng.GenerateBlock(pub_seed, N);

    // Compute PK.root using hypertree
    byte pub_root[N];
    SLHDSA_Internal::ht_pk_gen<Hash, InternalParams>(pub_root, sk_seed, pub_seed);

    // Assemble secret key: SK.seed || SK.prf || PK.seed || PK.root
    std::memcpy(sk, sk_seed, N);
    std::memcpy(sk + N, sk_prf, N);
    std::memcpy(sk + 2 * N, pub_seed, N);
    std::memcpy(sk + 3 * N, pub_root, N);

    // Assemble public key: PK.seed || PK.root
    std::memcpy(pk, pub_seed, N);
    std::memcpy(pk + N, pub_root, N);

    // Zeroize secret seeds on stack
    SecureWipeBuffer(sk_seed, N);
    SecureWipeBuffer(sk_prf, N);
}

/// SLH-DSA Signing
/// Per FIPS 205 Algorithm 22 (slh_sign)
template <class PARAMS>
static void slh_sign(byte *sig, const byte *msg, size_t msg_len,
                     const byte *sk, RandomNumberGenerator &rng)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    typedef HashContext<PARAMS> Hash;

    constexpr unsigned int N = InternalParams::n;
    constexpr unsigned int K = InternalParams::fors_trees;
    constexpr unsigned int A = InternalParams::fors_height;
    constexpr unsigned int H = InternalParams::h;
    constexpr unsigned int D = InternalParams::d;
    constexpr unsigned int HP = InternalParams::hp;
    constexpr unsigned int LEN = InternalParams::wots_len;

    // Parse secret key
    const byte *sk_seed = sk;
    const byte *sk_prf = sk + N;
    const byte *pub_seed = sk + 2 * N;
    const byte *pub_root = sk + 3 * N;

    // Generate randomizer R
    byte opt_rand[N];
    rng.GenerateBlock(opt_rand, N);

    byte R[N];
    Hash::prf_msg(R, sk_prf, opt_rand, msg, msg_len);

    // Copy R to signature
    std::memcpy(sig, R, N);

    // Compute message digest
    // Per FIPS 205 Section 9.1, digest is byte-aligned:
    // m = ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    constexpr size_t FORS_MSG_BITS = K * A;
    constexpr size_t TREE_BITS = H - HP;
    constexpr size_t LEAF_BITS = HP;
    constexpr size_t FORS_MSG_BYTES = (FORS_MSG_BITS + 7) / 8;
    constexpr size_t TREE_BYTES = (TREE_BITS + 7) / 8;
    constexpr size_t LEAF_BYTES = (LEAF_BITS + 7) / 8;
    constexpr size_t DIGEST_LEN = FORS_MSG_BYTES + TREE_BYTES + LEAF_BYTES;

    byte digest[DIGEST_LEN];
    Hash::h_msg(digest, DIGEST_LEN, R, pub_seed, pub_root, msg, msg_len);

    // Extract FORS message (first k*a bits)
    // Extract tree index and leaf index
    uint64_t idx_tree;
    uint32_t idx_leaf;
    extract_indices<InternalParams>(idx_tree, idx_leaf, digest + FORS_MSG_BYTES);

    // FORS signature
    byte addr[ADDR_BYTES] = {0};
    SLHDSA_Internal::set_layer_addr(addr, 0);
    SLHDSA_Internal::set_tree_addr(addr, idx_tree);
    SLHDSA_Internal::set_type(addr, ADDR_TYPE_FORS_TREE);
    SLHDSA_Internal::set_keypair_addr(addr, idx_leaf);

    byte fors_pk[N];
    SLHDSA_Internal::fors_sign<Hash, InternalParams>(sig + N, fors_pk, digest,
                                                      sk_seed, pub_seed, addr);

    // Hypertree signature on FORS public key
    constexpr size_t FORS_SIG_SIZE = SLHDSA_Internal::fors_sig_size<InternalParams>();
    SLHDSA_Internal::ht_sign<Hash, InternalParams>(sig + N + FORS_SIG_SIZE, fors_pk,
                                                    sk_seed, pub_seed, idx_tree, idx_leaf);

    // Zeroize signing randomness on stack
    SecureWipeBuffer(opt_rand, N);
    SecureWipeBuffer(R, N);
}

/// SLH-DSA Verification
/// Per FIPS 205 Algorithm 23 (slh_verify)
template <class PARAMS>
static bool slh_verify(const byte *msg, size_t msg_len,
                       const byte *sig, const byte *pk)
{
    typedef typename ParamTraits<PARAMS>::Internal InternalParams;
    typedef HashContext<PARAMS> Hash;

    constexpr unsigned int N = InternalParams::n;
    constexpr unsigned int K = InternalParams::fors_trees;
    constexpr unsigned int A = InternalParams::fors_height;
    constexpr unsigned int H = InternalParams::h;
    constexpr unsigned int D = InternalParams::d;
    constexpr unsigned int HP = InternalParams::hp;

    // Parse public key
    const byte *pub_seed = pk;
    const byte *pub_root = pk + N;

    // Parse signature
    const byte *R = sig;

    // Compute message digest
    // Per FIPS 205 Section 9.1, digest is byte-aligned:
    // m = ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    constexpr size_t FORS_MSG_BITS = K * A;
    constexpr size_t TREE_BITS = H - HP;
    constexpr size_t LEAF_BITS = HP;
    constexpr size_t FORS_MSG_BYTES = (FORS_MSG_BITS + 7) / 8;
    constexpr size_t TREE_BYTES = (TREE_BITS + 7) / 8;
    constexpr size_t LEAF_BYTES = (LEAF_BITS + 7) / 8;
    constexpr size_t DIGEST_LEN = FORS_MSG_BYTES + TREE_BYTES + LEAF_BYTES;

    byte digest[DIGEST_LEN];
    Hash::h_msg(digest, DIGEST_LEN, R, pub_seed, pub_root, msg, msg_len);

    // Extract indices
    uint64_t idx_tree;
    uint32_t idx_leaf;
    extract_indices<InternalParams>(idx_tree, idx_leaf, digest + FORS_MSG_BYTES);

    // Verify FORS signature
    byte addr[ADDR_BYTES] = {0};
    SLHDSA_Internal::set_layer_addr(addr, 0);
    SLHDSA_Internal::set_tree_addr(addr, idx_tree);
    SLHDSA_Internal::set_type(addr, ADDR_TYPE_FORS_TREE);
    SLHDSA_Internal::set_keypair_addr(addr, idx_leaf);

    constexpr size_t FORS_SIG_SIZE = SLHDSA_Internal::fors_sig_size<InternalParams>();
    const byte *fors_sig = sig + N;

    byte fors_pk[N];
    SLHDSA_Internal::fors_pk_from_sig<Hash, InternalParams>(fors_pk, fors_sig, digest,
                                                             pub_seed, addr);

    // Verify hypertree signature
    const byte *ht_sig = sig + N + FORS_SIG_SIZE;
    return SLHDSA_Internal::ht_verify<Hash, InternalParams>(fors_pk, ht_sig,
                                                             pub_seed, pub_root,
                                                             idx_tree, idx_leaf);
}

} // anonymous namespace

// ******************** SLHDSAPrivateKey Implementation ************************* //

template <class PARAMS>
bool SLHDSAPrivateKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    // Basic validation: check key sizes
    return m_sk.size() == SECRET_KEYLENGTH && m_pk.size() == PUBLIC_KEYLENGTH;
}

template <class PARAMS>
bool SLHDSAPrivateKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void SLHDSAPrivateKey<PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void SLHDSAPrivateKey<PARAMS>::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);

    // Generate keys per FIPS 205 Algorithm 21
    slh_keygen<PARAMS>(m_sk.begin(), m_pk.begin(), rng);
}

template <class PARAMS>
void SLHDSAPrivateKey<PARAMS>::SetPrivateKey(const byte *key, size_t len)
{
    if (len != SECRET_KEYLENGTH)
        throw InvalidArgument("SLHDSAPrivateKey: invalid key length");

    std::memcpy(m_sk.begin(), key, SECRET_KEYLENGTH);
    // Extract public key from secret key (last 2n bytes)
    std::memcpy(m_pk.begin(), key + SECRET_KEYLENGTH - PUBLIC_KEYLENGTH, PUBLIC_KEYLENGTH);
}

template <class PARAMS>
void SLHDSAPrivateKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
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
void SLHDSAPrivateKey<PARAMS>::BERDecode(BufferedTransformation &bt)
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

// ******************** SLHDSAPublicKey Implementation ************************* //

template <class PARAMS>
bool SLHDSAPublicKey<PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    return m_pk.size() == PUBLIC_KEYLENGTH;
}

template <class PARAMS>
bool SLHDSAPublicKey<PARAMS>::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class PARAMS>
void SLHDSAPublicKey<PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class PARAMS>
void SLHDSAPublicKey<PARAMS>::SetPublicKey(const byte *key, size_t len)
{
    if (len != PUBLIC_KEYLENGTH)
        throw InvalidArgument("SLHDSAPublicKey: invalid key length");

    std::memcpy(m_pk.begin(), key, PUBLIC_KEYLENGTH);
}

template <class PARAMS>
void SLHDSAPublicKey<PARAMS>::DEREncode(BufferedTransformation &bt) const
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
void SLHDSAPublicKey<PARAMS>::BERDecode(BufferedTransformation &bt)
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

// ******************** SLHDSASigner Implementation ************************* //

template <class PARAMS>
SLHDSASigner<PARAMS>::SLHDSASigner(RandomNumberGenerator &rng)
{
    m_key.GenerateRandom(rng, g_nullNameValuePairs);
}

template <class PARAMS>
SLHDSASigner<PARAMS>::SLHDSASigner(const byte *privateKey, size_t privateKeyLen)
{
    m_key.SetPrivateKey(privateKey, privateKeyLen);
}

template <class PARAMS>
size_t SLHDSASigner<PARAMS>::SignAndRestart(RandomNumberGenerator &rng,
    PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart) const
{
    MessageAccumulatorType& accum = static_cast<MessageAccumulatorType&>(messageAccumulator);

    // Get the accumulated message
    const byte *msg = accum.data();
    size_t msg_len = accum.size();

    // Sign per FIPS 205 Algorithm 22
    slh_sign<PARAMS>(signature, msg, msg_len,
                     m_key.GetPrivateKeyBytePtr(), rng);

    if (restart)
        accum.Restart();

    return SIGNATURE_LENGTH;
}

// ******************** SLHDSAVerifier Implementation ************************* //

template <class PARAMS>
SLHDSAVerifier<PARAMS>::SLHDSAVerifier(const byte *publicKey, size_t publicKeyLen)
{
    m_key.SetPublicKey(publicKey, publicKeyLen);
}

template <class PARAMS>
SLHDSAVerifier<PARAMS>::SLHDSAVerifier(const SLHDSASigner<PARAMS> &signer)
{
    m_key.SetPublicKey(signer.GetKey().GetPublicKeyBytePtr(), PUBLIC_KEYLENGTH);
}

template <class PARAMS>
bool SLHDSAVerifier<PARAMS>::VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const
{
    MessageAccumulatorType& accum = static_cast<MessageAccumulatorType&>(messageAccumulator);

    // Get the accumulated message and signature
    const byte *msg = accum.data();
    size_t msg_len = accum.size();
    const byte *sig = accum.signature();

    // Verify per FIPS 205 Algorithm 23
    bool result = slh_verify<PARAMS>(msg, msg_len, sig, m_key.GetPublicKeyBytePtr());

    accum.Restart();

    return result;
}

// ******************** Explicit Template Instantiations ************************* //

// Private Keys
template struct SLHDSAPrivateKey<SLHDSA_SHA2_128f>;
template struct SLHDSAPrivateKey<SLHDSA_SHA2_128s>;
template struct SLHDSAPrivateKey<SLHDSA_SHA2_192f>;
template struct SLHDSAPrivateKey<SLHDSA_SHA2_192s>;
template struct SLHDSAPrivateKey<SLHDSA_SHA2_256f>;
template struct SLHDSAPrivateKey<SLHDSA_SHA2_256s>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_128f>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_128s>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_192f>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_192s>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_256f>;
template struct SLHDSAPrivateKey<SLHDSA_SHAKE_256s>;

// Public Keys
template struct SLHDSAPublicKey<SLHDSA_SHA2_128f>;
template struct SLHDSAPublicKey<SLHDSA_SHA2_128s>;
template struct SLHDSAPublicKey<SLHDSA_SHA2_192f>;
template struct SLHDSAPublicKey<SLHDSA_SHA2_192s>;
template struct SLHDSAPublicKey<SLHDSA_SHA2_256f>;
template struct SLHDSAPublicKey<SLHDSA_SHA2_256s>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_128f>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_128s>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_192f>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_192s>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_256f>;
template struct SLHDSAPublicKey<SLHDSA_SHAKE_256s>;

// Signers
template struct SLHDSASigner<SLHDSA_SHA2_128f>;
template struct SLHDSASigner<SLHDSA_SHA2_128s>;
template struct SLHDSASigner<SLHDSA_SHA2_192f>;
template struct SLHDSASigner<SLHDSA_SHA2_192s>;
template struct SLHDSASigner<SLHDSA_SHA2_256f>;
template struct SLHDSASigner<SLHDSA_SHA2_256s>;
template struct SLHDSASigner<SLHDSA_SHAKE_128f>;
template struct SLHDSASigner<SLHDSA_SHAKE_128s>;
template struct SLHDSASigner<SLHDSA_SHAKE_192f>;
template struct SLHDSASigner<SLHDSA_SHAKE_192s>;
template struct SLHDSASigner<SLHDSA_SHAKE_256f>;
template struct SLHDSASigner<SLHDSA_SHAKE_256s>;

// Verifiers
template struct SLHDSAVerifier<SLHDSA_SHA2_128f>;
template struct SLHDSAVerifier<SLHDSA_SHA2_128s>;
template struct SLHDSAVerifier<SLHDSA_SHA2_192f>;
template struct SLHDSAVerifier<SLHDSA_SHA2_192s>;
template struct SLHDSAVerifier<SLHDSA_SHA2_256f>;
template struct SLHDSAVerifier<SLHDSA_SHA2_256s>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_128f>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_128s>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_192f>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_192s>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_256f>;
template struct SLHDSAVerifier<SLHDSA_SHAKE_256s>;

NAMESPACE_END
