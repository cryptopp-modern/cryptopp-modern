// slhdsa_hypertree.h - written and placed in the public domain by Colin Brown
//                      Hypertree and XMSS for SLH-DSA (FIPS 205 Section 7)
//                      Based on SPHINCS+ reference implementation (public domain)

#ifndef CRYPTOPP_SLHDSA_HYPERTREE_H
#define CRYPTOPP_SLHDSA_HYPERTREE_H

#include "slhdsa_internal.h"
#include "slhdsa_wots.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(SLHDSA_Internal)

// ******************** XMSS Implementation ************************* //
// Per FIPS 205 Section 7.1-7.2

/// Compute a node in an XMSS tree using treehash
/// Per FIPS 205 Algorithm 14 (xmss_node)
/// Computes the root of a subtree of height 'target_height' starting at 'start_idx'
template <class HASH_CTX, class PARAMS>
static void xmss_treehash(byte *node, const byte *sk_seed,
                          const byte *pub_seed, uint32_t start_idx,
                          uint32_t target_height, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int HP = PARAMS::hp;  // XMSS tree height
    constexpr unsigned int LEN = PARAMS::wots_len;

    // Stack for tree computation
    byte stack[(HP + 1) * N];
    unsigned int stack_offset = 0;

    // Process leaves left to right
    uint32_t num_leaves = 1u << target_height;

    for (uint32_t i = 0; i < num_leaves; i++) {
        uint32_t leaf_idx = start_idx + i;

        // Generate WOTS+ public key (leaf node)
        byte wots_pk[LEN * N];
        set_type(addr, ADDR_TYPE_WOTS);
        set_keypair_addr(addr, leaf_idx);
        wots_pk_gen<HASH_CTX, PARAMS>(wots_pk, sk_seed, pub_seed, addr);

        // Compress WOTS+ pk to leaf
        byte leaf[N];
        set_type(addr, ADDR_TYPE_WOTSPK);
        set_keypair_addr(addr, leaf_idx);
        HASH_CTX::thash_tl(leaf, wots_pk, LEN, pub_seed, addr);

        // Push leaf onto stack
        std::memcpy(stack + stack_offset * N, leaf, N);
        stack_offset++;

        // Compute internal nodes
        uint32_t tree_idx = leaf_idx;
        for (unsigned int h = 1; h <= target_height; h++) {
            // Check if we can combine nodes
            if ((tree_idx & 1) == 0) {
                // Left child - wait for right child
                break;
            }

            // Right child - combine with left sibling
            tree_idx = (tree_idx - 1) >> 1;

            set_type(addr, ADDR_TYPE_HASHTREE);
            set_tree_height(addr, h);
            set_tree_index(addr, tree_idx);

            // Combine: H(PK.seed, ADRS, left || right)
            byte combined[2 * N];
            std::memcpy(combined, stack + (stack_offset - 2) * N, N);
            std::memcpy(combined + N, stack + (stack_offset - 1) * N, N);

            stack_offset--;
            HASH_CTX::thash_h(stack + (stack_offset - 1) * N, combined, pub_seed, addr);
        }
    }

    // The result is at the bottom of the stack
    std::memcpy(node, stack, N);
}

/// Generate an XMSS signature and compute authentication path
/// Per FIPS 205 Algorithm 15 (xmss_sign)
template <class HASH_CTX, class PARAMS>
void xmss_sign(byte *sig, byte *root, const byte *msg,
               const byte *sk_seed, const byte *pub_seed,
               uint32_t leaf_idx, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int HP = PARAMS::hp;  // XMSS tree height
    constexpr unsigned int LEN = PARAMS::wots_len;

    // Generate WOTS+ signature
    set_type(addr, ADDR_TYPE_WOTS);
    set_keypair_addr(addr, leaf_idx);
    wots_sign<HASH_CTX, PARAMS>(sig, msg, sk_seed, pub_seed, addr);

    unsigned int sig_offset = LEN * N;  // After WOTS+ signature

    // Compute and store authentication path
    for (unsigned int h = 0; h < HP; h++) {
        // Compute sibling index at height h (XOR flips the bit)
        uint32_t sibling_idx = (leaf_idx >> h) ^ 1;

        // Compute the sibling subtree root at height h
        uint32_t subtree_start = sibling_idx << h;
        xmss_treehash<HASH_CTX, PARAMS>(sig + sig_offset, sk_seed, pub_seed,
                                         subtree_start, h, addr);
        sig_offset += N;
    }

    // Compute the tree root (for returning to caller)
    xmss_treehash<HASH_CTX, PARAMS>(root, sk_seed, pub_seed, 0, HP, addr);
}

/// Compute XMSS root from signature
/// Per FIPS 205 Algorithm 16 (xmss_PKFromSig)
template <class HASH_CTX, class PARAMS>
void xmss_pk_from_sig(byte *root, const byte *sig, const byte *msg,
                      const byte *pub_seed, uint32_t leaf_idx, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int HP = PARAMS::hp;
    constexpr unsigned int LEN = PARAMS::wots_len;

    // Compute WOTS+ public key from signature
    byte wots_pk[LEN * N];
    set_type(addr, ADDR_TYPE_WOTS);
    set_keypair_addr(addr, leaf_idx);
    wots_pk_from_sig<HASH_CTX, PARAMS>(wots_pk, sig, msg, pub_seed, addr);

    // Compress WOTS+ pk to leaf
    byte node[N];
    set_type(addr, ADDR_TYPE_WOTSPK);
    set_keypair_addr(addr, leaf_idx);
    HASH_CTX::thash_tl(node, wots_pk, LEN, pub_seed, addr);

    const byte *auth_path = sig + LEN * N;

    // Compute root using authentication path
    for (unsigned int h = 0; h < HP; h++) {
        const byte *sibling = auth_path + h * N;
        byte combined[2 * N];

        uint32_t parent_idx = leaf_idx >> (h + 1);

        set_type(addr, ADDR_TYPE_HASHTREE);
        set_tree_height(addr, h + 1);
        set_tree_index(addr, parent_idx);

        if ((leaf_idx >> h) & 1) {
            // We're on the right
            std::memcpy(combined, sibling, N);
            std::memcpy(combined + N, node, N);
        } else {
            // We're on the left
            std::memcpy(combined, node, N);
            std::memcpy(combined + N, sibling, N);
        }

        HASH_CTX::thash_h(node, combined, pub_seed, addr);
    }

    std::memcpy(root, node, N);
}

// ******************** Hypertree Implementation ************************* //
// Per FIPS 205 Section 7.3

/// Generate hypertree signature
/// Per FIPS 205 Algorithm 17 (ht_sign)
template <class HASH_CTX, class PARAMS>
void ht_sign(byte *sig, const byte *msg,
             const byte *sk_seed, const byte *pub_seed,
             uint64_t idx_tree, uint32_t idx_leaf)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int D = PARAMS::d;
    constexpr unsigned int HP = PARAMS::hp;
    constexpr unsigned int LEN = PARAMS::wots_len;

    // Size of one XMSS signature: WOTS+ sig + auth path
    constexpr unsigned int XMSS_SIG_SIZE = (LEN + HP) * N;

    byte addr[ADDR_BYTES] = {0};
    byte root[N];

    // Sign at layer 0
    set_layer_addr(addr, 0);
    set_tree_addr(addr, idx_tree);

    xmss_sign<HASH_CTX, PARAMS>(sig, root, msg, sk_seed, pub_seed, idx_leaf, addr);

    unsigned int sig_offset = XMSS_SIG_SIZE;

    // Sign at remaining layers
    for (unsigned int layer = 1; layer < D; layer++) {
        // Update tree and leaf indices for next layer
        idx_leaf = static_cast<uint32_t>(idx_tree & ((1u << HP) - 1));
        idx_tree >>= HP;

        set_layer_addr(addr, layer);
        set_tree_addr(addr, idx_tree);

        xmss_sign<HASH_CTX, PARAMS>(sig + sig_offset, root, root,
                                     sk_seed, pub_seed, idx_leaf, addr);
        sig_offset += XMSS_SIG_SIZE;
    }
}

/// Verify hypertree signature
/// Per FIPS 205 Algorithm 18 (ht_verify)
template <class HASH_CTX, class PARAMS>
bool ht_verify(const byte *msg, const byte *sig,
               const byte *pub_seed, const byte *pub_root,
               uint64_t idx_tree, uint32_t idx_leaf)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int D = PARAMS::d;
    constexpr unsigned int HP = PARAMS::hp;
    constexpr unsigned int LEN = PARAMS::wots_len;

    constexpr unsigned int XMSS_SIG_SIZE = (LEN + HP) * N;

    byte addr[ADDR_BYTES] = {0};
    byte node[N];

    // Verify at layer 0
    set_layer_addr(addr, 0);
    set_tree_addr(addr, idx_tree);

    xmss_pk_from_sig<HASH_CTX, PARAMS>(node, sig, msg, pub_seed, idx_leaf, addr);

    unsigned int sig_offset = XMSS_SIG_SIZE;

    // Verify at remaining layers
    for (unsigned int layer = 1; layer < D; layer++) {
        // Update indices for next layer
        idx_leaf = static_cast<uint32_t>(idx_tree & ((1u << HP) - 1));
        idx_tree >>= HP;

        set_layer_addr(addr, layer);
        set_tree_addr(addr, idx_tree);

        xmss_pk_from_sig<HASH_CTX, PARAMS>(node, sig + sig_offset, node,
                                            pub_seed, idx_leaf, addr);
        sig_offset += XMSS_SIG_SIZE;
    }

    // Compare computed root with public key root (constant-time)
    return VerifyBufsEqual(node, pub_root, N);
}

/// Compute hypertree public key (root)
/// Per FIPS 205: the public key root is the XMSS tree root at the top layer (D-1)
template <class HASH_CTX, class PARAMS>
void ht_pk_gen(byte *pub_root, const byte *sk_seed, const byte *pub_seed)
{
    constexpr unsigned int D = PARAMS::d;
    constexpr unsigned int HP = PARAMS::hp;

    byte addr[ADDR_BYTES] = {0};

    // Compute XMSS tree root at top layer (D-1), tree 0
    set_layer_addr(addr, D - 1);
    set_tree_addr(addr, 0);
    xmss_treehash<HASH_CTX, PARAMS>(pub_root, sk_seed, pub_seed, 0, HP, addr);
}

/// Compute the size of an XMSS signature
template <class PARAMS>
static constexpr size_t xmss_sig_size()
{
    // WOTS+ signature + authentication path
    return (PARAMS::wots_len + PARAMS::hp) * PARAMS::n;
}

/// Compute the size of a hypertree signature
template <class PARAMS>
static constexpr size_t ht_sig_size()
{
    // d XMSS signatures
    return PARAMS::d * xmss_sig_size<PARAMS>();
}

NAMESPACE_END  // SLHDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_SLHDSA_HYPERTREE_H
