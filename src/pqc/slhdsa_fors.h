// slhdsa_fors.h - written and placed in the public domain by Colin Brown
//                 FORS few-time signature for SLH-DSA (FIPS 205 Section 6)
//                 Based on SPHINCS+ reference implementation (public domain)

#ifndef CRYPTOPP_SLHDSA_FORS_H
#define CRYPTOPP_SLHDSA_FORS_H

#include "slhdsa_internal.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(SLHDSA_Internal)

// ******************** FORS Implementation ************************* //
// Per FIPS 205 Section 6
//
// FORS (Forest of Random Subsets) is a few-time signature scheme.
// It uses k binary trees of height a. Each signature reveals one
// leaf per tree, selected based on the message digest.

/// Generate a FORS secret key element
/// Per FIPS 205 Algorithm 10 (fors_SKgen)
/// Returns the idx-th secret key value
template <class HASH_CTX, class PARAMS>
void fors_sk_gen(byte *sk, const byte *sk_seed,
                        const byte *pub_seed, byte *addr, uint32_t idx)
{
    constexpr unsigned int N = PARAMS::n;

    // Set address for FORS PRF
    // Per FIPS 205 Algorithm 10: setTypeAndClear, then restore keypair
    byte sk_addr[ADDR_BYTES];
    std::memcpy(sk_addr, addr, ADDR_BYTES);
    set_type(sk_addr, ADDR_TYPE_FORSPRF);
    copy_keypair_addr(sk_addr, addr);
    set_tree_index(sk_addr, idx);

    // sk = PRF(PK.seed, SK.seed, ADRS)
    HASH_CTX::prf(sk, pub_seed, sk_seed, sk_addr);
}

/// Compute a node in a FORS tree
/// Per FIPS 205 Algorithm 11 (fors_node)
/// Computes the root of the subtree of height 'height' starting at 'node_idx'
template <class HASH_CTX, class PARAMS>
void fors_treehash(byte *node, const byte *sk_seed,
                          const byte *pub_seed, byte *addr,
                          uint32_t start_idx, uint32_t target_height)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int A = PARAMS::fors_height;

    // Stack for tree computation
    // Maximum stack depth is target_height + 1
    byte stack[(A + 1) * N];
    unsigned int stack_offset = 0;

    // Process leaves left to right
    uint32_t num_leaves = 1u << target_height;

    for (uint32_t i = 0; i < num_leaves; i++) {
        uint32_t leaf_idx = start_idx + i;

        // Generate leaf: F(PK.seed, ADRS, sk[leaf_idx])
        byte sk[N];
        fors_sk_gen<HASH_CTX, PARAMS>(sk, sk_seed, pub_seed, addr, leaf_idx);

        // Hash the secret key to get leaf
        // FIPS 205 Algorithm 11: type stays FORS_TREE, no setTypeAndClear
        byte leaf[N];
        set_tree_height(addr, 0);
        set_tree_index(addr, leaf_idx);
        HASH_CTX::thash_f(leaf, sk, pub_seed, addr);

        SecureWipeBuffer(sk, N);

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

/// Generate FORS signature and compute public key
/// Per FIPS 205 Algorithm 12 (fors_sign)
/// msg is the message digest of length ceil(k*a/8) bytes
template <class HASH_CTX, class PARAMS>
void fors_sign(byte *sig, byte *pk, const byte *msg,
               const byte *sk_seed, const byte *pub_seed, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int K = PARAMS::fors_trees;
    constexpr unsigned int A = PARAMS::fors_height;

    // Each FORS tree has 2^a leaves
    // We sign k values, one from each tree
    // Signature = k * (sk_value + a * auth_path_node) = k * (1 + a) * n bytes

    byte roots[K * N];  // Collect tree roots for public key computation

    // Process each FORS tree
    unsigned int sig_offset = 0;
    unsigned int msg_bit_offset = 0;

    for (unsigned int i = 0; i < K; i++) {
        // Extract a-bit index from message digest
        uint32_t idx = 0;
        for (unsigned int j = 0; j < A; j++) {
            unsigned int byte_idx = msg_bit_offset / 8;
            unsigned int bit_idx = msg_bit_offset % 8;
            idx |= ((msg[byte_idx] >> (7 - bit_idx)) & 1) << (A - 1 - j);
            msg_bit_offset++;
        }

        // Compute the base index for this tree
        uint32_t tree_base = i * (1u << A);
        uint32_t leaf_idx = tree_base + idx;

        // Generate and output the secret key value
        fors_sk_gen<HASH_CTX, PARAMS>(sig + sig_offset, sk_seed, pub_seed, addr, leaf_idx);
        sig_offset += N;

        // Generate authentication path
        // For each level, output the sibling node
        for (unsigned int h = 0; h < A; h++) {
            // Compute sibling subtree index (XOR flips the bit at height h)
            uint32_t sibling_idx = (tree_base + (idx ^ (1u << h))) >> h;

            // Compute the sibling subtree root at height h
            uint32_t subtree_start = (sibling_idx << h);
            fors_treehash<HASH_CTX, PARAMS>(sig + sig_offset, sk_seed, pub_seed,
                                             addr, subtree_start, h);
            sig_offset += N;
        }

        // Compute the root of this FORS tree for public key
        fors_treehash<HASH_CTX, PARAMS>(roots + i * N, sk_seed, pub_seed,
                                         addr, tree_base, A);
    }

    // Compute FORS public key: T_k(PK.seed, ADRS, roots)
    // Per FIPS 205 Algorithm 12: setTypeAndClear, then restore keypair
    byte saved_keypair[4];
    std::memcpy(saved_keypair, addr + ADDR_KEYPAIR_OFFSET, 4);
    set_type(addr, ADDR_TYPE_FORSPK);
    std::memcpy(addr + ADDR_KEYPAIR_OFFSET, saved_keypair, 4);
    HASH_CTX::thash_tl(pk, roots, K, pub_seed, addr);
}

/// Compute FORS public key from signature
/// Per FIPS 205 Algorithm 13 (fors_pkFromSig)
template <class HASH_CTX, class PARAMS>
void fors_pk_from_sig(byte *pk, const byte *sig, const byte *msg,
                      const byte *pub_seed, byte *addr)
{
    constexpr unsigned int N = PARAMS::n;
    constexpr unsigned int K = PARAMS::fors_trees;
    constexpr unsigned int A = PARAMS::fors_height;

    byte roots[K * N];  // Collect computed roots
    unsigned int sig_offset = 0;
    unsigned int msg_bit_offset = 0;

    for (unsigned int i = 0; i < K; i++) {
        // Extract a-bit index from message digest
        uint32_t idx = 0;
        for (unsigned int j = 0; j < A; j++) {
            unsigned int byte_idx = msg_bit_offset / 8;
            unsigned int bit_idx = msg_bit_offset % 8;
            idx |= ((msg[byte_idx] >> (7 - bit_idx)) & 1) << (A - 1 - j);
            msg_bit_offset++;
        }

        uint32_t tree_base = i * (1u << A);
        uint32_t node_idx = tree_base + idx;

        // Get secret key from signature and compute leaf
        // FIPS 205 Algorithm 13: type stays FORS_TREE, no setTypeAndClear
        byte leaf[N];
        set_tree_height(addr, 0);
        set_tree_index(addr, node_idx);
        HASH_CTX::thash_f(leaf, sig + sig_offset, pub_seed, addr);
        sig_offset += N;

        // Compute root using authentication path
        byte node[N];
        std::memcpy(node, leaf, N);

        for (unsigned int h = 0; h < A; h++) {
            // Get sibling from auth path
            const byte *sibling = sig + sig_offset;
            sig_offset += N;

            // Compute parent index (absolute index in the combined tree)
            node_idx >>= 1;

            set_tree_height(addr, h + 1);
            set_tree_index(addr, node_idx);

            // Combine nodes - check if we're left or right child
            byte combined[2 * N];
            if ((idx >> h) & 1) {
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

        // Store this tree's root
        std::memcpy(roots + i * N, node, N);
    }

    // Compute FORS public key from roots
    // Per FIPS 205 Algorithm 13: setTypeAndClear, then restore keypair
    byte saved_keypair[4];
    std::memcpy(saved_keypair, addr + ADDR_KEYPAIR_OFFSET, 4);
    set_type(addr, ADDR_TYPE_FORSPK);
    std::memcpy(addr + ADDR_KEYPAIR_OFFSET, saved_keypair, 4);
    HASH_CTX::thash_tl(pk, roots, K, pub_seed, addr);
}

/// Compute the size of a FORS signature
template <class PARAMS>
static constexpr size_t fors_sig_size()
{
    // k trees, each contributes: 1 secret value + a auth path nodes
    return PARAMS::fors_trees * (1 + PARAMS::fors_height) * PARAMS::n;
}

/// Compute the size of the message digest used by FORS
template <class PARAMS>
static constexpr size_t fors_msg_size()
{
    // k * a bits = ceil(k * a / 8) bytes
    return (PARAMS::fors_trees * PARAMS::fors_height + 7) / 8;
}

NAMESPACE_END  // SLHDSA_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_SLHDSA_FORS_H
