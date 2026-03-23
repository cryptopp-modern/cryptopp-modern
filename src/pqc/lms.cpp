// lms.cpp - written and placed in the public domain by Colin Brown
//           LMS/LM-OTS implementation (RFC 8554, NIST SP 800-208)
//           Stage 1: SHA-256 only. The implementation hardcodes SHA256
//           for all hash operations, matching the SHA256_M32 parameter sets.

#include <cryptopp/pch.h>
#include <cryptopp/sha.h>
#include <cryptopp/misc.h>
#include <cryptopp/secblock.h>

#include <cstring>

#include "lms_params.h"

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(LMS_Internal)

// ==================== LM-OTS Private Key Derivation ====================
// RFC 8554 Appendix A: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)

/// \brief Derive a single OTS chain private key element
/// \param out output buffer (n bytes)
/// \param I the 16-byte identifier
/// \param q the leaf index
/// \param i the chain index (0 to p-1)
/// \param SEED the secret seed (n bytes)
/// \param n hash output length
static void lmots_derive_chain_key(byte *out, const byte *I, uint32_t q,
                                   uint16_t i, const byte *SEED, unsigned int n)
{
    SHA256 hash;
    byte buf4[4], buf2[2], buf1[1];

    hash.Update(I, 16);
    u32str(buf4, q);
    hash.Update(buf4, 4);
    u16str(buf2, i);
    hash.Update(buf2, 2);
    u8str(buf1, 0xff);
    hash.Update(buf1, 1);
    hash.Update(SEED, n);
    hash.TruncatedFinal(out, n);
}

// ==================== Winternitz Chain Iteration ====================
// RFC 8554 Section 4.4: tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)

/// \brief Apply one step of the Winternitz hash chain
/// \param tmp in/out buffer (n bytes), modified in place
/// \param I the 16-byte identifier
/// \param q the leaf index
/// \param i the chain index
/// \param j the iteration index
/// \param n hash output length
static void lmots_chain_step(byte *tmp, const byte *I, uint32_t q,
                             uint16_t i, uint8_t j, unsigned int n)
{
    SHA256 hash;
    byte buf4[4], buf2[2], buf1[1];

    hash.Update(I, 16);
    u32str(buf4, q);
    hash.Update(buf4, 4);
    u16str(buf2, i);
    hash.Update(buf2, 2);
    u8str(buf1, j);
    hash.Update(buf1, 1);
    hash.Update(tmp, n);
    hash.TruncatedFinal(tmp, n);
}

/// \brief Apply multiple steps of the Winternitz hash chain
/// \param tmp in/out buffer (n bytes)
/// \param I the 16-byte identifier
/// \param q the leaf index
/// \param i the chain index
/// \param startJ starting iteration
/// \param steps number of iterations to apply
/// \param n hash output length
static void lmots_chain(byte *tmp, const byte *I, uint32_t q,
                        uint16_t i, unsigned int startJ, unsigned int steps,
                        unsigned int n)
{
    for (unsigned int j = startJ; j < startJ + steps; j++)
        lmots_chain_step(tmp, I, q, i, static_cast<uint8_t>(j), n);
}

// ==================== LM-OTS Public Key Computation ====================
// RFC 8554 Algorithm 4b (generating K from private key)
// K = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
// where z[i] = chain(x[i], 0, 2^w - 1)

void lmots_compute_public_key(byte *K, const byte *I, uint32_t q,
                              const byte *SEED, const OTSParams &params)
{
    const unsigned int n = params.n;
    const unsigned int p = params.p;
    const unsigned int maxJ = (1u << params.w) - 1;

    // Compute the hash: H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
    SHA256 final_hash;
    byte buf4[4], buf2[2];

    final_hash.Update(I, 16);
    u32str(buf4, q);
    final_hash.Update(buf4, 4);
    u16str(buf2, D_PBLC);
    final_hash.Update(buf2, 2);

    SecByteBlock tmp(n);
    for (unsigned int i = 0; i < p; i++)
    {
        // Derive x[i] = chain private key element
        lmots_derive_chain_key(tmp, I, q, static_cast<uint16_t>(i), SEED, n);
        // Chain from 0 to 2^w - 1
        lmots_chain(tmp, I, q, static_cast<uint16_t>(i), 0, maxJ, n);
        final_hash.Update(tmp, n);
    }
    final_hash.TruncatedFinal(K, n);

    SecureWipeBuffer(tmp, n);
}

// ==================== LM-OTS Signing ====================
// RFC 8554 Algorithm 3

void lmots_sign(byte *sig, const byte *message, size_t messageLen,
                const byte *I, uint32_t q, const byte *SEED,
                const byte *C, const OTSParams &params)
{
    const unsigned int n = params.n;
    const unsigned int p = params.p;
    const unsigned int w = params.w;
    const unsigned int ls = params.ls;
    const unsigned int u = params.u;

    // Step 1: Encode OTS type in signature
    u32str(sig, params.type_id);
    byte *sig_C = sig + 4;
    byte *sig_y = sig + 4 + n;

    // Step 2: Copy C (randomiser) into signature
    std::memcpy(sig_C, C, n);

    // Step 3: Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    SecByteBlock Q(n);
    {
        SHA256 hash;
        byte buf4[4], buf2[2];
        hash.Update(I, 16);
        u32str(buf4, q);
        hash.Update(buf4, 4);
        u16str(buf2, D_MESG);
        hash.Update(buf2, 2);
        hash.Update(C, n);
        hash.Update(message, messageLen);
        hash.TruncatedFinal(Q, n);
    }

    // Step 4: Compute checksum and append to Q
    byte cksm_bytes[2];
    u16str(cksm_bytes, checksum(Q, w, ls, u));

    // Build Q || Cksm for coefficient extraction
    SecByteBlock Q_cksm(n + 2);
    std::memcpy(Q_cksm, Q, n);
    std::memcpy(Q_cksm + n, cksm_bytes, 2);

    // Step 5: For each chain, derive private key and iterate
    SecByteBlock tmp(n);
    for (unsigned int i = 0; i < p; i++)
    {
        unsigned int a = coef(Q_cksm, i, w);

        // Derive x[i]
        lmots_derive_chain_key(tmp, I, q, static_cast<uint16_t>(i), SEED, n);
        // Chain from 0 to a
        lmots_chain(tmp, I, q, static_cast<uint16_t>(i), 0, a, n);
        // Write y[i] to signature
        std::memcpy(sig_y + static_cast<size_t>(i) * n, tmp, n);
    }

    SecureWipeBuffer(tmp, n);
    SecureWipeBuffer(Q, n);
    SecureWipeBuffer(Q_cksm, Q_cksm.size());
}

// ==================== LM-OTS Candidate Key from Signature ====================
// RFC 8554 Algorithm 4a

void lmots_compute_candidate_key(byte *Kc, const byte *sig,
                                 const byte *message, size_t messageLen,
                                 const byte *I, uint32_t q,
                                 const OTSParams &params)
{
    const unsigned int n = params.n;
    const unsigned int p = params.p;
    const unsigned int w = params.w;
    const unsigned int ls = params.ls;
    const unsigned int u = params.u;
    const unsigned int maxJ = (1u << w) - 1;

    // Parse signature: type(4) + C(n) + y[0..p-1](p*n)
    const byte *sig_C = sig + 4;
    const byte *sig_y = sig + 4 + n;

    // Step 1: Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    SecByteBlock Q(n);
    {
        SHA256 hash;
        byte buf4[4], buf2[2];
        hash.Update(I, 16);
        u32str(buf4, q);
        hash.Update(buf4, 4);
        u16str(buf2, D_MESG);
        hash.Update(buf2, 2);
        hash.Update(sig_C, n);
        hash.Update(message, messageLen);
        hash.TruncatedFinal(Q, n);
    }

    // Step 2: Compute checksum
    byte cksm_bytes[2];
    u16str(cksm_bytes, checksum(Q, w, ls, u));

    SecByteBlock Q_cksm(n + 2);
    std::memcpy(Q_cksm, Q, n);
    std::memcpy(Q_cksm + n, cksm_bytes, 2);

    // Step 3: Compute z[i] and hash into Kc
    // Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
    SHA256 final_hash;
    byte buf4[4], buf2[2];

    final_hash.Update(I, 16);
    u32str(buf4, q);
    final_hash.Update(buf4, 4);
    u16str(buf2, D_PBLC);
    final_hash.Update(buf2, 2);

    SecByteBlock tmp(n);
    for (unsigned int i = 0; i < p; i++)
    {
        unsigned int a = coef(Q_cksm, i, w);

        // Copy y[i] from signature
        std::memcpy(tmp, sig_y + static_cast<size_t>(i) * n, n);
        // Chain from a to 2^w - 1
        lmots_chain(tmp, I, q, static_cast<uint16_t>(i), a, maxJ - a, n);
        final_hash.Update(tmp, n);
    }
    final_hash.TruncatedFinal(Kc, n);

    SecureWipeBuffer(tmp, n);
    SecureWipeBuffer(Q, n);
    SecureWipeBuffer(Q_cksm, Q_cksm.size());
}

// ==================== LMS Merkle Tree ====================

/// \brief Compute LMS leaf node hash
/// \details leaf = H(I || u32str(r) || u16str(D_LEAF) || K)
///  where r = node number = 2^h + q, K = OTS public key for leaf q
static void lms_leaf_hash(byte *out, const byte *I, uint32_t r,
                          const byte *K, unsigned int m)
{
    SHA256 hash;
    byte buf4[4], buf2[2];

    hash.Update(I, 16);
    u32str(buf4, r);
    hash.Update(buf4, 4);
    u16str(buf2, D_LEAF);
    hash.Update(buf2, 2);
    hash.Update(K, m);
    hash.TruncatedFinal(out, m);
}

/// \brief Compute LMS internal node hash
/// \details node = H(I || u32str(r) || u16str(D_INTR) || left || right)
static void lms_interior_hash(byte *out, const byte *I, uint32_t r,
                              const byte *left, const byte *right,
                              unsigned int m)
{
    SHA256 hash;
    byte buf4[4], buf2[2];

    hash.Update(I, 16);
    u32str(buf4, r);
    hash.Update(buf4, 4);
    u16str(buf2, D_INTR);
    hash.Update(buf2, 2);
    hash.Update(left, m);
    hash.Update(right, m);
    hash.TruncatedFinal(out, m);
}

/// \brief Compute the full LMS Merkle tree
/// \param tree output buffer for all 2^(h+1) nodes, each m bytes.
///  tree[0] is unused. tree[1] is the root. tree[2^h .. 2^(h+1)-1] are leaves.
/// \param I the 16-byte identifier
/// \param SEED the secret seed
/// \param lmsParams LMS parameter set
/// \param otsParams LM-OTS parameter set
/// \details Stage 1 simplification: computes and stores the full tree.
///  This is acceptable for H5 (32 leaves) and H10 (1024 leaves) but
///  must be replaced with incremental traversal for larger heights.
void lms_compute_full_tree(byte *tree, const byte *I, const byte *SEED,
                           const LMSParams &lmsParams, const OTSParams &otsParams)
{
    const unsigned int h = lmsParams.h;
    const unsigned int m = lmsParams.m;
    const uint32_t numLeaves = 1u << h;

    // Compute leaf nodes: tree[2^h + q] = H(I || u32str(2^h + q) || D_LEAF || K_q)
    SecByteBlock K(m);
    for (uint32_t q = 0; q < numLeaves; q++)
    {
        lmots_compute_public_key(K, I, q, SEED, otsParams);
        lms_leaf_hash(tree + static_cast<size_t>(numLeaves + q) * m,
                      I, numLeaves + q, K, m);
    }
    SecureWipeBuffer(K, m);

    // Compute interior nodes bottom-up
    for (uint32_t r = numLeaves - 1; r >= 1; r--)
    {
        lms_interior_hash(tree + static_cast<size_t>(r) * m, I, r,
                          tree + static_cast<size_t>(2 * r) * m,
                          tree + static_cast<size_t>(2 * r + 1) * m, m);
    }
}

/// \brief Extract the authentication path for leaf q from a precomputed tree
/// \param path output buffer (h * m bytes)
/// \param tree the full precomputed tree
/// \param q the leaf index
/// \param lmsParams LMS parameter set
void lms_extract_auth_path(byte *path, const byte *tree, uint32_t q,
                           const LMSParams &lmsParams)
{
    const unsigned int h = lmsParams.h;
    const unsigned int m = lmsParams.m;
    const uint32_t numLeaves = 1u << h;

    // Walk from leaf to root, collecting sibling hashes
    uint32_t node = numLeaves + q;
    for (unsigned int level = 0; level < h; level++)
    {
        uint32_t sibling = node ^ 1;  // XOR with 1 gives sibling
        std::memcpy(path + static_cast<size_t>(level) * m,
                    tree + static_cast<size_t>(sibling) * m, m);
        node = node / 2;  // move to parent
    }
}

/// \brief Verify an LMS authentication path against a known root
/// \param candidateLeaf the candidate leaf hash (m bytes)
/// \param path the authentication path (h * m bytes)
/// \param q the leaf index
/// \param root the known tree root (m bytes, T[1])
/// \param I the 16-byte identifier
/// \param lmsParams LMS parameter set
/// \return true if the candidate root matches the known root
bool lms_verify_path(const byte *candidateLeaf, const byte *path,
                     uint32_t q, const byte *root, const byte *I,
                     const LMSParams &lmsParams)
{
    const unsigned int h = lmsParams.h;
    const unsigned int m = lmsParams.m;
    const uint32_t numLeaves = 1u << h;

    SecByteBlock tmp(m);
    std::memcpy(tmp, candidateLeaf, m);

    uint32_t node = numLeaves + q;
    for (unsigned int level = 0; level < h; level++)
    {
        const byte *sibling = path + static_cast<size_t>(level) * m;
        uint32_t parent = node / 2;

        if (node % 2 == 0)
        {
            // node is left child
            lms_interior_hash(tmp, I, parent, tmp, sibling, m);
        }
        else
        {
            // node is right child
            lms_interior_hash(tmp, I, parent, sibling, tmp, m);
        }
        node = parent;
    }

    // Constant-time comparison with known root
    return VerifyBufsEqual(tmp, root, m);
}

NAMESPACE_END  // LMS_Internal
NAMESPACE_END  // CryptoPP
