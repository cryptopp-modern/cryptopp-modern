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

    SecureWipeBuffer(tmp.data(), tmp.size());
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

    SecureWipeBuffer(tmp.data(), tmp.size());
    SecureWipeBuffer(Q.data(), Q.size());
    SecureWipeBuffer(Q_cksm.data(), Q_cksm.size());
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

    SecureWipeBuffer(tmp.data(), tmp.size());
    SecureWipeBuffer(Q.data(), Q.size());
    SecureWipeBuffer(Q_cksm.data(), Q_cksm.size());
}

// ==================== LMS Merkle Tree ====================

/// \brief Compute LMS leaf node hash
/// \details leaf = H(I || u32str(r) || u16str(D_LEAF) || K)
///  where r = node number = 2^h + q, K = OTS public key for leaf q
void lms_leaf_hash(byte *out, const byte *I, uint32_t r,
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
void lms_interior_hash(byte *out, const byte *I, uint32_t r,
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
    SecureWipeBuffer(K.data(), K.size());

    // Compute interior nodes bottom-up
    for (uint32_t r = numLeaves; r-- > 1; )
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

// ==================== Template Implementations ====================
// These require the public header for template class definitions.

#include <cryptopp/lms.h>

NAMESPACE_BEGIN(CryptoPP)

namespace LMS_Internal {
    template <class OTS_PARAMS>
    inline OTSParams MakeOTSParams() {
        return OTSParams{OTS_PARAMS::TYPE_ID, OTS_PARAMS::N, OTS_PARAMS::W,
                         OTS_PARAMS::P, OTS_PARAMS::LS, OTS_PARAMS::U};
    }

    template <class LMS_PARAMS>
    inline LMSParams MakeLMSParams() {
        return LMSParams{LMS_PARAMS::TYPE_ID, LMS_PARAMS::M, LMS_PARAMS::H};
    }
}

// ******************** LMSPublicKey ************************* //

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::SetPublicKey(const byte *pk, size_t len)
{
    if (!pk || len != PUBLIC_KEY_SIZE)
        throw InvalidArgument("LMSPublicKey: invalid public key length");
    m_pk.Assign(pk, len);
}

template <class LMS_PARAMS, class OTS_PARAMS>
bool LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    if (m_pk.size() != PUBLIC_KEY_SIZE)
        return false;

    // Verify embedded type IDs match the parameter set
    using namespace LMS_Internal;
    uint32_t lmsType = (static_cast<uint32_t>(m_pk[0]) << 24) |
                       (static_cast<uint32_t>(m_pk[1]) << 16) |
                       (static_cast<uint32_t>(m_pk[2]) << 8) |
                       (static_cast<uint32_t>(m_pk[3]));
    uint32_t otsType = (static_cast<uint32_t>(m_pk[4]) << 24) |
                       (static_cast<uint32_t>(m_pk[5]) << 16) |
                       (static_cast<uint32_t>(m_pk[6]) << 8) |
                       (static_cast<uint32_t>(m_pk[7]));
    return lmsType == LMS_PARAMS::TYPE_ID && otsType == OTS_PARAMS::TYPE_ID;
}

template <class LMS_PARAMS, class OTS_PARAMS>
bool LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::GetVoidValue(
    const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name); CRYPTOPP_UNUSED(valueType); CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

// ******************** LMSPrivateKey ************************* //

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::SetPrivateKey(
    const byte *seed, size_t seedLen,
    const byte *identifier, size_t idLen)
{
    if (!seed || seedLen != SEED_SIZE)
        throw InvalidArgument("LMSPrivateKey: invalid seed length");
    if (!identifier || idLen != I_SIZE)
        throw InvalidArgument("LMSPrivateKey: invalid identifier length");
    m_seed.Assign(seed, seedLen);
    m_I.Assign(identifier, idLen);
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::GenerateRandom(
    RandomNumberGenerator &rng, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    m_seed.resize(SEED_SIZE);
    m_I.resize(I_SIZE);
    rng.GenerateBlock(m_seed, SEED_SIZE);
    rng.GenerateBlock(m_I, I_SIZE);
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::MakePublicKey(
    LMSPublicKey<LMS_PARAMS, OTS_PARAMS> &pub) const
{
    using namespace LMS_Internal;

    const OTSParams otsP = MakeOTSParams<OTS_PARAMS>();
    const LMSParams lmsP = MakeLMSParams<LMS_PARAMS>();

    const unsigned int m = LMS_PARAMS::M;
    const uint32_t numNodes = 2u * (1u << LMS_PARAMS::H);

    // Compute full tree
    SecByteBlock tree(static_cast<size_t>(numNodes) * m);
    lms_compute_full_tree(tree, m_I, m_seed, lmsP, otsP);

    // Build public key: LMS type(4) + OTS type(4) + I(16) + T[1](m)
    const size_t pkLen = 4 + 4 + 16 + m;
    SecByteBlock pkBuf(pkLen);
    u32str(pkBuf, LMS_PARAMS::TYPE_ID);
    u32str(pkBuf + 4, OTS_PARAMS::TYPE_ID);
    std::memcpy(pkBuf + 8, m_I, 16);
    std::memcpy(pkBuf + 24, tree + m, m);  // tree[1] = root

    pub.SetPublicKey(pkBuf, pkLen);

    SecureWipeBuffer(tree.data(), tree.size());
}

template <class LMS_PARAMS, class OTS_PARAMS>
bool LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::Validate(
    RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    return m_seed.size() == SEED_SIZE && m_I.size() == I_SIZE;
}

template <class LMS_PARAMS, class OTS_PARAMS>
bool LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::GetVoidValue(
    const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name); CRYPTOPP_UNUSED(valueType); CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

// ******************** LMSVerifier ************************* //

template <class LMS_PARAMS, class OTS_PARAMS>
LMSVerifier<LMS_PARAMS, OTS_PARAMS>::LMSVerifier(const byte *publicKey, size_t len)
{
    m_key.SetPublicKey(publicKey, len);
}

template <class LMS_PARAMS, class OTS_PARAMS>
bool LMSVerifier<LMS_PARAMS, OTS_PARAMS>::VerifyAndRestart(
    PK_MessageAccumulator &messageAccumulator) const
{
    using namespace LMS_Internal;

    MessageAccumulatorType &accum = static_cast<MessageAccumulatorType&>(messageAccumulator);

    const byte *sig = accum.signature();
    const byte *message = accum.data();
    const size_t messageLen = accum.size();
    const unsigned int m = LMS_PARAMS::M;
    const unsigned int h = LMS_PARAMS::H;

    const OTSParams otsP = MakeOTSParams<OTS_PARAMS>();
    const LMSParams lmsP = MakeLMSParams<LMS_PARAMS>();

    // Parse LMS signature: q(4) + OTS sig(ots_sig_len) + LMS type(4) + auth path(h*m)
    const size_t otsSigLen = otsP.SigLen();
    const size_t expectedSigLen = 4 + otsSigLen + 4 + static_cast<size_t>(h) * m;

    if (expectedSigLen != SIGNATURE_LENGTH)
    {
        accum.Restart();
        return false;
    }

    // Extract q
    const byte *sig_q = sig;
    uint32_t q = (static_cast<uint32_t>(sig_q[0]) << 24) |
                 (static_cast<uint32_t>(sig_q[1]) << 16) |
                 (static_cast<uint32_t>(sig_q[2]) << 8) |
                 (static_cast<uint32_t>(sig_q[3]));

    // Validate q is in range
    if (q >= static_cast<uint32_t>(1u << h))
    {
        accum.Restart();
        return false;
    }

    // Extract OTS signature, LMS type, auth path
    const byte *otsSig = sig + 4;
    const byte *sig_lmsType = sig + 4 + otsSigLen;
    const byte *authPath = sig + 4 + otsSigLen + 4;

    // Verify LMS type matches
    uint32_t sigLmsType = (static_cast<uint32_t>(sig_lmsType[0]) << 24) |
                          (static_cast<uint32_t>(sig_lmsType[1]) << 16) |
                          (static_cast<uint32_t>(sig_lmsType[2]) << 8) |
                          (static_cast<uint32_t>(sig_lmsType[3]));

    if (sigLmsType != LMS_PARAMS::TYPE_ID)
    {
        accum.Restart();
        return false;
    }

    // Verify OTS type in signature matches
    uint32_t sigOtsType = (static_cast<uint32_t>(otsSig[0]) << 24) |
                          (static_cast<uint32_t>(otsSig[1]) << 16) |
                          (static_cast<uint32_t>(otsSig[2]) << 8) |
                          (static_cast<uint32_t>(otsSig[3]));

    if (sigOtsType != OTS_PARAMS::TYPE_ID)
    {
        accum.Restart();
        return false;
    }

    // Compute candidate OTS public key from signature
    SecByteBlock Kc(m);
    lmots_compute_candidate_key(Kc, otsSig, message, messageLen,
                                m_key.GetI(), q, otsP);

    // Compute candidate leaf hash
    const uint32_t numLeaves = 1u << h;
    SecByteBlock candidateLeaf(m);
    lms_leaf_hash(candidateLeaf, m_key.GetI(), numLeaves + q, Kc, m);

    // Verify auth path against stored root
    bool result = lms_verify_path(candidateLeaf, authPath, q,
                                  m_key.GetRoot(), m_key.GetI(), lmsP);

    SecureWipeBuffer(Kc.data(), Kc.size());
    SecureWipeBuffer(candidateLeaf.data(), candidateLeaf.size());

    accum.Restart();
    return result;
}

// ******************** LMSSigner ************************* //

template <class LMS_PARAMS, class OTS_PARAMS>
LMSSigner<LMS_PARAMS, OTS_PARAMS>::LMSSigner(
    const PrivateKeyType &key, SignerStateStore &store)
    : m_key(key), m_store(&store)
{
    // Precompute the Merkle tree on first construction.
    // Stage 1 simplification: full tree stored in memory.
    using namespace LMS_Internal;

    const OTSParams otsP = MakeOTSParams<OTS_PARAMS>();
    const LMSParams lmsP = MakeLMSParams<LMS_PARAMS>();

    const unsigned int m = LMS_PARAMS::M;
    const uint32_t numNodes = 2u * (1u << LMS_PARAMS::H);

    m_tree.resize(static_cast<size_t>(numNodes) * m);
    lms_compute_full_tree(m_tree, key.GetIdentifierBytePtr(),
                          key.GetSeedBytePtr(), lmsP, otsP);
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSSigner<LMS_PARAMS, OTS_PARAMS>::SignMessage(
    RandomNumberGenerator &rng,
    const byte *message, size_t messageLen,
    byte *signature)
{
    if (!signature)
        throw InvalidArgument(AlgorithmName() + ": signature buffer is null");
    if (!message && messageLen > 0)
        throw InvalidArgument(AlgorithmName() + ": message is null with non-zero length");

    using namespace LMS_Internal;

    const OTSParams otsP = MakeOTSParams<OTS_PARAMS>();
    const LMSParams lmsP = MakeLMSParams<LMS_PARAMS>();

    const unsigned int n = OTS_PARAMS::N;
    const unsigned int m = LMS_PARAMS::M;
    const unsigned int h = LMS_PARAMS::H;

    // Reserve (authoritative safety boundary)
    StateReservation reservation = m_store->ReserveNext();
    uint32_t q = static_cast<uint32_t>(reservation.LeafIndex());

    CRYPTOPP_ASSERT(q < (1u << LMS_PARAMS::H));

    try
    {
        // Generate randomiser C
        SecByteBlock C(n);
        rng.GenerateBlock(C, n);

        // Build LMS signature: q(4) + OTS_sig + LMS_type(4) + auth_path(h*m)
        // Step 1: q
        u32str(signature, q);

        // Step 2: OTS signature at offset 4
        byte *otsSigPos = signature + 4;
        lmots_sign(otsSigPos, message, messageLen,
                   m_key.GetIdentifierBytePtr(), q,
                   m_key.GetSeedBytePtr(), C, otsP);

        // Step 3: LMS type at offset 4 + otsSigLen
        const size_t otsSigLen = otsP.SigLen();
        u32str(signature + 4 + otsSigLen, LMS_PARAMS::TYPE_ID);

        // Step 4: Auth path at offset 4 + otsSigLen + 4
        byte *authPathPos = signature + 4 + otsSigLen + 4;
        lms_extract_auth_path(authPathPos, m_tree, q, lmsP);

        // C is a SecByteBlock - cleaned up by destructor on all paths.

        // Commit
        m_store->CommitReservation(reservation);
    }
    catch (...)
    {
        // Abort burns the index
        m_store->AbortReservation(reservation);
        throw;
    }
}

// ******************** Explicit Template Instantiations ************************* //

template struct LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSPublicKey<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSPrivateKey<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSVerifier<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSSigner<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

NAMESPACE_END  // CryptoPP
