// lms.cpp - written and placed in the public domain by Colin Brown
//           LMS/LM-OTS implementation (RFC 8554, NIST SP 800-208)
//           Stage 1: SHA-256 only. The implementation hardcodes SHA256
//           for all hash operations, matching the SHA256_M32 parameter sets.

#include <cryptopp/pch.h>
#include <cryptopp/sha.h>
#include <cryptopp/misc.h>
#include <cryptopp/secblock.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

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

// ==================== LMS Public Key Byte Assembly ====================

/// \brief Assemble LMS public key bytes: LMS_type(4) + OTS_type(4) + I(16) + T[1](m)
/// \param out output buffer (must be at least 4+4+16+m bytes)
/// \param lmsTypeId LMS algorithm type ID
/// \param otsTypeId LM-OTS algorithm type ID
/// \param I 16-byte identifier
/// \param root tree root T[1] (m bytes)
/// \param m hash output length
void build_lms_public_key_bytes(byte *out, uint32_t lmsTypeId, uint32_t otsTypeId,
                                const byte *I, const byte *root, unsigned int m)
{
    u32str(out, lmsTypeId);
    u32str(out + 4, otsTypeId);
    std::memcpy(out + 8, I, 16);
    std::memcpy(out + 24, root, m);
}

// ==================== HSS Child Key Derivation ====================
// ACVP convention: same Appendix A formula with reserved chain indices.

void derive_child_seed(byte *childSeed, const byte *parentI,
                       uint32_t parentLeaf, const byte *parentSeed,
                       unsigned int n)
{
    SHA256 hash;
    byte buf4[4], buf2[2], buf1[1];

    hash.Update(parentI, 16);
    u32str(buf4, parentLeaf);
    hash.Update(buf4, 4);
    u16str(buf2, 0xFFFE);  // i = 65534: child SEED
    hash.Update(buf2, 2);
    u8str(buf1, 0xFF);
    hash.Update(buf1, 1);
    hash.Update(parentSeed, n);
    hash.TruncatedFinal(childSeed, n);
}

void derive_child_identifier(byte *childI, const byte *parentI,
                              uint32_t parentLeaf, const byte *parentSeed,
                              unsigned int n)
{
    SHA256 hash;
    byte buf4[4], buf2[2], buf1[1];

    hash.Update(parentI, 16);
    u32str(buf4, parentLeaf);
    hash.Update(buf4, 4);
    u16str(buf2, 0xFFFF);  // i = 65535: child identifier
    hash.Update(buf2, 2);
    u8str(buf1, 0xFF);
    hash.Update(buf1, 1);
    hash.Update(parentSeed, n);
    hash.TruncatedFinal(childI, 16);  // I is always 16 bytes
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

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // X.509 SubjectPublicKeyInfo format (RFC 8708)
    // AlgorithmIdentifier parameters MUST be absent (not NULL)
    DERSequenceEncoder publicKeyInfo(bt);
        DERSequenceEncoder algorithm(publicKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        // Public key bytes go directly in BIT STRING, no wrapping
        DEREncodeBitString(publicKeyInfo, m_pk.begin(), PUBLIC_KEY_SIZE);
    publicKeyInfo.MessageEnd();
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::BERDecode(BufferedTransformation &bt)
{
    // X.509 SubjectPublicKeyInfo format (RFC 8708)
    BERSequenceDecoder publicKeyInfo(bt);
        BERSequenceDecoder algorithm(publicKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        SecByteBlock subjectPublicKey;
        unsigned int unusedBits;
        BERDecodeBitString(publicKeyInfo, subjectPublicKey, unusedBits);
        if (unusedBits != 0 || subjectPublicKey.size() != PUBLIC_KEY_SIZE)
            BERDecodeError();
        SetPublicKey(subjectPublicKey.begin(), PUBLIC_KEY_SIZE);

    publicKeyInfo.MessageEnd();
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
    build_lms_public_key_bytes(pkBuf, LMS_PARAMS::TYPE_ID, OTS_PARAMS::TYPE_ID,
                               m_I, tree + m, m);

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

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // Library PKCS#8 wrapping with LMS OID.
    // Private key payload is SEED || I (concatenated, no leaf index).
    // This is not an RFC-defined private key format.
    DERSequenceEncoder privateKeyInfo(bt);
        DEREncodeUnsigned<word32>(privateKeyInfo, 0);  // version 0 only

        DERSequenceEncoder algorithm(privateKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
            DERGeneralEncoder privateKey(octetString, OCTET_STRING);
                privateKey.Put(m_seed.begin(), SEED_SIZE);
                privateKey.Put(m_I.begin(), I_SIZE);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

template <class LMS_PARAMS, class OTS_PARAMS>
void LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::BERDecode(BufferedTransformation &bt)
{
    // Library PKCS#8 wrapping with LMS OID. Version 0 only.
    const size_t privKeyLen = SEED_SIZE + I_SIZE;

    BERSequenceDecoder privateKeyInfo(bt);
        word32 version;
        BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 0);

        BERSequenceDecoder algorithm(privateKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
            BERGeneralDecoder privateKey(octetString, OCTET_STRING);
                if (!privateKey.IsDefiniteLength() ||
                    privateKey.RemainingLength() != privKeyLen)
                    BERDecodeError();
                SecByteBlock seed(SEED_SIZE);
                SecByteBlock identifier(I_SIZE);
                privateKey.Get(seed.begin(), SEED_SIZE);
                privateKey.Get(identifier.begin(), I_SIZE);
                SetPrivateKey(seed.begin(), SEED_SIZE, identifier.begin(), I_SIZE);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
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

// ******************** Explicit LMS Template Instantiations ************************* //

template struct LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSPublicKey<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSPrivateKey<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSVerifier<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

template struct LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>;
template struct LMSSigner<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>;

NAMESPACE_END  // CryptoPP

// ==================== HSS Template Implementations ====================

#include <cryptopp/hss.h>

NAMESPACE_BEGIN(CryptoPP)

// ******************** HSS Internal Helpers ************************* //

namespace {

/// \brief Bounded cursor for strict HSS signature parsing
/// \details Self-checking: ReadU32() and ReadBlock() return false/null
///  on underflow. Callers should still pre-check with HasAtLeast() for
///  clarity, but the cursor is safe even without pre-checks.
struct SignatureCursor
{
    const byte *data;
    size_t remaining;
    bool failed;

    bool ReadU32(uint32_t &val)
    {
        if (remaining < 4) { failed = true; return false; }
        val = (static_cast<uint32_t>(data[0]) << 24) |
              (static_cast<uint32_t>(data[1]) << 16) |
              (static_cast<uint32_t>(data[2]) << 8) |
              (static_cast<uint32_t>(data[3]));
        data += 4;
        remaining -= 4;
        return true;
    }

    const byte* ReadBlock(size_t n)
    {
        if (remaining < n) { failed = true; return NULLPTR; }
        const byte *ptr = data;
        data += n;
        remaining -= n;
        return ptr;
    }

    bool HasExactly(size_t n) const { return remaining == n; }
    bool HasAtLeast(size_t n) const { return remaining >= n; }
    bool Failed() const { return failed; }
};

/// \brief Verify a single LMS signature over arbitrary message bytes
/// \details Used by HSS verifier for both intermediate key signing and
///  final message signing. Operates on raw byte buffers, not key objects.
/// \param pubKey raw LMS public key bytes: LMS_type(4) + OTS_type(4) + I(16) + T[1](m)
/// \param message the signed message bytes
/// \param messageLen message length
/// \param lmsSig raw LMS signature: q(4) + OTS_sig + LMS_type(4) + auth_path(h*m)
/// \param lmsP LMS runtime parameters
/// \param otsP OTS runtime parameters
/// \return true if signature verifies
bool lms_verify_signature_raw(
    const byte *pubKey,
    const byte *message, size_t messageLen,
    const byte *lmsSig,
    const LMS_Internal::LMSParams &lmsP,
    const LMS_Internal::OTSParams &otsP)
{
    using namespace LMS_Internal;

    const unsigned int m = lmsP.m;
    const unsigned int h = lmsP.h;

    // Extract I and root T[1] from public key
    const byte *I = pubKey + 8;       // offset past LMS_type(4) + OTS_type(4)
    const byte *root = pubKey + 24;   // offset past LMS_type(4) + OTS_type(4) + I(16)

    // Parse q from signature
    uint32_t q = (static_cast<uint32_t>(lmsSig[0]) << 24) |
                 (static_cast<uint32_t>(lmsSig[1]) << 16) |
                 (static_cast<uint32_t>(lmsSig[2]) << 8) |
                 (static_cast<uint32_t>(lmsSig[3]));

    if (q >= (1u << h))
        return false;

    const byte *otsSig = lmsSig + 4;
    const size_t otsSigLen = otsP.SigLen();
    const byte *authPath = lmsSig + 4 + otsSigLen + 4;

    // Verify OTS type in signature
    uint32_t sigOtsType = (static_cast<uint32_t>(otsSig[0]) << 24) |
                          (static_cast<uint32_t>(otsSig[1]) << 16) |
                          (static_cast<uint32_t>(otsSig[2]) << 8) |
                          (static_cast<uint32_t>(otsSig[3]));
    if (sigOtsType != otsP.type_id)
        return false;

    // Verify LMS type in signature
    const byte *sigLmsTypePtr = lmsSig + 4 + otsSigLen;
    uint32_t sigLmsType = (static_cast<uint32_t>(sigLmsTypePtr[0]) << 24) |
                          (static_cast<uint32_t>(sigLmsTypePtr[1]) << 16) |
                          (static_cast<uint32_t>(sigLmsTypePtr[2]) << 8) |
                          (static_cast<uint32_t>(sigLmsTypePtr[3]));
    if (sigLmsType != lmsP.type_id)
        return false;

    // Compute candidate OTS public key
    SecByteBlock Kc(m);
    lmots_compute_candidate_key(Kc, otsSig, message, messageLen, I, q, otsP);

    // Compute candidate leaf hash
    const uint32_t numLeaves = 1u << h;
    SecByteBlock candidateLeaf(m);
    lms_leaf_hash(candidateLeaf, I, numLeaves + q, Kc, m);

    // Verify auth path
    bool result = lms_verify_path(candidateLeaf, authPath, q, root, I, lmsP);

    SecureWipeBuffer(Kc.data(), Kc.size());
    SecureWipeBuffer(candidateLeaf.data(), candidateLeaf.size());

    return result;
}

}  // anonymous namespace

// ******************** HSSPublicKey ************************* //

template <class HSS_PARAMS>
void HSSPublicKey<HSS_PARAMS>::SetPublicKey(const byte *pk, size_t len)
{
    if (!pk || len != PUBLIC_KEY_SIZE)
        throw InvalidArgument("HSSPublicKey: invalid public key length");
    m_pk.Assign(pk, len);
}

template <class HSS_PARAMS>
uint32_t HSSPublicKey<HSS_PARAMS>::GetL() const
{
    return (static_cast<uint32_t>(m_pk[0]) << 24) |
           (static_cast<uint32_t>(m_pk[1]) << 16) |
           (static_cast<uint32_t>(m_pk[2]) << 8) |
           (static_cast<uint32_t>(m_pk[3]));
}

template <class HSS_PARAMS>
bool HSSPublicKey<HSS_PARAMS>::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    if (m_pk.size() != PUBLIC_KEY_SIZE)
        return false;

    // Verify L matches template parameter
    if (GetL() != HSS_PARAMS::L)
        return false;

    // Validate the embedded root LMS public key by delegating to LMSPublicKey
    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;
    typedef LMSPublicKey<LMS_P, OTS_P> RootLMSKeyType;

    try {
        RootLMSKeyType rootLmsKey;
        rootLmsKey.SetPublicKey(GetRootLMSPublicKey(), HSS_PARAMS::LMSPublicKeySize());
        if (!rootLmsKey.Validate(rng, level))
            return false;
    } catch (const Exception &) {
        return false;
    }

    return true;
}

template <class HSS_PARAMS>
bool HSSPublicKey<HSS_PARAMS>::GetVoidValue(
    const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name); CRYPTOPP_UNUSED(valueType); CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class HSS_PARAMS>
void HSSPublicKey<HSS_PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class HSS_PARAMS>
void HSSPublicKey<HSS_PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // X.509 SubjectPublicKeyInfo (RFC 8708)
    // AlgorithmIdentifier parameters MUST be absent (not NULL)
    DERSequenceEncoder publicKeyInfo(bt);
        DERSequenceEncoder algorithm(publicKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DEREncodeBitString(publicKeyInfo, m_pk.begin(), PUBLIC_KEY_SIZE);
    publicKeyInfo.MessageEnd();
}

template <class HSS_PARAMS>
void HSSPublicKey<HSS_PARAMS>::BERDecode(BufferedTransformation &bt)
{
    // X.509 SubjectPublicKeyInfo (RFC 8708)
    BERSequenceDecoder publicKeyInfo(bt);
        BERSequenceDecoder algorithm(publicKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        SecByteBlock subjectPublicKey;
        unsigned int unusedBits;
        BERDecodeBitString(publicKeyInfo, subjectPublicKey, unusedBits);
        if (unusedBits != 0 || subjectPublicKey.size() != PUBLIC_KEY_SIZE)
            BERDecodeError();
        SetPublicKey(subjectPublicKey.begin(), PUBLIC_KEY_SIZE);

    publicKeyInfo.MessageEnd();
}

// ******************** HSSPrivateKey ************************* //

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::SetPrivateKey(
    const byte *seed, size_t seedLen,
    const byte *identifier, size_t idLen)
{
    if (!seed || seedLen != SEED_SIZE)
        throw InvalidArgument("HSSPrivateKey: invalid seed length");
    if (!identifier || idLen != I_SIZE)
        throw InvalidArgument("HSSPrivateKey: invalid identifier length");
    m_seed.Assign(seed, seedLen);
    m_I.Assign(identifier, idLen);
}

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::GenerateRandom(
    RandomNumberGenerator &rng, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);
    m_seed.resize(SEED_SIZE);
    m_I.resize(I_SIZE);
    rng.GenerateBlock(m_seed, SEED_SIZE);
    rng.GenerateBlock(m_I, I_SIZE);
}

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::MakePublicKey(HSSPublicKey<HSS_PARAMS> &pub) const
{
    using namespace LMS_Internal;

    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;

    const OTSParams otsP = MakeOTSParams<OTS_P>();
    const LMSParams lmsP = MakeLMSParams<LMS_P>();

    const unsigned int m = LMS_P::M;
    const uint32_t numNodes = 2u * (1u << LMS_P::H);

    // Compute root Merkle tree
    SecByteBlock tree(static_cast<size_t>(numNodes) * m);
    lms_compute_full_tree(tree, m_I, m_seed, lmsP, otsP);

    // Build HSS public key: L(4) + LMS public key
    SecByteBlock pkBuf(HSS_PARAMS::PublicKeySize());
    u32str(pkBuf, HSS_PARAMS::L);
    build_lms_public_key_bytes(pkBuf + 4, LMS_P::TYPE_ID, OTS_P::TYPE_ID,
                               m_I, tree + m, m);

    pub.SetPublicKey(pkBuf, HSS_PARAMS::PublicKeySize());

    SecureWipeBuffer(tree.data(), tree.size());
}

template <class HSS_PARAMS>
bool HSSPrivateKey<HSS_PARAMS>::Validate(
    RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);
    return m_seed.size() == SEED_SIZE && m_I.size() == I_SIZE;
}

template <class HSS_PARAMS>
bool HSSPrivateKey<HSS_PARAMS>::GetVoidValue(
    const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name); CRYPTOPP_UNUSED(valueType); CRYPTOPP_UNUSED(pValue);
    return false;
}

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::DEREncode(BufferedTransformation &bt) const
{
    // Library PKCS#8 wrapping. Inner payload is SEED || I only;
    // level count and parameter types are carried by the template type.
    DERSequenceEncoder privateKeyInfo(bt);
        DEREncodeUnsigned<word32>(privateKeyInfo, 0);  // version 0

        DERSequenceEncoder algorithm(privateKeyInfo);
            GetAlgorithmID().DEREncode(algorithm);
        algorithm.MessageEnd();

        DERGeneralEncoder octetString(privateKeyInfo, OCTET_STRING);
            DERGeneralEncoder privateKey(octetString, OCTET_STRING);
                privateKey.Put(m_seed.begin(), SEED_SIZE);
                privateKey.Put(m_I.begin(), I_SIZE);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

template <class HSS_PARAMS>
void HSSPrivateKey<HSS_PARAMS>::BERDecode(BufferedTransformation &bt)
{
    const size_t privKeyLen = SEED_SIZE + I_SIZE;

    BERSequenceDecoder privateKeyInfo(bt);
        word32 version;
        BERDecodeUnsigned<word32>(privateKeyInfo, version, INTEGER, 0, 0);

        BERSequenceDecoder algorithm(privateKeyInfo);
            OID oid(algorithm);
            if (oid != GetAlgorithmID())
                BERDecodeError();
        algorithm.MessageEnd();

        BERGeneralDecoder octetString(privateKeyInfo, OCTET_STRING);
            BERGeneralDecoder privateKey(octetString, OCTET_STRING);
                if (!privateKey.IsDefiniteLength() ||
                    privateKey.RemainingLength() != privKeyLen)
                    BERDecodeError();
                SecByteBlock seed(SEED_SIZE);
                SecByteBlock identifier(I_SIZE);
                privateKey.Get(seed.begin(), SEED_SIZE);
                privateKey.Get(identifier.begin(), I_SIZE);
                SetPrivateKey(seed.begin(), SEED_SIZE, identifier.begin(), I_SIZE);
            privateKey.MessageEnd();
        octetString.MessageEnd();

    privateKeyInfo.MessageEnd();
}

// ******************** HSSVerifier ************************* //

template <class HSS_PARAMS>
HSSVerifier<HSS_PARAMS>::HSSVerifier(const byte *publicKey, size_t len)
{
    m_key.SetPublicKey(publicKey, len);
}

template <class HSS_PARAMS>
bool HSSVerifier<HSS_PARAMS>::VerifyAndRestart(
    PK_MessageAccumulator &messageAccumulator) const
{
    using namespace LMS_Internal;

    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;

    MessageAccumulatorType &accum =
        static_cast<MessageAccumulatorType&>(messageAccumulator);

    const byte *sig = accum.signature();
    const byte *message = accum.data();
    const size_t messageLen = accum.size();

    const OTSParams otsP = MakeOTSParams<OTS_P>();
    const LMSParams lmsP = MakeLMSParams<LMS_P>();

    const size_t lmsSigSize = HSS_PARAMS::LMSSignatureSize();
    const size_t lmsPubSize = HSS_PARAMS::LMSPublicKeySize();

    // Create bounded cursor over signature
    SignatureCursor cursor = {sig, SIGNATURE_LENGTH, false};

    // Step 1: Read and validate Nspk
    uint32_t Nspk = 0;
    if (!cursor.ReadU32(Nspk) || Nspk != HSS_PARAMS::L - 1)
    {
        accum.Restart();
        return false;
    }

    // Start with root LMS public key
    SecByteBlock currentKey(lmsPubSize);
    std::memcpy(currentKey, m_key.GetRootLMSPublicKey(), lmsPubSize);

    // Step 2: Verify each intermediate signed public key
    for (uint32_t i = 0; i < Nspk; i++)
    {
        const byte *intermediateSig = cursor.ReadBlock(lmsSigSize);
        if (!intermediateSig)
        {
            accum.Restart();
            return false;
        }

        const byte *childPubKey = cursor.ReadBlock(lmsPubSize);
        if (!childPubKey)
        {
            accum.Restart();
            return false;
        }

        // Validate child public key via LMSPublicKey delegation
        {
            typedef LMSPublicKey<LMS_P, OTS_P> ChildLMSKeyType;
            ChildLMSKeyType childLmsKey;
            try {
                childLmsKey.SetPublicKey(childPubKey, lmsPubSize);
            } catch (const Exception &) {
                accum.Restart();
                return false;
            }
            if (!childLmsKey.Validate(NullRNG(), 0))
            {
                accum.Restart();
                return false;
            }
        }

        // Verify: parent LMS signature over child public key
        if (!lms_verify_signature_raw(currentKey, childPubKey, lmsPubSize,
                                       intermediateSig, lmsP, otsP))
        {
            accum.Restart();
            return false;
        }

        // Advance to child key
        std::memcpy(currentKey, childPubKey, lmsPubSize);
    }

    // Step 3: Verify final LMS signature on message (reject trailing garbage)
    if (!cursor.HasExactly(lmsSigSize))
    {
        accum.Restart();
        return false;
    }
    const byte *finalSig = cursor.ReadBlock(lmsSigSize);

    bool result = lms_verify_signature_raw(currentKey, message, messageLen,
                                            finalSig, lmsP, otsP);

    SecureWipeBuffer(currentKey.data(), currentKey.size());

    accum.Restart();
    return result;
}

// ******************** HSSSigner::DecomposeGlobalIndex ************************* //

template <class HSS_PARAMS>
void HSSSigner<HSS_PARAMS>::DecomposeGlobalIndex(uint64_t globalIndex,
                                                  uint32_t *perLevel,
                                                  unsigned int levels)
{
    CRYPTOPP_ASSERT(levels >= 2 && levels <= 4);
    CRYPTOPP_ASSERT(globalIndex < HSS_PARAMS::TotalSignatures());

    const uint64_t N = static_cast<uint64_t>(HSS_PARAMS::LEAVES_PER_LEVEL);
    uint64_t remaining = globalIndex;

    for (int i = static_cast<int>(levels) - 1; i >= 0; i--)
    {
        perLevel[i] = static_cast<uint32_t>(remaining % N);
        remaining /= N;
    }
}

// ******************** HSSSigner ************************* //

template <class HSS_PARAMS>
HSSSigner<HSS_PARAMS>::HSSSigner(const PrivateKeyType &key, SignerStateStore &store)
    : m_rootKey(key), m_store(store), m_levels(HSS_PARAMS::L), m_reconciled(false)
{
    // Lazy: no caches built here. First SignMessage() calls ReconcileState().
    for (unsigned int i = 0; i < HSS_PARAMS::L; i++)
        m_levels[i].initialised = false;
}

template <class HSS_PARAMS>
void HSSSigner<HSS_PARAMS>::SignMessage(
    RandomNumberGenerator &rng,
    const byte *message, size_t messageLen,
    byte *signature)
{
    if (!signature)
        throw InvalidArgument(AlgorithmName() + ": signature buffer is null");
    if (!message && messageLen > 0)
        throw InvalidArgument(AlgorithmName() + ": message is null with non-zero length");

    // Reserve global signing index (authoritative safety boundary)
    StateReservation reservation = m_store.ReserveNext();
    uint64_t globalIndex = reservation.LeafIndex();

    uint32_t perLevel[4];  // max 4 levels
    DecomposeGlobalIndex(globalIndex, perLevel, HSS_PARAMS::L);

    try
    {
        if (!m_reconciled)
        {
            ReconcileState(globalIndex);
            m_reconciled = true;
        }
        else
        {
            // Check subtree boundaries: if parent leaf changed, rebuild from that level
            for (unsigned int i = 0; i < HSS_PARAMS::L - 1; i++)
            {
                if (!m_levels[i + 1].initialised ||
                    perLevel[i] != m_levels[i + 1].childSubtreeId)
                {
                    BuildSubtreeChain(i + 1, perLevel);
                    break;  // cascade handled inside BuildSubtreeChain
                }
            }
        }

        ProduceSignature(rng, message, messageLen, signature, perLevel);
        m_store.CommitReservation(reservation);
    }
    catch (...)
    {
        m_store.AbortReservation(reservation);
        throw;
    }
}

template <class HSS_PARAMS>
void HSSSigner<HSS_PARAMS>::ReconcileState(uint64_t globalIndex)
{
    using namespace LMS_Internal;

    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;

    const OTSParams otsP = MakeOTSParams<OTS_P>();
    const LMSParams lmsP = MakeLMSParams<LMS_P>();
    const unsigned int m = LMS_P::M;
    const unsigned int n = OTS_P::N;
    const uint32_t numNodes = 2u * (1u << LMS_P::H);

    uint32_t perLevel[4];
    DecomposeGlobalIndex(globalIndex, perLevel, HSS_PARAMS::L);

    // Level 0: root - use root key material directly
    LevelState &root = m_levels[0];
    root.seed.Assign(m_rootKey.GetSeedBytePtr(), n);
    root.identifier.Assign(m_rootKey.GetIdentifierBytePtr(), 16);
    root.tree.resize(static_cast<size_t>(numNodes) * m);
    lms_compute_full_tree(root.tree, root.identifier, root.seed, lmsP, otsP);

    // Build root LMS public key
    const size_t lmsPubSize = HSS_PARAMS::LMSPublicKeySize();
    root.lmsPublicKey.resize(lmsPubSize);
    build_lms_public_key_bytes(root.lmsPublicKey, LMS_P::TYPE_ID, OTS_P::TYPE_ID,
                               root.identifier, root.tree + m, m);

    root.childSubtreeId = 0;  // unused for level 0
    root.parentSignatureOnChild.resize(0);  // root has no parent
    root.initialised = true;

    // Levels 1..L-1: derive from parent
    if (HSS_PARAMS::L > 1)
        BuildSubtreeChain(1, perLevel);
}

template <class HSS_PARAMS>
void HSSSigner<HSS_PARAMS>::BuildSubtreeChain(
    unsigned int fromLevel, const uint32_t *perLevel)
{
    using namespace LMS_Internal;

    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;

    const OTSParams otsP = MakeOTSParams<OTS_P>();
    const LMSParams lmsP = MakeLMSParams<LMS_P>();
    const unsigned int m = LMS_P::M;
    const unsigned int n = OTS_P::N;
    const uint32_t numNodes = 2u * (1u << LMS_P::H);

    const size_t lmsPubSize = HSS_PARAMS::LMSPublicKeySize();
    const size_t lmsSigSize = HSS_PARAMS::LMSSignatureSize();

    for (unsigned int level = fromLevel; level < HSS_PARAMS::L; level++)
    {
        LevelState &parent = m_levels[level - 1];
        LevelState &child = m_levels[level];
        uint32_t parentLeaf = perLevel[level - 1];

        // Derive child key material (deterministic, no RNG)
        child.seed.resize(n);
        child.identifier.resize(16);
        derive_child_seed(child.seed, parent.identifier, parentLeaf,
                          parent.seed, n);
        derive_child_identifier(child.identifier, parent.identifier,
                                parentLeaf, parent.seed, n);

        // Compute child Merkle tree
        child.tree.resize(static_cast<size_t>(numNodes) * m);
        lms_compute_full_tree(child.tree, child.identifier, child.seed,
                              lmsP, otsP);

        // Build child LMS public key
        child.lmsPublicKey.resize(lmsPubSize);
        build_lms_public_key_bytes(child.lmsPublicKey, LMS_P::TYPE_ID,
                                   OTS_P::TYPE_ID, child.identifier,
                                   child.tree + m, m);

        // Sign child public key with parent LMS tree
        // This consumes parent leaf perLevel[level-1]
        child.parentSignatureOnChild.resize(lmsSigSize);
        byte *sig = child.parentSignatureOnChild;

        // LMS signature: q(4) + OTS_sig + LMS_type(4) + auth_path(h*m)
        u32str(sig, parentLeaf);

        // Deterministic C for intermediate signing (i=0xFFFD, library-internal).
        // This MUST be deterministic so that signer reconstruction from the
        // same key + store position reproduces the exact same parent-signs-child
        // LMS signature. Using random C here would produce a valid but different
        // signature on each reconstruction, violating the parent OTS leaf's
        // one-time property. See lms_params.h for the full convention.
        SecByteBlock C(n);
        lmots_derive_chain_key(C, parent.identifier, parentLeaf,
                               static_cast<uint16_t>(0xFFFD), parent.seed, n);

        lmots_sign(sig + 4, child.lmsPublicKey, lmsPubSize,
                   parent.identifier, parentLeaf, parent.seed, C, otsP);

        const size_t otsSigLen = otsP.SigLen();
        u32str(sig + 4 + otsSigLen, LMS_P::TYPE_ID);

        lms_extract_auth_path(sig + 4 + otsSigLen + 4, parent.tree,
                              parentLeaf, lmsP);

        SecureWipeBuffer(C.data(), C.size());

        child.childSubtreeId = parentLeaf;
        child.initialised = true;
    }
}

template <class HSS_PARAMS>
void HSSSigner<HSS_PARAMS>::ProduceSignature(
    RandomNumberGenerator &rng,
    const byte *message, size_t messageLen,
    byte *signature, const uint32_t *perLevel)
{
    using namespace LMS_Internal;

    typedef typename HSS_PARAMS::LMSParameters LMS_P;
    typedef typename HSS_PARAMS::OTSParameters OTS_P;

    const OTSParams otsP = MakeOTSParams<OTS_P>();
    const LMSParams lmsP = MakeLMSParams<LMS_P>();
    const unsigned int n = OTS_P::N;

    const size_t lmsSigSize = HSS_PARAMS::LMSSignatureSize();
    const size_t lmsPubSize = HSS_PARAMS::LMSPublicKeySize();

    size_t offset = 0;

    // Nspk = L - 1
    u32str(signature + offset, HSS_PARAMS::L - 1);
    offset += 4;

    // Intermediate levels: emit cached parentSignatureOnChild + lmsPublicKey
    for (unsigned int level = 1; level < HSS_PARAMS::L; level++)
    {
        const LevelState &lvl = m_levels[level];
        CRYPTOPP_ASSERT(lvl.initialised);
        CRYPTOPP_ASSERT(lvl.parentSignatureOnChild.size() == lmsSigSize);
        CRYPTOPP_ASSERT(lvl.lmsPublicKey.size() == lmsPubSize);

        std::memcpy(signature + offset, lvl.parentSignatureOnChild, lmsSigSize);
        offset += lmsSigSize;
        std::memcpy(signature + offset, lvl.lmsPublicKey, lmsPubSize);
        offset += lmsPubSize;
    }

    // Final: sign message with bottom-level LMS tree
    const unsigned int bottomLevel = HSS_PARAMS::L - 1;
    const LevelState &bottom = m_levels[bottomLevel];
    uint32_t q = perLevel[bottomLevel];

    byte *finalSig = signature + offset;

    // LMS signature: q(4) + OTS_sig + LMS_type(4) + auth_path(h*m)
    u32str(finalSig, q);

    // Generate randomiser C (only RNG usage in entire signing flow)
    SecByteBlock C(n);
    rng.GenerateBlock(C, n);

    lmots_sign(finalSig + 4, message, messageLen,
               bottom.identifier, q, bottom.seed, C, otsP);

    const size_t otsSigLen = otsP.SigLen();
    u32str(finalSig + 4 + otsSigLen, LMS_P::TYPE_ID);

    lms_extract_auth_path(finalSig + 4 + otsSigLen + 4, bottom.tree,
                          q, lmsP);

    SecureWipeBuffer(C.data(), C.size());
}

// ******************** Explicit HSS Template Instantiations ************************* //

template class HSSPublicKey<HSS_SHA256_H5_W8_L2_Params>;
template class HSSPublicKey<HSS_SHA256_H10_W8_L2_Params>;

template class HSSPrivateKey<HSS_SHA256_H5_W8_L2_Params>;
template class HSSPrivateKey<HSS_SHA256_H10_W8_L2_Params>;

template class HSSVerifier<HSS_SHA256_H5_W8_L2_Params>;
template class HSSVerifier<HSS_SHA256_H10_W8_L2_Params>;

template class HSSSigner<HSS_SHA256_H5_W8_L2_Params>;
template class HSSSigner<HSS_SHA256_H10_W8_L2_Params>;

template class HSSPublicKey<HSS_SHA256_H5_W8_L3_Params>;
template class HSSPrivateKey<HSS_SHA256_H5_W8_L3_Params>;
template class HSSVerifier<HSS_SHA256_H5_W8_L3_Params>;
template class HSSSigner<HSS_SHA256_H5_W8_L3_Params>;

NAMESPACE_END  // CryptoPP
