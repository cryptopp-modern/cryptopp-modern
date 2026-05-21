// hss.h - written and placed in the public domain by Colin Brown
//         HSS (Hierarchical Signature System) - RFC 8554 Section 6, NIST SP 800-208

/// \file hss.h
/// \brief HSS hierarchical stateful hash-based signature scheme (RFC 8554)
/// \details HSS stacks multiple LMS trees in a hierarchy. A root tree
///  signs child tree public keys, and the bottom-level tree signs messages.
///  This dramatically increases signing capacity compared to single-tree LMS.
///  HSS requires L >= 2. For single-tree signatures, use LMS directly.
///  The signer uses PK_StatefulSigner (not PK_Signer) to make
///  the stateful nature explicit. The verifier uses the conventional
///  PK_Verifier interface. The SignerStateStore tracks a single global
///  signature counter; the signer decomposes it into per-level indices.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-6">RFC 8554 Section 6</A>,
///  <A HREF="https://csrc.nist.gov/pubs/sp/800/208/final">NIST SP 800-208</A>
/// \since cryptopp-modern 2026.6.0

#ifndef CRYPTOPP_HSS_H
#define CRYPTOPP_HSS_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/stateful.h>
#include <cryptopp/lms.h>
#include <cryptopp/misc.h>
#include <cryptopp/allocate.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include <cstring>
#include <vector>

NAMESPACE_BEGIN(CryptoPP)

// ******************** HSS Parameter Sets ************************* //

/// \brief HSS parameter set with uniform LMS/OTS types at all levels
/// \tparam LMS_PARAMS LMS parameter set (used at every level)
/// \tparam OTS_PARAMS LM-OTS parameter set (used at every level)
/// \tparam LEVELS number of tree levels (must be >= 2)
/// \details Uniform parameters only (same LMS/OTS at all levels).
///  Mixed parameter sets across levels may be added in a future release.
template <class LMS_PARAMS, class OTS_PARAMS, unsigned int LEVELS>
struct HSS_Params
{
    static_assert(LEVELS >= 2, "HSS requires at least 2 levels");
    static_assert(LEVELS <= 4, "HSS supports up to 4 levels");

    CRYPTOPP_CONSTANT(L = LEVELS);
    typedef LMS_PARAMS LMSParameters;
    typedef OTS_PARAMS OTSParameters;

    CRYPTOPP_CONSTANT(LEAVES_PER_LEVEL = LMS_PARAMS::TOTAL_LEAVES);

    /// \brief Check if total capacity fits in uint64_t
    static constexpr bool CapacityFitsUint64()
    {
        uint64_t cap = 1;
        for (unsigned int i = 0; i < LEVELS; i++)
        {
            if (cap > UINT64_MAX / static_cast<uint64_t>(LEAVES_PER_LEVEL))
                return false;
            cap *= static_cast<uint64_t>(LEAVES_PER_LEVEL);
        }
        return true;
    }

    static_assert(CapacityFitsUint64(), "HSS capacity exceeds uint64_t");

    /// \brief Total signing capacity
    static constexpr uint64_t TotalSignatures()
    {
        uint64_t total = 1;
        for (unsigned int i = 0; i < LEVELS; i++)
            total *= static_cast<uint64_t>(LEAVES_PER_LEVEL);
        return total;
    }

    /// \brief LMS signature size for one level
    static constexpr size_t LMSSignatureSize()
    {
        return 4 + OTS_PARAMS::SIG_LEN + 4 +
               static_cast<size_t>(LMS_PARAMS::H) * static_cast<size_t>(LMS_PARAMS::M);
    }

    /// \brief LMS public key size
    static constexpr size_t LMSPublicKeySize()
    {
        return 4 + 4 + 16 + LMS_PARAMS::M;
    }

    /// \brief HSS signature size
    /// \details u32(Nspk) + (L-1) * (lms_sig + lms_pub) + lms_sig
    static constexpr size_t SignatureSize()
    {
        return 4 +
               (LEVELS - 1) * (LMSSignatureSize() + LMSPublicKeySize()) +
               LMSSignatureSize();
    }

    /// \brief HSS public key size
    /// \details u32(L) + lms_pub
    static constexpr size_t PublicKeySize()
    {
        return 4 + LMSPublicKeySize();
    }

    /// \brief Algorithm name
    static std::string StaticAlgorithmName()
    {
        return "HSS[" + std::to_string(LEVELS) + "]/" +
               LMS_PARAMS::StaticAlgorithmName() + "/" +
               OTS_PARAMS::StaticAlgorithmName();
    }
};

// ******************** HSS Message Accumulator ************************* //

/// \brief HSS message accumulator
/// \details Buffers the entire message. First bytes reserved for signature
///  during verification.
template <class HSS_PARAMS>
struct HSS_MessageAccumulator : public PK_MessageAccumulator
{
    static const size_t SIGNATURE_LENGTH = HSS_PARAMS::SignatureSize();

    HSS_MessageAccumulator() { Restart(); }

    HSS_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng);
        Restart();
    }

    void Update(const byte *msg, size_t len) {
        if (len == 0) return;
        if (!msg)
            throw InvalidArgument("HSS: Update called with null pointer and non-zero length");
        m_msg.insert(m_msg.end(), msg, msg + len);
    }

    void Restart() {
        m_msg.clear();
        m_msg.reserve(2048 + SIGNATURE_LENGTH);
        m_msg.resize(SIGNATURE_LENGTH);
    }

    byte* signature() { return m_msg.data(); }
    const byte* signature() const { return m_msg.data(); }
    const byte* data() const { return m_msg.data() + SIGNATURE_LENGTH; }
    size_t size() const { return m_msg.size() - SIGNATURE_LENGTH; }

protected:
    std::vector<byte, AllocatorWithCleanup<byte> > m_msg;
};

// ******************** HSS Public Key ************************* //

/// \brief HSS public key (verification key)
/// \tparam HSS_PARAMS HSS parameter set
/// \details The HSS public key contains L (number of levels) followed
///  by the root LMS public key.
/// \details Validate() checks L matches the template, and performs full
///  structural validation of the embedded root LMS public key.
template <class HSS_PARAMS>
class HSSPublicKey : public PublicKey
{
public:
    static const size_t PUBLIC_KEY_SIZE = HSS_PARAMS::PublicKeySize();

    HSSPublicKey() : m_pk(PUBLIC_KEY_SIZE) { std::memset(m_pk, 0, PUBLIC_KEY_SIZE); }
    virtual ~HSSPublicKey() = default;

    /// \brief Get the algorithm OID
    /// \details Same OID as LMS (RFC 8554, RFC 8708).
    OID GetAlgorithmID() const { return ASN1::id_alg_hss_lms_hashsig(); }

    /// \brief Validate public key structure
    /// \details Checks: size, L == LEVELS, root LMS key type IDs,
    ///  full root LMS public key structural validation.
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;

    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    void SetPublicKey(const byte *pk, size_t len);
    const byte* GetPublicKeyBytePtr() const { return m_pk.begin(); }
    size_t GetPublicKeyByteLength() const { return PUBLIC_KEY_SIZE; }

    /// \brief Get the encoded L value (first 4 bytes, big-endian)
    uint32_t GetL() const;

    /// \brief Get pointer to the root LMS public key (offset 4)
    const byte* GetRootLMSPublicKey() const { return m_pk.begin() + 4; }

    /// \brief DER encode (X.509 SubjectPublicKeyInfo, RFC 8708)
    void DEREncode(BufferedTransformation &bt) const;
    void BERDecode(BufferedTransformation &bt);
    void Save(BufferedTransformation &bt) const { DEREncode(bt); }
    void Load(BufferedTransformation &bt) { BERDecode(bt); }

private:
    SecByteBlock m_pk;
};

// ******************** HSS Private Key ************************* //

/// \brief HSS private key material
/// \tparam HSS_PARAMS HSS parameter set
/// \details Contains only root immutable key material (seed + identifier).
///  Child keys are derived deterministically at runtime.
///  Signing progress lives in the SignerStateStore, not in the key.
///  Serialising and deserialising a private key does not restore signing
///  capability; a valid state store is required.
template <class HSS_PARAMS>
class HSSPrivateKey : public PrivateKey
{
public:
    CRYPTOPP_CONSTANT(SEED_SIZE = HSS_PARAMS::OTSParameters::N);
    CRYPTOPP_CONSTANT(I_SIZE = 16);

    HSSPrivateKey() : m_seed(SEED_SIZE), m_I(I_SIZE) {}
    virtual ~HSSPrivateKey() = default;

    /// \brief Get the algorithm OID
    OID GetAlgorithmID() const { return ASN1::id_alg_hss_lms_hashsig(); }

    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;

    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
    void AssignFrom(const NameValuePairs &source);

    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);

    void SetPrivateKey(const byte *seed, size_t seedLen,
                       const byte *identifier, size_t idLen);
    const byte* GetSeedBytePtr() const { return m_seed.begin(); }
    const byte* GetIdentifierBytePtr() const { return m_I.begin(); }

    /// \brief Compute the HSS public key
    /// \details Computes the root LMS Merkle tree to derive T[1],
    ///  then assembles L + root LMS public key.
    void MakePublicKey(HSSPublicKey<HSS_PARAMS> &pub) const;

    /// \brief Library PKCS#8 wrapping
    /// \details For cryptopp-modern persistence only. Not an RFC-defined
    ///  HSS private key format. Not portable across implementations.
    void DEREncode(BufferedTransformation &bt) const;
    void BERDecode(BufferedTransformation &bt);
    void Save(BufferedTransformation &bt) const { DEREncode(bt); }
    void Load(BufferedTransformation &bt) { BERDecode(bt); }

private:
    SecByteBlock m_seed;
    SecByteBlock m_I;
};

// ******************** HSS Verifier ************************* //

/// \brief HSS signature verifier (stateless)
/// \tparam HSS_PARAMS HSS parameter set
/// \details Verification is a strict bounded chain walk: parse Nspk,
///  verify each intermediate signed public key, then verify the final
///  message signature. Rejects truncation, trailing garbage, and
///  mismatched type IDs.
template <class HSS_PARAMS>
class HSSVerifier : public PK_Verifier
{
public:
    typedef HSS_PARAMS Parameters;
    typedef HSSPublicKey<HSS_PARAMS> PublicKeyType;
    typedef HSS_MessageAccumulator<HSS_PARAMS> MessageAccumulatorType;

    static const size_t SIGNATURE_LENGTH = HSS_PARAMS::SignatureSize();

    virtual ~HSSVerifier() = default;

    HSSVerifier() {}
    HSSVerifier(const byte *publicKey, size_t len);

    std::string AlgorithmName() const { return HSS_PARAMS::StaticAlgorithmName(); }

    // PublicKeyAlgorithm interface
    PublicKey& AccessPublicKey() { return m_key; }
    const PublicKey& GetPublicKey() const { return m_key; }

    // PK_SignatureScheme interface
    size_t SignatureLength() const { return SIGNATURE_LENGTH; }
    size_t MaxRecoverableLength() const { return 0; }
    size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const {
        CRYPTOPP_UNUSED(signatureLength);
        return 0;
    }

    bool IsProbabilistic() const { return false; }
    bool AllowNonrecoverablePart() const { return true; }
    bool RecoverablePartFirst() const { return false; }

    // PK_Verifier interface
    PK_MessageAccumulator* NewVerificationAccumulator() const {
        return new MessageAccumulatorType();
    }

    void InputSignature(PK_MessageAccumulator &messageAccumulator,
        const byte *signature, size_t signatureLength) const {
        if (!signature || signatureLength != SIGNATURE_LENGTH)
            throw InvalidArgument(AlgorithmName() + ": invalid signature length");
        MessageAccumulatorType &accum = static_cast<MessageAccumulatorType&>(messageAccumulator);
        std::memcpy(accum.signature(), signature, SIGNATURE_LENGTH);
    }

    bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const;

    DecodingResult RecoverAndRestart(byte *recoveredMessage,
        PK_MessageAccumulator &messageAccumulator) const {
        CRYPTOPP_UNUSED(recoveredMessage);
        CRYPTOPP_UNUSED(messageAccumulator);
        throw NotImplemented("HSSVerifier: recoverable messages not supported");
    }

    PublicKeyType& AccessKey() { return m_key; }
    const PublicKeyType& GetKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** HSS Signer ************************* //

/// \brief HSS stateful signature signer
/// \tparam HSS_PARAMS HSS parameter set
/// \details Each signature consumes one global signing index. The signer
///  decomposes it into per-level LMS leaf indices and manages subtree
///  chain regeneration internally. Caches are built lazily on first
///  SignMessage(). Not thread-safe.
template <class HSS_PARAMS>
class HSSSigner : public PK_StatefulSigner
{
public:
    typedef HSS_PARAMS Parameters;
    typedef HSSPrivateKey<HSS_PARAMS> PrivateKeyType;

    static const size_t SIGNATURE_LENGTH = HSS_PARAMS::SignatureSize();

    virtual ~HSSSigner() = default;

    /// \brief Construct signer bound to a private key and state store
    /// \details The store's total capacity must equal
    ///  HSS_PARAMS::TotalSignatures(). Caches are built lazily.
    HSSSigner(const PrivateKeyType &key, SignerStateStore &store);

    // Non-copyable
    HSSSigner(const HSSSigner &) = delete;
    HSSSigner &operator=(const HSSSigner &) = delete;

    // Movable (caches move with signer)
    HSSSigner(HSSSigner &&) = default;
    HSSSigner &operator=(HSSSigner &&) = default;

    // PK_StatefulSigner interface
    std::string AlgorithmName() const override { return HSS_PARAMS::StaticAlgorithmName(); }
    size_t SignatureLength() const override { return SIGNATURE_LENGTH; }
    bool IsExhausted() const override { return m_store.IsExhausted(); }
    uint64_t RemainingSignatures() const override { return m_store.RemainingSignatures(); }

    /// \brief Sign a message (not thread-safe)
    /// \details Consumes one global signing index. Internally manages
    ///  subtree chain regeneration when crossing subtree boundaries.
    ///  All parent leaf consumption during regeneration is part of the
    ///  reserved capability. Failure after reservation burns the index.
    void SignMessage(
        RandomNumberGenerator &rng,
        const byte *message, size_t messageLen,
        byte *signature) override;

    const PrivateKeyType &GetKey() const { return m_rootKey; }

private:
    PrivateKeyType m_rootKey;
    SignerStateStore &m_store;

    /// \brief Per-level cached state
    struct LevelState {
        SecByteBlock seed;                      ///< derived SEED for this level
        SecByteBlock identifier;                ///< derived I for this level
        SecByteBlock tree;                      ///< precomputed Merkle tree (full node array)
        SecByteBlock lmsPublicKey;              ///< LMS public key bytes for this level
        SecByteBlock parentSignatureOnChild;    ///< parent's LMS sig authenticating this
                                                ///< level's public key (empty for level 0)
        uint32_t childSubtreeId;                ///< parent leaf that signed this subtree
                                                ///< (unused for level 0 - root has no parent)
        bool initialised;                       ///< false until first reconciliation
    };
    std::vector<LevelState> m_levels;
    bool m_reconciled;

    // Deterministic helpers (no RNG needed for derivation/tree computation)
    void ReconcileState(uint64_t globalIndex);
    void BuildSubtreeChain(unsigned int fromLevel, const uint32_t *perLevel);
    static void DecomposeGlobalIndex(uint64_t globalIndex,
                                     uint32_t *perLevel, unsigned int levels);

    // Signing helper (needs RNG for bottom-level OTS randomiser C only)
    void ProduceSignature(RandomNumberGenerator &rng,
                          const byte *message, size_t messageLen,
                          byte *signature, const uint32_t *perLevel);
};

// ******************** HSS Scheme ************************* //

/// \brief HSS signature scheme
template <class HSS_PARAMS>
struct HSS
{
    typedef HSSSigner<HSS_PARAMS> Signer;
    typedef HSSVerifier<HSS_PARAMS> Verifier;
    typedef HSSPrivateKey<HSS_PARAMS> PrivateKey;
    typedef HSSPublicKey<HSS_PARAMS> PublicKey;

    static std::string StaticAlgorithmName() { return HSS_PARAMS::StaticAlgorithmName(); }
};

// ******************** Convenience Typedefs ************************* //

/// \name HSS Scheme Typedefs
//@{

/// 2-level HSS with H5/W8: 1,024 signatures
typedef HSS_Params<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, 2> HSS_SHA256_H5_W8_L2_Params;
typedef HSS<HSS_SHA256_H5_W8_L2_Params> HSS_SHA256_H5_W8_L2;

/// 2-level HSS with H10/W8: 1,048,576 signatures
typedef HSS_Params<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8, 2> HSS_SHA256_H10_W8_L2_Params;
typedef HSS<HSS_SHA256_H10_W8_L2_Params> HSS_SHA256_H10_W8_L2;

/// 3-level HSS with H5/W8: 32,768 signatures
typedef HSS_Params<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, 3> HSS_SHA256_H5_W8_L3_Params;
typedef HSS<HSS_SHA256_H5_W8_L3_Params> HSS_SHA256_H5_W8_L3;

//@}

NAMESPACE_END

#endif  // CRYPTOPP_HSS_H
