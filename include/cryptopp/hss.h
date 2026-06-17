// hss.h - written and placed in the public domain by Colin Brown
//         HSS (Hierarchical Signature System) - RFC 8554 Section 6, NIST SP 800-208

/// \file hss.h
/// \brief HSS hierarchical stateful hash-based signature scheme (RFC 8554)
/// \details HSS stacks LMS trees in a hierarchy. Parent trees sign child
///  public keys; the bottom tree signs messages. Signing state is tracked
///  by SignerStateStore and exposed through PK_StatefulSigner.
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

// ******************** HSS Capacity ************************* //

namespace HSS_Internal {

// C++11 compile-time Base^N helper with overflow detection.
template <uint64_t Base, unsigned int N>
struct HSSCapacity
{
    static const bool fits =
        HSSCapacity<Base, N - 1>::fits &&
        HSSCapacity<Base, N - 1>::value <= UINT64_MAX / Base;

    static const uint64_t value =
        HSSCapacity<Base, N - 1>::value * Base;
};

template <uint64_t Base>
struct HSSCapacity<Base, 0>
{
    static const bool fits = true;
    static const uint64_t value = 1;
};

// C++11 compile-time type-at-index helper for parameter packs.
template <unsigned int I, class Head, class... Tail>
struct TypeAt
{
    typedef typename TypeAt<I - 1, Tail...>::type type;
};

template <class Head, class... Tail>
struct TypeAt<0, Head, Tail...>
{
    typedef Head type;
};

} // namespace HSS_Internal

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
        return HSS_Internal::HSSCapacity<LEAVES_PER_LEVEL, LEVELS>::fits;
    }

    static_assert(CapacityFitsUint64(), "HSS capacity exceeds uint64_t");

    /// \brief Total signing capacity
    static constexpr uint64_t TotalSignatures()
    {
        return HSS_Internal::HSSCapacity<LEAVES_PER_LEVEL, LEVELS>::value;
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

    // Per-level indexed accessors. Uniform here: every index resolves to the
    // same LMS/OTS pair.

    /// \brief Level descriptor for level I
    template <unsigned int I>
    struct LevelAt
    {
        static_assert(I < LEVELS, "HSS level index out of range");
        typedef LMS_PARAMS LMSParams;
        typedef OTS_PARAMS OTSParams;
    };

    /// \brief LMS parameter set at level I
    template <unsigned int I>
    using LMSParamsAt = typename LevelAt<I>::LMSParams;

    /// \brief LM-OTS parameter set at level I
    template <unsigned int I>
    using OTSParamsAt = typename LevelAt<I>::OTSParams;

    /// \brief LMS signature size at level I
    template <unsigned int I>
    static constexpr size_t LMSSignatureSizeAt()
    {
        return 4 + OTSParamsAt<I>::SIG_LEN + 4 +
               static_cast<size_t>(LMSParamsAt<I>::H) *
               static_cast<size_t>(LMSParamsAt<I>::M);
    }

    /// \brief LMS public key size at level I
    template <unsigned int I>
    static constexpr size_t LMSPublicKeySizeAt()
    {
        return 4 + 4 + 16 + LMSParamsAt<I>::M;
    }

    /// \brief Leaf count of the level-I tree
    template <unsigned int I>
    static constexpr uint64_t LeavesAt()
    {
        return static_cast<uint64_t>(LMSParamsAt<I>::TOTAL_LEAVES);
    }
};

// ******************** HSS Message Accumulator ************************* //

/// \brief HSS message accumulator
/// \details Stores the signature prefix and message bytes for verification.
template <class HSS_PARAMS>
struct HSS_MessageAccumulator : public PK_MessageAccumulator
{
    static const size_t SIGNATURE_LENGTH = HSS_PARAMS::SignatureSize();

    HSS_MessageAccumulator() { Restart(); }

    HSS_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng);
        Restart();
    }

    void Update(const byte *msg, size_t len) override {
        if (len == 0) return;
        if (!msg)
            throw InvalidArgument("HSS: Update called with null pointer and non-zero length");
        m_msg.insert(m_msg.end(), msg, msg + len);
    }

    void Restart() override {
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

/// \brief HSS public key
/// \tparam HSS_PARAMS HSS parameter set
/// \details Contains L followed by the root LMS public key.
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
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const override;

    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const override;
    void AssignFrom(const NameValuePairs &source) override;

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
    void Save(BufferedTransformation &bt) const override { DEREncode(bt); }
    void Load(BufferedTransformation &bt) override { BERDecode(bt); }

private:
    SecByteBlock m_pk;
};

// ******************** HSS Private Key ************************* //

/// \brief HSS private key material
/// \tparam HSS_PARAMS HSS parameter set
/// \details Contains root seed and identifier material. Child keys are
///  derived as needed. Signing progress is held by SignerStateStore.
template <class HSS_PARAMS>
class HSSPrivateKey : public PrivateKey
{
public:
    CRYPTOPP_CONSTANT(SEED_SIZE = HSS_PARAMS::template OTSParamsAt<0>::N);
    CRYPTOPP_CONSTANT(I_SIZE = 16);

    HSSPrivateKey() : m_seed(SEED_SIZE), m_I(I_SIZE) {}
    virtual ~HSSPrivateKey() = default;

    /// \brief Get the algorithm OID
    OID GetAlgorithmID() const { return ASN1::id_alg_hss_lms_hashsig(); }

    bool Validate(RandomNumberGenerator &rng, unsigned int level) const override;

    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const override;
    void AssignFrom(const NameValuePairs &source) override;

    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params) override;

    void SetPrivateKey(const byte *seed, size_t seedLen,
                       const byte *identifier, size_t idLen);
    const byte* GetSeedBytePtr() const { return m_seed.begin(); }
    const byte* GetIdentifierBytePtr() const { return m_I.begin(); }

    /// \brief Compute the HSS public key
    void MakePublicKey(HSSPublicKey<HSS_PARAMS> &pub) const;

    /// \brief Library PKCS#8 wrapping
    /// \details For cryptopp-modern persistence only. Not an RFC-defined
    ///  HSS private key format. Not portable across implementations.
    void DEREncode(BufferedTransformation &bt) const;
    void BERDecode(BufferedTransformation &bt);
    void Save(BufferedTransformation &bt) const override { DEREncode(bt); }
    void Load(BufferedTransformation &bt) override { BERDecode(bt); }

private:
    SecByteBlock m_seed;
    SecByteBlock m_I;
};

// ******************** HSS Verifier ************************* //

/// \brief HSS signature verifier
/// \tparam HSS_PARAMS HSS parameter set
/// \details Verifies the signed public-key chain and final message
///  signature. Rejects truncation, trailing data, and mismatched type IDs.
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

    std::string AlgorithmName() const override { return HSS_PARAMS::StaticAlgorithmName(); }

    // PublicKeyAlgorithm interface
    PublicKey& AccessPublicKey() override { return m_key; }
    const PublicKey& GetPublicKey() const override { return m_key; }

    // PK_SignatureScheme interface
    size_t SignatureLength() const override { return SIGNATURE_LENGTH; }
    size_t MaxRecoverableLength() const override { return 0; }
    size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const override {
        CRYPTOPP_UNUSED(signatureLength);
        return 0;
    }

    bool IsProbabilistic() const override { return false; }
    bool AllowNonrecoverablePart() const override { return true; }
    bool RecoverablePartFirst() const override { return false; }

    // PK_Verifier interface
    PK_MessageAccumulator* NewVerificationAccumulator() const override {
        return new MessageAccumulatorType();
    }

    void InputSignature(PK_MessageAccumulator &messageAccumulator,
        const byte *signature, size_t signatureLength) const override {
        if (!signature || signatureLength != SIGNATURE_LENGTH)
            throw InvalidArgument(AlgorithmName() + ": invalid signature length");
        MessageAccumulatorType &accum = static_cast<MessageAccumulatorType&>(messageAccumulator);
        std::memcpy(accum.signature(), signature, SIGNATURE_LENGTH);
    }

    bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const override;

    DecodingResult RecoverAndRestart(byte *recoveredMessage,
        PK_MessageAccumulator &messageAccumulator) const override {
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
///  derives per-level LMS indices from that value and rebuilds subtree
///  state as needed. Not thread-safe.
template <class HSS_PARAMS>
class HSSSigner : public PK_StatefulSigner
{
public:
    typedef HSS_PARAMS Parameters;
    typedef HSSPrivateKey<HSS_PARAMS> PrivateKeyType;

    static const size_t SIGNATURE_LENGTH = HSS_PARAMS::SignatureSize();

    virtual ~HSSSigner() = default;

    /// \brief Construct signer bound to a private key and state store
    /// \details The store capacity must match HSS_PARAMS::TotalSignatures().
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
    bool IsExhausted() const override
    {
        if (!m_store)
            throw SignerStateIntegrityFailure(AlgorithmName() + ": state store is null");
        return m_store->IsExhausted();
    }

    uint64_t RemainingSignatures() const override
    {
        if (!m_store)
            throw SignerStateIntegrityFailure(AlgorithmName() + ": state store is null");
        return m_store->RemainingSignatures();
    }

    /// \brief Sign a message
    /// \details Consumes one global signing index. A failure after
    ///  reservation burns that index.
    void SignMessage(
        RandomNumberGenerator &rng,
        const byte *message, size_t messageLen,
        byte *signature) override;

    const PrivateKeyType &GetKey() const { return m_rootKey; }

private:
    PrivateKeyType m_rootKey;
    SignerStateStore *m_store;  // non-owning, caller manages lifetime

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

/// 4-level HSS with H5/W8: 1,048,576 signatures
typedef HSS_Params<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8, 4> HSS_SHA256_H5_W8_L4_Params;
typedef HSS<HSS_SHA256_H5_W8_L4_Params> HSS_SHA256_H5_W8_L4;

//@}

NAMESPACE_END

#endif  // CRYPTOPP_HSS_H
