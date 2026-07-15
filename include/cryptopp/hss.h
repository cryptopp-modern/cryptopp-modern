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

// Per-level LMS signature size from a level descriptor (RFC 8554 Section 5.4).
template <class Level>
constexpr size_t LmsSigSizeOf()
{
    return 4 + Level::OTSParams::SIG_LEN + 4 +
           static_cast<size_t>(Level::LMSParams::H) *
           static_cast<size_t>(Level::LMSParams::M);
}

// Per-level LMS public key size from a level descriptor (RFC 8554 Section 5.3).
template <class Level>
constexpr size_t LmsPubSizeOf()
{
    return 4 + 4 + 16 + Level::LMSParams::M;
}

// Product of per-level leaf counts. Overflow is checked by
// division-before-multiplication so the guard cannot itself overflow.
template <class... Levels>
struct CapacityOf;

template <>
struct CapacityOf<>
{
    static const bool fits = true;
    static const uint64_t value = 1;
};

template <class Head, class... Tail>
struct CapacityOf<Head, Tail...>
{
    static const uint64_t headLeaves =
        static_cast<uint64_t>(Head::LMSParams::TOTAL_LEAVES);
    static const bool fits = CapacityOf<Tail...>::fits &&
        CapacityOf<Tail...>::value <= UINT64_MAX / headLeaves;
    static const uint64_t value = headLeaves * CapacityOf<Tail...>::value;
};

// Sum of per-level LMS signature sizes over all levels.
template <class... Levels>
struct SumSigSizes;

template <>
struct SumSigSizes<>
{
    static constexpr size_t value() { return 0; }
};

template <class Head, class... Tail>
struct SumSigSizes<Head, Tail...>
{
    static constexpr size_t value()
    {
        return LmsSigSizeOf<Head>() + SumSigSizes<Tail...>::value();
    }
};

// Sum of per-level LMS public key sizes over all levels.
template <class... Levels>
struct SumPubSizes;

template <>
struct SumPubSizes<>
{
    static constexpr size_t value() { return 0; }
};

template <class Head, class... Tail>
struct SumPubSizes<Head, Tail...>
{
    static constexpr size_t value()
    {
        return LmsPubSizeOf<Head>() + SumPubSizes<Tail...>::value();
    }
};

// True when every level shares one LM-OTS hash output size N.
template <class... Levels>
struct SameN;

template <>
struct SameN<>
{
    static const bool value = true;
};

template <class Head>
struct SameN<Head>
{
    static const bool value = true;
};

template <class First, class Second, class... Tail>
struct SameN<First, Second, Tail...>
{
    static const bool value =
        (static_cast<size_t>(First::OTSParams::N) ==
         static_cast<size_t>(Second::OTSParams::N)) &&
        SameN<Second, Tail...>::value;
};

// True when every level's LMS hash output size M matches its LM-OTS N.
// Each level defers to the pair-level CompatibleLMSParams trait.
template <class... Levels>
struct MatchingMN;

template <>
struct MatchingMN<>
{
    static const bool value = true;
};

template <class Head, class... Tail>
struct MatchingMN<Head, Tail...>
{
    static const bool value =
        CompatibleLMSParams<typename Head::LMSParams,
                            typename Head::OTSParams>::value &&
        MatchingMN<Tail...>::value;
};

// Append each level's "<LMSname>/<OTSname>" to out, top level first.
template <class... Levels>
struct LevelNames;

template <>
struct LevelNames<>
{
    static void Append(std::vector<std::string> &) {}
};

template <class Head, class... Tail>
struct LevelNames<Head, Tail...>
{
    static void Append(std::vector<std::string> &out)
    {
        out.push_back(Head::LMSParams::StaticAlgorithmName() + "/" +
                      Head::OTSParams::StaticAlgorithmName());
        LevelNames<Tail...>::Append(out);
    }
};

} // namespace HSS_Internal

// ******************** HSS Parameter Sets ************************* //

/// \brief One level descriptor in an HSS hierarchy
/// \tparam LMS_PARAMS LMS parameter set for this level
/// \tparam OTS_PARAMS LM-OTS parameter set for this level
/// \details Levels are ordered top (root) first. A uniform configuration
///  repeats the same descriptor at every level.
template <class LMS_PARAMS, class OTS_PARAMS>
struct HSSLevel
{
    typedef LMS_PARAMS LMSParams;
    typedef OTS_PARAMS OTSParams;
};

/// \brief HSS parameter set with per-level LMS and LM-OTS choices
/// \tparam Levels two to four HSSLevel descriptors, top (root) level first
/// \details Uniform configurations repeat the same HSSLevel at every level.
///  All levels must share one LM-OTS hash output size N, and each level's
///  LMS hash output size M must match its LM-OTS N.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-6">RFC 8554 Section 6</A>
template <class... Levels>
struct HSS_Params
{
    static_assert(sizeof...(Levels) >= 2, "HSS requires at least 2 levels");
    static_assert(sizeof...(Levels) <= 4, "HSS supports up to 4 levels");
    static_assert(HSS_Internal::SameN<Levels...>::value,
        "HSS levels must share one LM-OTS hash output size N");
    static_assert(HSS_Internal::MatchingMN<Levels...>::value,
        "HSS level LMS M must match its LM-OTS N");

    CRYPTOPP_CONSTANT(L = sizeof...(Levels));

    /// \brief Level descriptor at level I
    template <unsigned int I>
    using LevelAt = typename HSS_Internal::TypeAt<I, Levels...>::type;

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
        return HSS_Internal::LmsSigSizeOf<LevelAt<I> >();
    }

    /// \brief LMS public key size at level I
    template <unsigned int I>
    static constexpr size_t LMSPublicKeySizeAt()
    {
        return HSS_Internal::LmsPubSizeOf<LevelAt<I> >();
    }

    /// \brief Leaf count of the level-I tree
    template <unsigned int I>
    static constexpr uint64_t LeavesAt()
    {
        return static_cast<uint64_t>(LMSParamsAt<I>::TOTAL_LEAVES);
    }

    /// \brief Check if total capacity fits in uint64_t
    static constexpr bool CapacityFitsUint64()
    {
        return HSS_Internal::CapacityOf<Levels...>::fits;
    }

    static_assert(CapacityFitsUint64(), "HSS capacity exceeds uint64_t");

    /// \brief Total signing capacity
    static constexpr uint64_t TotalSignatures()
    {
        return HSS_Internal::CapacityOf<Levels...>::value;
    }

    /// \brief HSS signature size
    /// \details u32(Nspk) + an LMS signature at every level + the embedded
    ///  child public key at every level below the root (RFC 8554 Section 6).
    static constexpr size_t SignatureSize()
    {
        return 4 + HSS_Internal::SumSigSizes<Levels...>::value()
                 + HSS_Internal::SumPubSizes<Levels...>::value()
                 - LMSPublicKeySizeAt<0>();
    }

    /// \brief HSS public key size
    /// \details u32(L) + root LMS public key
    static constexpr size_t PublicKeySize()
    {
        return 4 + LMSPublicKeySizeAt<0>();
    }

    /// \brief Algorithm name
    /// \details Uniform configurations keep the HSS[L]/<lms>/<ots> form. Mixed
    ///  configurations list each level: HSS[L]/(<l0>,<l1>,...).
    static std::string StaticAlgorithmName()
    {
        std::vector<std::string> names;
        HSS_Internal::LevelNames<Levels...>::Append(names);

        bool uniform = true;
        for (size_t i = 1; i < names.size(); i++)
            if (names[i] != names[0]) { uniform = false; break; }

        const std::string prefix = "HSS[" + std::to_string(sizeof...(Levels)) + "]/";
        if (uniform)
            return prefix + names[0];

        std::string out = prefix + "(";
        for (size_t i = 0; i < names.size(); i++)
        {
            if (i) out += ",";
            out += names[i];
        }
        return out + ")";
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
typedef HSS_Params<
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> > HSS_SHA256_H5_W8_L2_Params;
typedef HSS<HSS_SHA256_H5_W8_L2_Params> HSS_SHA256_H5_W8_L2;

/// 2-level HSS with H10/W8: 1,048,576 signatures
typedef HSS_Params<
    HSSLevel<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8> > HSS_SHA256_H10_W8_L2_Params;
typedef HSS<HSS_SHA256_H10_W8_L2_Params> HSS_SHA256_H10_W8_L2;

/// 3-level HSS with H5/W8: 32,768 signatures
typedef HSS_Params<
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> > HSS_SHA256_H5_W8_L3_Params;
typedef HSS<HSS_SHA256_H5_W8_L3_Params> HSS_SHA256_H5_W8_L3;

/// 4-level HSS with H5/W8: 1,048,576 signatures
typedef HSS_Params<
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>,
    HSSLevel<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> > HSS_SHA256_H5_W8_L4_Params;
typedef HSS<HSS_SHA256_H5_W8_L4_Params> HSS_SHA256_H5_W8_L4;

/// 2-level mixed HSS with H10/W4 over H5/W8: 32,768 signatures (RFC 8554 Appendix F TC2)
typedef HSS_Params<
    HSSLevel<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4>,
    HSSLevel<LMS_SHA256_M32_H5,  LMOTS_SHA256_N32_W8> > HSS_SHA256_H10W4_H5W8_L2_Params;
typedef HSS<HSS_SHA256_H10W4_H5W8_L2_Params> HSS_SHA256_H10W4_H5W8_L2;

//@}

NAMESPACE_END

#endif  // CRYPTOPP_HSS_H
