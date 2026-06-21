// lms.h - written and placed in the public domain by Colin Brown
//         LMS (Leighton-Micali Signatures) - RFC 8554, NIST SP 800-208
//         SHA-256 parameter sets (H5, H10; LM-OTS W1, W2, W4, W8)

/// \file lms.h
/// \brief LMS stateful hash-based signature scheme (RFC 8554)
/// \details LMS is a stateful hash-based signature scheme standardized in
///  NIST SP 800-208. Each signature consumes signer state (a one-time
///  signing index). Index reuse breaks security.
/// \details The signer uses PK_StatefulSigner (not PK_Signer) to make
///  the stateful nature explicit. The verifier uses the conventional
///  PK_Verifier interface.
/// \details Supports SHA-256 LMS tree heights H=5 (32 signatures) and
///  H=10 (1024 signatures) with SHA-256/N32 LM-OTS Winternitz parameters
///  W=1, W=2, W=4, and W=8.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554">RFC 8554</A>,
///  <A HREF="https://csrc.nist.gov/pubs/sp/800/208/final">NIST SP 800-208</A>
/// \since cryptopp-modern 2026.6.0

#ifndef CRYPTOPP_LMS_H
#define CRYPTOPP_LMS_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/stateful.h>
#include <cryptopp/misc.h>
#include <cryptopp/allocate.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include <cstring>
#include <vector>

NAMESPACE_BEGIN(CryptoPP)

// ******************** LM-OTS Parameter Sets ************************* //

/// \brief LM-OTS SHA256/N32/W1 parameters
/// \details Winternitz W=1, 8516-byte OTS signatures.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-4">RFC 8554 Section 4</A>
struct LMOTS_SHA256_N32_W1
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x01);
    CRYPTOPP_CONSTANT(N = 32);
    CRYPTOPP_CONSTANT(W = 1);
    CRYPTOPP_CONSTANT(P = 265);
    CRYPTOPP_CONSTANT(U = 256);    // ceil(8*N/W) = message coefficients
    CRYPTOPP_CONSTANT(LS = 7);
    CRYPTOPP_CONSTANT(SIG_LEN = 4 + 32 + 265 * 32);  // 8516
    static_assert(SIG_LEN == 4 + N + P * N, "LMOTS W1 SIG_LEN mismatch");

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMOTS-SHA256-N32-W1"; }
};

/// \brief LM-OTS SHA256/N32/W2 parameters
/// \details Winternitz W=2, 4292-byte OTS signatures.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-4">RFC 8554 Section 4</A>
struct LMOTS_SHA256_N32_W2
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x02);
    CRYPTOPP_CONSTANT(N = 32);
    CRYPTOPP_CONSTANT(W = 2);
    CRYPTOPP_CONSTANT(P = 133);
    CRYPTOPP_CONSTANT(U = 128);    // ceil(8*N/W) = message coefficients
    CRYPTOPP_CONSTANT(LS = 6);
    CRYPTOPP_CONSTANT(SIG_LEN = 4 + 32 + 133 * 32);  // 4292
    static_assert(SIG_LEN == 4 + N + P * N, "LMOTS W2 SIG_LEN mismatch");

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMOTS-SHA256-N32-W2"; }
};

/// \brief LM-OTS SHA256/N32/W4 parameters
/// \details Winternitz W=4, 2180-byte OTS signatures.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-4">RFC 8554 Section 4</A>
struct LMOTS_SHA256_N32_W4
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x03);
    CRYPTOPP_CONSTANT(N = 32);
    CRYPTOPP_CONSTANT(W = 4);
    CRYPTOPP_CONSTANT(P = 67);
    CRYPTOPP_CONSTANT(U = 64);    // ceil(8*N/W) = message coefficients
    CRYPTOPP_CONSTANT(LS = 4);
    CRYPTOPP_CONSTANT(SIG_LEN = 4 + 32 + 67 * 32);  // 2180
    static_assert(SIG_LEN == 4 + N + P * N, "LMOTS W4 SIG_LEN mismatch");

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMOTS-SHA256-N32-W4"; }
};

/// \brief LM-OTS SHA256/N32/W8 parameters
/// \details LMOTS_SHA256_N32_W8 uses SHA-256 with a 32-byte hash output
///  and Winternitz parameter W=8. This gives the smallest OTS signatures
///  (1124 bytes) and is the most common parameter choice.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-4">RFC 8554 Section 4</A>
struct LMOTS_SHA256_N32_W8
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x04);
    CRYPTOPP_CONSTANT(N = 32);
    CRYPTOPP_CONSTANT(W = 8);
    CRYPTOPP_CONSTANT(P = 34);
    CRYPTOPP_CONSTANT(U = 32);    // ceil(8*N/W) = message coefficients
    CRYPTOPP_CONSTANT(LS = 0);
    CRYPTOPP_CONSTANT(SIG_LEN = 4 + 32 + 34 * 32);  // 1124

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMOTS-SHA256-N32-W8"; }
};

// ******************** LMS Parameter Sets ************************* //

/// \brief LMS SHA256/M32/H5 parameters (32 signatures)
/// \details Tree height 5 gives 2^5 = 32 one-time signing keys.
///  Suitable for testing and low-volume signing.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-5">RFC 8554 Section 5</A>
struct LMS_SHA256_M32_H5
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x05);
    CRYPTOPP_CONSTANT(M = 32);
    CRYPTOPP_CONSTANT(H = 5);
    CRYPTOPP_CONSTANT(TOTAL_LEAVES = 1u << 5);  // 32

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMS-SHA256-M32-H5"; }
};

/// \brief LMS SHA256/M32/H10 parameters (1024 signatures)
/// \details Tree height 10 gives 2^10 = 1024 one-time signing keys.
///  Suitable for moderate-volume signing.
/// \sa <A HREF="https://www.rfc-editor.org/rfc/rfc8554#section-5">RFC 8554 Section 5</A>
struct LMS_SHA256_M32_H10
{
    CRYPTOPP_CONSTANT(TYPE_ID = 0x06);
    CRYPTOPP_CONSTANT(M = 32);
    CRYPTOPP_CONSTANT(H = 10);
    CRYPTOPP_CONSTANT(TOTAL_LEAVES = 1u << 10);  // 1024

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "LMS-SHA256-M32-H10"; }
};

// ******************** LMS Message Accumulator ************************* //

/// \brief LMS message accumulator
/// \details Buffers the entire message before verification. The first
///  bytes of storage are reserved for the signature during verification.
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMS_MessageAccumulator : public PK_MessageAccumulator
{
    // LMS signature: q(4) + OTS sig(4+n+p*n) + LMS type(4) + auth path(h*m)
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH =
        4 + OTS_PARAMS::SIG_LEN + 4 +
        static_cast<int>(LMS_PARAMS::H) * static_cast<int>(LMS_PARAMS::M));
    CRYPTOPP_CONSTANT(RESERVE_SIZE = 2048 + SIGNATURE_LENGTH);

    /// \brief Create a message accumulator
    LMS_MessageAccumulator() { Restart(); }

    /// \brief Create a message accumulator with RNG
    LMS_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng);
        Restart();
    }

    /// \brief Add data to the accumulator
    void Update(const byte *msg, size_t len) override {
        if (len == 0) return;
        if (!msg)
            throw InvalidArgument("LMS: Update called with null pointer and non-zero length");
        m_msg.insert(m_msg.end(), msg, msg + len);
    }

    /// \brief Reset the accumulator
    void Restart() override {
        m_msg.clear();
        m_msg.reserve(RESERVE_SIZE);
        m_msg.resize(SIGNATURE_LENGTH);
    }

    /// \brief Retrieve pointer to signature buffer
    byte* signature() { return m_msg.data(); }

    /// \brief Retrieve pointer to signature buffer (const)
    const byte* signature() const { return m_msg.data(); }

    /// \brief Retrieve pointer to message data (after signature area)
    const byte* data() const { return m_msg.data() + SIGNATURE_LENGTH; }

    /// \brief Retrieve size of message data
    size_t size() const { return m_msg.size() - SIGNATURE_LENGTH; }

protected:
    std::vector<byte, AllocatorWithCleanup<byte> > m_msg;
};

// ******************** LMS Public Key ************************* //

/// \brief LMS public key (verification key)
/// \tparam LMS_PARAMS LMS parameter set (tree parameters)
/// \tparam OTS_PARAMS LM-OTS parameter set (one-time signature parameters)
/// \details The public key contains the LMS type, OTS type, 16-byte
///  identifier I, and the Merkle tree root hash T[1].
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMSPublicKey : public PublicKey
{
    // Public key: LMS type(4) + OTS type(4) + I(16) + T[1](m)
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 4 + 4 + 16 + LMS_PARAMS::M);

    LMSPublicKey() : m_pk(PUBLIC_KEY_SIZE) { std::memset(m_pk, 0, PUBLIC_KEY_SIZE); }
    virtual ~LMSPublicKey() = default;

    /// \brief Get the algorithm OID
    /// \details All LMS parameter sets share a single OID (RFC 8554, RFC 8708).
    OID GetAlgorithmID() const { return ASN1::id_alg_hss_lms_hashsig(); }

    /// \brief Check this object for errors
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const override;

    /// \brief Get a named value
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const override;

    /// \brief Assign contents from another source
    void AssignFrom(const NameValuePairs &source) override;

    /// \brief Set the public key from raw bytes
    /// \param pk pointer to public key data
    /// \param len length of public key (must be PUBLIC_KEY_SIZE)
    void SetPublicKey(const byte *pk, size_t len);

    /// \brief Get pointer to public key bytes
    const byte* GetPublicKeyBytePtr() const { return m_pk.begin(); }

    /// \brief Get public key size in bytes
    size_t GetPublicKeyByteLength() const { return PUBLIC_KEY_SIZE; }

    /// \brief Get pointer to identifier I (16 bytes, offset 8 in public key)
    const byte* GetI() const { return m_pk.begin() + 8; }

    /// \brief Get pointer to tree root T[1] (m bytes, offset 24 in public key)
    const byte* GetRoot() const { return m_pk.begin() + 24; }

    /// \brief DER encode the public key (X.509 SubjectPublicKeyInfo format)
    /// \param bt BufferedTransformation to write to
    /// \details Per RFC 8708, the public key bytes are placed directly in
    ///  the BIT STRING with no additional ASN.1 wrapping. Algorithm
    ///  parameters MUST be absent (not NULL).
    void DEREncode(BufferedTransformation &bt) const;

    /// \brief BER decode the public key (X.509 SubjectPublicKeyInfo format)
    /// \param bt BufferedTransformation to read from
    void BERDecode(BufferedTransformation &bt);

    /// \brief Save the key to a BufferedTransformation
    void Save(BufferedTransformation &bt) const override { DEREncode(bt); }

    /// \brief Load the key from a BufferedTransformation
    void Load(BufferedTransformation &bt) override { BERDecode(bt); }

private:
    SecByteBlock m_pk;
};

// ******************** LMS Private Key ************************* //

/// \brief LMS private key material (signing key)
/// \tparam LMS_PARAMS LMS parameter set (tree parameters)
/// \tparam OTS_PARAMS LM-OTS parameter set (one-time signature parameters)
/// \details The private key contains the secret seed and identifier I.
///  The leaf index lives in the SignerStateStore, not in the key.
///  Serialising and deserialising a private key does not restore
///  signing capability; a valid state store is required.
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMSPrivateKey : public PrivateKey
{
    CRYPTOPP_CONSTANT(SEED_SIZE = OTS_PARAMS::N);
    CRYPTOPP_CONSTANT(I_SIZE = 16);

    LMSPrivateKey() : m_seed(SEED_SIZE), m_I(I_SIZE) {}
    virtual ~LMSPrivateKey() = default;

    /// \brief Get the algorithm OID
    OID GetAlgorithmID() const { return ASN1::id_alg_hss_lms_hashsig(); }

    /// \brief Check this object for errors
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const override;

    /// \brief Get a named value
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const override;

    /// \brief Assign contents from another source
    void AssignFrom(const NameValuePairs &source) override;

    /// \brief Generate a random key pair
    /// \param rng a RandomNumberGenerator to produce keying material
    /// \param params additional initialization parameters (unused)
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params) override;

    /// \brief Set the private key from seed and identifier
    /// \param seed pointer to the secret seed (SEED_SIZE bytes)
    /// \param seedLen length of seed
    /// \param identifier pointer to the identifier I (I_SIZE bytes)
    /// \param idLen length of identifier
    void SetPrivateKey(const byte *seed, size_t seedLen,
                       const byte *identifier, size_t idLen);

    /// \brief Get pointer to secret seed
    const byte* GetSeedBytePtr() const { return m_seed.begin(); }

    /// \brief Get pointer to identifier I
    const byte* GetIdentifierBytePtr() const { return m_I.begin(); }

    /// \brief Compute the corresponding public key
    /// \param pub receives the computed public key
    /// \details This computes the full Merkle tree root from the seed.
    ///  It is an expensive operation proportional to 2^h hash evaluations.
    void MakePublicKey(LMSPublicKey<LMS_PARAMS, OTS_PARAMS> &pub) const;

    /// \brief DER encode the private key (library PKCS#8 wrapping)
    /// \param bt BufferedTransformation to write to
    /// \details Uses a PKCS#8 wrapper with the LMS OID and an opaque
    ///  inner OCTET STRING carrying SEED || I. This is a library-defined
    ///  format, not an RFC-standardised private key encoding.
    ///  Does not contain signing progress; reconstructing a
    ///  signer requires a valid state store.
    void DEREncode(BufferedTransformation &bt) const;

    /// \brief BER decode the private key (library PKCS#8 wrapping)
    /// \param bt BufferedTransformation to read from
    void BERDecode(BufferedTransformation &bt);

    /// \brief Save the key to a BufferedTransformation
    void Save(BufferedTransformation &bt) const override { DEREncode(bt); }

    /// \brief Load the key from a BufferedTransformation
    void Load(BufferedTransformation &bt) override { BERDecode(bt); }

private:
    SecByteBlock m_seed;    // SEED (n bytes)
    SecByteBlock m_I;       // identifier (16 bytes)
};

// ******************** LMS Verifier ************************* //

/// \brief LMS signature verifier (stateless)
/// \tparam LMS_PARAMS LMS parameter set
/// \tparam OTS_PARAMS LM-OTS parameter set
/// \details LMSVerifier uses the conventional PK_Verifier interface.
///  Verification is entirely stateless.
/// \note The full PK_Verifier surface is implemented because PK_Verifier
///  requires these methods. Most are trivial one-liners. The real work
///  is in VerifyAndRestart().
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMSVerifier : public PK_Verifier
{
    typedef LMS_PARAMS LMSParameters;
    typedef OTS_PARAMS OTSParameters;
    typedef LMSPublicKey<LMS_PARAMS, OTS_PARAMS> PublicKeyType;
    typedef LMS_MessageAccumulator<LMS_PARAMS, OTS_PARAMS> MessageAccumulatorType;

    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = MessageAccumulatorType::SIGNATURE_LENGTH);

    virtual ~LMSVerifier() = default;

    /// \brief Default constructor
    LMSVerifier() {}

    /// \brief Construct from public key bytes
    LMSVerifier(const byte *publicKey, size_t len);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const override {
        return LMS_PARAMS::StaticAlgorithmName() + "/" + OTS_PARAMS::StaticAlgorithmName();
    }

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
        throw NotImplemented("LMSVerifier: recoverable messages not supported");
    }

    /// \brief Access the public key (typed)
    PublicKeyType& AccessKey() { return m_key; }

    /// \brief Get the public key (typed)
    const PublicKeyType& GetKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** LMS Signer ************************* //

/// \brief LMS stateful signature signer
/// \tparam LMS_PARAMS LMS parameter set
/// \tparam OTS_PARAMS LM-OTS parameter set
/// \details LMSSigner uses PK_StatefulSigner (not PK_Signer) because
///  each signature consumes a one-time signing index. The signer is
///  non-copyable and must be bound to a SignerStateStore.
/// \details The caller must ensure the state store outlives the signer.
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMSSigner : public PK_StatefulSigner
{
    typedef LMS_PARAMS LMSParameters;
    typedef OTS_PARAMS OTSParameters;
    typedef LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> PrivateKeyType;

    static const size_t SIGNATURE_LENGTH =
        4 + OTS_PARAMS::SIG_LEN + 4 +
        static_cast<size_t>(LMS_PARAMS::H) * static_cast<size_t>(LMS_PARAMS::M);

    virtual ~LMSSigner() = default;

    /// \brief Construct a signer bound to a private key and state store
    /// \param key the private key (seed + identifier)
    /// \param store the state backend (caller manages lifetime)
    LMSSigner(const PrivateKeyType &key, SignerStateStore &store);

    // Non-copyable
    LMSSigner(const LMSSigner &) = delete;
    LMSSigner &operator=(const LMSSigner &) = delete;

    // Movable
    LMSSigner(LMSSigner &&) = default;
    LMSSigner &operator=(LMSSigner &&) = default;

    // PK_StatefulSigner interface
    std::string AlgorithmName() const override {
        return LMS_PARAMS::StaticAlgorithmName() + "/" + OTS_PARAMS::StaticAlgorithmName();
    }

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

    void SignMessage(
        RandomNumberGenerator &rng,
        const byte *message, size_t messageLen,
        byte *signature) override;

    /// \brief Get the private key (typed)
    const PrivateKeyType &GetKey() const { return m_key; }

private:
    PrivateKeyType m_key;
    SignerStateStore *m_store;  // non-owning, caller manages lifetime
    SecByteBlock m_tree;        // precomputed full Merkle tree
};

// ******************** LMS Scheme ************************* //

/// \brief LMS signature scheme
/// \tparam LMS_PARAMS LMS parameter set
/// \tparam OTS_PARAMS LM-OTS parameter set
template <class LMS_PARAMS, class OTS_PARAMS>
struct LMS
{
    typedef LMSSigner<LMS_PARAMS, OTS_PARAMS> Signer;
    typedef LMSVerifier<LMS_PARAMS, OTS_PARAMS> Verifier;
    typedef LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> PrivateKey;
    typedef LMSPublicKey<LMS_PARAMS, OTS_PARAMS> PublicKey;

    static std::string StaticAlgorithmName() {
        return LMS_PARAMS::StaticAlgorithmName() + "/" + OTS_PARAMS::StaticAlgorithmName();
    }
};

// ******************** Convenience Typedefs ************************* //

/// \name Scheme Typedefs
//@{
typedef LMS<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> LMS_SHA256_H5_W8;
typedef LMS<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8> LMS_SHA256_H10_W8;

typedef LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> LMS_SHA256_H5_W8_Signer;
typedef LMSSigner<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8> LMS_SHA256_H10_W8_Signer;

typedef LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> LMS_SHA256_H5_W8_Verifier;
typedef LMSVerifier<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8> LMS_SHA256_H10_W8_Verifier;
//@}

NAMESPACE_END

#endif  // CRYPTOPP_LMS_H
