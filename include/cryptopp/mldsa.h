// mldsa.h - written and placed in the public domain by Colin Brown
//           ML-DSA (FIPS 204) Module-Lattice Digital Signature Algorithm
//           Based on CRYSTALS-Dilithium reference implementation (public domain)

/// \file mldsa.h
/// \brief ML-DSA (FIPS 204) module-lattice digital signature algorithm
/// \details ML-DSA is a digital signature algorithm standardized in FIPS 204,
///  based on the CRYSTALS-Dilithium algorithm. It provides EUF-CMA secure
///  digital signatures resistant to attacks by quantum computers.
/// \details ML-DSA is suitable for general-purpose digital signatures, code
///  signing, certificate signing, and any application requiring post-quantum
///  secure authentication.
/// \details Parameter sets are named ML-DSA-{XX} where XX indicates the
///  security strength: 44 (128-bit), 65 (192-bit), or 87 (256-bit).
/// \sa <A HREF="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</A>
/// \since cryptopp-modern 2026.3.0

#ifndef CRYPTOPP_MLDSA_H
#define CRYPTOPP_MLDSA_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/misc.h>
#include <cryptopp/allocate.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include <vector>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Parameter Sets ************************* //

/// \brief ML-DSA-44 parameters (NIST security level 2)
/// \details Provides approximately 128-bit security against classical and
///  quantum attacks. Good balance of security and performance for most uses.
struct MLDSA_44
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 1312);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 2560);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 2420);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 2);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-DSA-44"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_dsa_44(); }
};

/// \brief ML-DSA-65 parameters (NIST security level 3)
/// \details Provides approximately 192-bit security against classical and
///  quantum attacks. Recommended default for most applications.
struct MLDSA_65
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 1952);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 4032);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 3309);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-DSA-65"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_dsa_65(); }
};

/// \brief ML-DSA-87 parameters (NIST security level 5)
/// \details Provides approximately 256-bit security against classical and
///  quantum attacks. Highest security level available.
struct MLDSA_87
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 2592);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 4896);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 4627);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-DSA-87"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_dsa_87(); }
};

// ******************** ML-DSA Message Accumulator ************************* //

/// \brief ML-DSA message accumulator
/// \tparam PARAMS parameter set (MLDSA_44, MLDSA_65, or MLDSA_87)
/// \details ML-DSA buffers the entire message before signing/verification.
///  The first bytes of storage are reserved for the signature during verification.
template <class PARAMS>
struct MLDSA_MessageAccumulator : public PK_MessageAccumulator
{
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);
    CRYPTOPP_CONSTANT(RESERVE_SIZE = 2048 + SIGNATURE_LENGTH);

    /// \brief Create a message accumulator
    MLDSA_MessageAccumulator() { Restart(); }

    /// \brief Create a message accumulator with RNG
    /// \param rng a RandomNumberGenerator (unused, for interface compatibility)
    MLDSA_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng);
        Restart();
    }

    /// \brief Add data to the accumulator
    /// \param msg pointer to message data
    /// \param len length of message data in bytes
    void Update(const byte *msg, size_t len) {
        if (len == 0) return;
        if (!msg)
            throw InvalidArgument("ML-DSA: Update called with null pointer and non-zero length");
        m_msg.insert(m_msg.end(), msg, msg + len);
    }

    /// \brief Set the context string for signing/verification
    /// \details FIPS 204 Section 5.2 allows an optional context string (up to 255 bytes)
    ///  that is included in the message prefix. Empty by default (pure signing mode).
    /// \param ctx pointer to context data (may be NULL if ctxLen is 0)
    /// \param ctxLen length of context in bytes (max 255 per FIPS 204)
    void SetContext(const byte *ctx, size_t ctxLen) {
        if (ctxLen > 255)
            throw InvalidArgument("ML-DSA: context string exceeds 255 bytes");
        if (ctx && ctxLen)
            m_ctx.assign(ctx, ctx + ctxLen);
        else
            m_ctx.clear();
    }

    /// \brief Get pointer to context data
    const byte* context() const { return m_ctx.data(); }

    /// \brief Get context size in bytes
    size_t contextSize() const { return m_ctx.size(); }

    /// \brief Reset the accumulator
    void Restart() {
        m_msg.reserve(RESERVE_SIZE);
        m_msg.resize(SIGNATURE_LENGTH);
    }

    /// \brief Retrieve pointer to signature buffer
    byte* signature() { return m_msg.data(); }

    /// \brief Retrieve pointer to signature buffer
    const byte* signature() const { return m_msg.data(); }

    /// \brief Retrieve pointer to data buffer
    const byte* data() const { return m_msg.data() + SIGNATURE_LENGTH; }

    /// \brief Retrieve size of data buffer
    size_t size() const { return m_msg.size() - SIGNATURE_LENGTH; }

protected:
    std::vector<byte, AllocatorWithCleanup<byte> > m_msg;
    std::vector<byte, AllocatorWithCleanup<byte> > m_ctx;
};

// ******************** ML-DSA Private Key ************************* //

/// \brief ML-DSA private key (signing key)
/// \tparam PARAMS parameter set (MLDSA_44, MLDSA_65, or MLDSA_87)
/// \details MLDSAPrivateKey holds the secret key material for signing messages.
///  It also contains the embedded public key for convenience.
template <class PARAMS>
struct MLDSAPrivateKey : public PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);

    virtual ~MLDSAPrivateKey() {}

    /// \brief Get the algorithm OID
    OID GetAlgorithmID() const { return PARAMS::StaticAlgorithmOID(); }

    /// \brief Check this object for errors
    /// \param rng a RandomNumberGenerator for objects which use randomized testing
    /// \param level the level of thoroughness
    /// \return true if the tests pass
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;

    /// \brief Get a named value
    /// \param name the name of the value to retrieve
    /// \param valueType reference to a variable that receives the value type
    /// \param pValue void pointer to a variable that receives the value
    /// \return true if the value was retrieved
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;

    /// \brief Assign contents from another source
    /// \param source the source NameValuePairs
    void AssignFrom(const NameValuePairs &source);

    /// \brief Generate a random key
    /// \param rng a RandomNumberGenerator to produce keying material
    /// \param params additional initialization parameters
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);

    /// \brief Set the private key bytes
    /// \param key pointer to the private key data
    /// \param len length of the private key (must be SECRET_KEYLENGTH)
    void SetPrivateKey(const byte *key, size_t len);

    /// \brief Get pointer to private key bytes
    const byte* GetPrivateKeyBytePtr() const { return m_sk.begin(); }

    /// \brief Get pointer to public key bytes
    const byte* GetPublicKeyBytePtr() const { return m_pk.begin(); }

    /// \brief Get private key size in bytes
    size_t GetPrivateKeySize() const { return SECRET_KEYLENGTH; }

    /// \brief Get public key size in bytes
    size_t GetPublicKeySize() const { return PUBLIC_KEYLENGTH; }

    /// \brief DER encode the private key (PKCS#8 OneAsymmetricKey format)
    /// \param bt BufferedTransformation to write to
    void DEREncode(BufferedTransformation &bt) const;

    /// \brief BER decode the private key (PKCS#8 OneAsymmetricKey format)
    /// \param bt BufferedTransformation to read from
    void BERDecode(BufferedTransformation &bt);

    /// \brief Save the key to a BufferedTransformation
    /// \param bt BufferedTransformation to write to
    void Save(BufferedTransformation &bt) const { DEREncode(bt); }

    /// \brief Load the key from a BufferedTransformation
    /// \param bt BufferedTransformation to read from
    void Load(BufferedTransformation &bt) { BERDecode(bt); }

private:
    SecByteBlock m_sk;
    SecByteBlock m_pk;
};

// ******************** ML-DSA Public Key ************************* //

/// \brief ML-DSA public key (verification key)
/// \tparam PARAMS parameter set (MLDSA_44, MLDSA_65, or MLDSA_87)
/// \details MLDSAPublicKey holds the public key material for verifying signatures.
template <class PARAMS>
struct MLDSAPublicKey : public PublicKey
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);

    virtual ~MLDSAPublicKey() {}

    /// \brief Get the algorithm OID
    OID GetAlgorithmID() const { return PARAMS::StaticAlgorithmOID(); }

    /// \brief Check this object for errors
    /// \param rng a RandomNumberGenerator for objects which use randomized testing
    /// \param level the level of thoroughness
    /// \return true if the tests pass
    bool Validate(RandomNumberGenerator &rng, unsigned int level) const;

    /// \brief Get a named value
    /// \param name the name of the value to retrieve
    /// \param valueType reference to a variable that receives the value type
    /// \param pValue void pointer to a variable that receives the value
    /// \return true if the value was retrieved
    bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;

    /// \brief Assign contents from another source
    /// \param source the source NameValuePairs
    void AssignFrom(const NameValuePairs &source);

    /// \brief Set the public key bytes
    /// \param key pointer to the public key data
    /// \param len length of the public key (must be PUBLIC_KEYLENGTH)
    void SetPublicKey(const byte *key, size_t len);

    /// \brief Get pointer to public key bytes
    const byte* GetPublicKeyBytePtr() const { return m_pk.begin(); }

    /// \brief Get public key size in bytes
    size_t GetPublicKeySize() const { return PUBLIC_KEYLENGTH; }

    /// \brief DER encode the public key (X.509 SubjectPublicKeyInfo format)
    /// \param bt BufferedTransformation to write to
    void DEREncode(BufferedTransformation &bt) const;

    /// \brief BER decode the public key (X.509 SubjectPublicKeyInfo format)
    /// \param bt BufferedTransformation to read from
    void BERDecode(BufferedTransformation &bt);

    /// \brief Save the key to a BufferedTransformation
    /// \param bt BufferedTransformation to write to
    void Save(BufferedTransformation &bt) const { DEREncode(bt); }

    /// \brief Load the key from a BufferedTransformation
    /// \param bt BufferedTransformation to read from
    void Load(BufferedTransformation &bt) { BERDecode(bt); }

private:
    SecByteBlock m_pk;
};

// ******************** ML-DSA Signer ************************* //

/// \brief ML-DSA digital signature signer
/// \tparam PARAMS parameter set (MLDSA_44, MLDSA_65, or MLDSA_87)
/// \details MLDSASigner provides digital signature generation using the
///  ML-DSA (FIPS 204) algorithm. The signer holds the private key.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   MLDSASigner<MLDSA_65> signer(rng);  // Generate new key pair
///
///   std::string message = "Message to sign";
///   SecByteBlock signature(signer.SignatureLength());
///   size_t sigLen = signer.SignMessage(rng,
///       (const byte*)message.data(), message.size(), signature.begin());
/// \endcode
/// \sa MLDSAVerifier, <A HREF="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</A>
template <class PARAMS>
struct MLDSASigner : public PK_Signer
{
    typedef PARAMS Parameters;
    typedef MLDSAPrivateKey<PARAMS> PrivateKeyType;
    typedef MLDSA_MessageAccumulator<PARAMS> MessageAccumulatorType;

    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~MLDSASigner() {}

    /// \brief Default constructor
    MLDSASigner() {}

    /// \brief Construct and generate a new key pair
    /// \param rng random number generator
    MLDSASigner(RandomNumberGenerator &rng);

    /// \brief Construct from existing private key bytes
    /// \param privateKey pointer to private key bytes
    /// \param privateKeyLen length of private key (must be SECRET_KEY_SIZE)
    MLDSASigner(const byte *privateKey, size_t privateKeyLen);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return PARAMS::StaticAlgorithmName(); }

    // PrivateKeyAlgorithm interface
    PrivateKey& AccessPrivateKey() { return m_key; }
    const PrivateKey& GetPrivateKey() const { return m_key; }

    // PK_SignatureScheme interface
    size_t SignatureLength() const { return SIGNATURE_LENGTH; }
    size_t MaxRecoverableLength() const { return 0; }
    size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const {
        CRYPTOPP_UNUSED(signatureLength);
        return 0;
    }

    bool IsProbabilistic() const { return true; }
    bool AllowNonrecoverablePart() const { return true; }
    bool RecoverablePartFirst() const { return false; }

    // PK_Signer interface
    PK_MessageAccumulator* NewSignatureAccumulator(RandomNumberGenerator &rng) const {
        return new MessageAccumulatorType(rng);
    }

    void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator,
        const byte *recoverableMessage, size_t recoverableMessageLength) const {
        CRYPTOPP_UNUSED(messageAccumulator);
        CRYPTOPP_UNUSED(recoverableMessage);
        CRYPTOPP_UNUSED(recoverableMessageLength);
        throw NotImplemented("MLDSASigner: recoverable messages not supported");
    }

    size_t SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator,
        byte *signature, bool restart = true) const;

    /// \brief Access the private key
    PrivateKeyType& AccessKey() { return m_key; }

    /// \brief Get the private key
    const PrivateKeyType& GetKey() const { return m_key; }

protected:
    PrivateKeyType m_key;
};

// ******************** ML-DSA Verifier ************************* //

/// \brief ML-DSA digital signature verifier
/// \tparam PARAMS parameter set (MLDSA_44, MLDSA_65, or MLDSA_87)
/// \details MLDSAVerifier provides digital signature verification using the
///  ML-DSA (FIPS 204) algorithm. The verifier holds only the public key.
/// \par Example
/// \code
///   MLDSAVerifier<MLDSA_65> verifier;
///   verifier.AccessKey().SetPublicKey(publicKey, publicKeyLen);
///
///   bool valid = verifier.VerifyMessage(
///       (const byte*)message.data(), message.size(),
///       signature, signatureLen);
/// \endcode
/// \sa MLDSASigner, <A HREF="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</A>
template <class PARAMS>
struct MLDSAVerifier : public PK_Verifier
{
    typedef PARAMS Parameters;
    typedef MLDSAPublicKey<PARAMS> PublicKeyType;
    typedef MLDSA_MessageAccumulator<PARAMS> MessageAccumulatorType;

    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~MLDSAVerifier() {}

    /// \brief Default constructor
    MLDSAVerifier() {}

    /// \brief Construct from signer (extract public key)
    /// \param signer the signer whose public key to use
    MLDSAVerifier(const MLDSASigner<PARAMS> &signer);

    /// \brief Construct from public key bytes
    /// \param publicKey pointer to public key bytes
    /// \param publicKeyLen length of public key (must be PUBLIC_KEY_SIZE)
    MLDSAVerifier(const byte *publicKey, size_t publicKeyLen);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return PARAMS::StaticAlgorithmName(); }

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

    bool IsProbabilistic() const { return true; }
    bool AllowNonrecoverablePart() const { return true; }
    bool RecoverablePartFirst() const { return false; }

    // PK_Verifier interface
    PK_MessageAccumulator* NewVerificationAccumulator() const {
        return new MessageAccumulatorType();
    }

    void InputSignature(PK_MessageAccumulator &messageAccumulator,
        const byte *signature, size_t signatureLength) const {
        if (!signature || signatureLength != SIGNATURE_LENGTH)
            throw InvalidArgument(PARAMS::StaticAlgorithmName() + ": invalid signature length");
        MessageAccumulatorType& accum = static_cast<MessageAccumulatorType&>(messageAccumulator);
        std::memcpy(accum.signature(), signature, SIGNATURE_LENGTH);
    }

    bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const;

    DecodingResult RecoverAndRestart(byte *recoveredMessage,
        PK_MessageAccumulator &messageAccumulator) const {
        CRYPTOPP_UNUSED(recoveredMessage);
        CRYPTOPP_UNUSED(messageAccumulator);
        throw NotImplemented("MLDSAVerifier: recoverable messages not supported");
    }

    /// \brief Access the public key
    PublicKeyType& AccessKey() { return m_key; }

    /// \brief Get the public key
    const PublicKeyType& GetKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** ML-DSA Scheme ************************* //

/// \brief ML-DSA signature scheme
/// \tparam PARAMS parameter set
template <class PARAMS>
struct MLDSA
{
    typedef MLDSASigner<PARAMS> Signer;
    typedef MLDSAVerifier<PARAMS> Verifier;
    typedef MLDSAPrivateKey<PARAMS> PrivateKey;
    typedef MLDSAPublicKey<PARAMS> PublicKey;

    static std::string StaticAlgorithmName() { return PARAMS::StaticAlgorithmName(); }
};

// ******************** Convenience Typedefs ************************* //

/// \name Scheme Typedefs
//@{
typedef MLDSA<MLDSA_44> MLDSA44;
typedef MLDSA<MLDSA_65> MLDSA65;
typedef MLDSA<MLDSA_87> MLDSA87;
//@}

/// \name ML-DSA-44 Signer/Verifier Types
//@{
typedef MLDSASigner<MLDSA_44> MLDSA_44_Signer;
typedef MLDSAVerifier<MLDSA_44> MLDSA_44_Verifier;
//@}

/// \name ML-DSA-65 Signer/Verifier Types
//@{
typedef MLDSASigner<MLDSA_65> MLDSA_65_Signer;
typedef MLDSAVerifier<MLDSA_65> MLDSA_65_Verifier;
//@}

/// \name ML-DSA-87 Signer/Verifier Types
//@{
typedef MLDSASigner<MLDSA_87> MLDSA_87_Signer;
typedef MLDSAVerifier<MLDSA_87> MLDSA_87_Verifier;
//@}

NAMESPACE_END

#endif  // CRYPTOPP_MLDSA_H
