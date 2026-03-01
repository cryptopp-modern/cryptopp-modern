// slhdsa.h - written and placed in the public domain by Colin Brown
//            SLH-DSA (FIPS 205) Stateless Hash-Based Digital Signature Algorithm
//            Based on SPHINCS+ reference implementation (public domain)

/// \file slhdsa.h
/// \brief SLH-DSA (FIPS 205) stateless hash-based digital signature algorithm
/// \details SLH-DSA is a stateless hash-based signature scheme standardized in
///  FIPS 205. Unlike stateful schemes (XMSS, LMS), SLH-DSA does not require
///  state management, making it safer for general use. The tradeoff is larger
///  signatures compared to lattice-based schemes.
/// \details SLH-DSA is based entirely on hash function security (SHA-256 or SHAKE),
///  providing conservative security assumptions. It is recommended as a backup
///  signature algorithm in case lattice-based schemes prove vulnerable.
/// \details Parameter sets are named as SLH-DSA-{HASH}-{SECURITY}{VARIANT} where:
///  - HASH is SHA2 or SHAKE
///  - SECURITY is 128, 192, or 256 (bit security level)
///  - VARIANT is 'f' (fast, larger signatures) or 's' (small, smaller signatures)
/// \sa <A HREF="https://csrc.nist.gov/pubs/fips/205/final">FIPS 205</A>
/// \since cryptopp-modern 2026.3.0

#ifndef CRYPTOPP_SLHDSA_H
#define CRYPTOPP_SLHDSA_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/misc.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

#include <vector>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Parameter Sets ************************* //

/// \brief SLH-DSA-SHA2-128f parameters (NIST security level 1, fast)
/// \details Fast variant with larger signatures but faster signing/verification.
///  Recommended for most applications requiring 128-bit security.
struct SLHDSA_SHA2_128f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 32);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 17088);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 1);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-128f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_128f(); }
};

/// \brief SLH-DSA-SHA2-128s parameters (NIST security level 1, small)
/// \details Small variant with smaller signatures but slower signing/verification.
struct SLHDSA_SHA2_128s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 32);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 7856);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 1);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-128s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_128s(); }
};

/// \brief SLH-DSA-SHA2-192f parameters (NIST security level 3, fast)
struct SLHDSA_SHA2_192f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 48);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 96);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 35664);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-192f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_192f(); }
};

/// \brief SLH-DSA-SHA2-192s parameters (NIST security level 3, small)
struct SLHDSA_SHA2_192s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 48);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 96);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 16224);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-192s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_192s(); }
};

/// \brief SLH-DSA-SHA2-256f parameters (NIST security level 5, fast)
struct SLHDSA_SHA2_256f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 128);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 49856);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-256f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_256f(); }
};

/// \brief SLH-DSA-SHA2-256s parameters (NIST security level 5, small)
struct SLHDSA_SHA2_256s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 128);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 29792);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHA2-256s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_sha2_256s(); }
};

/// \brief SLH-DSA-SHAKE-128f parameters (NIST security level 1, fast)
struct SLHDSA_SHAKE_128f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 32);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 17088);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 1);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-128f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_128f(); }
};

/// \brief SLH-DSA-SHAKE-128s parameters (NIST security level 1, small)
struct SLHDSA_SHAKE_128s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 32);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 7856);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 1);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-128s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_128s(); }
};

/// \brief SLH-DSA-SHAKE-192f parameters (NIST security level 3, fast)
struct SLHDSA_SHAKE_192f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 48);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 96);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 35664);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-192f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_192f(); }
};

/// \brief SLH-DSA-SHAKE-192s parameters (NIST security level 3, small)
struct SLHDSA_SHAKE_192s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 48);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 96);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 16224);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-192s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_192s(); }
};

/// \brief SLH-DSA-SHAKE-256f parameters (NIST security level 5, fast)
struct SLHDSA_SHAKE_256f
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 128);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 49856);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-256f"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_256f(); }
};

/// \brief SLH-DSA-SHAKE-256s parameters (NIST security level 5, small)
struct SLHDSA_SHAKE_256s
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 64);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 128);
    CRYPTOPP_CONSTANT(SIGNATURE_SIZE = 29792);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "SLH-DSA-SHAKE-256s"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_slh_dsa_shake_256s(); }
};

// ******************** Message Accumulator ************************* //

/// \brief SLH-DSA message accumulator
/// \details SLH-DSA buffers the entire message before signing/verification.
///  The first bytes of storage are reserved for the signature during verification.
/// \details The accumulator is used for both signing and verification.
template <class PARAMS>
struct SLHDSA_MessageAccumulator : public PK_MessageAccumulator
{
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);
    CRYPTOPP_CONSTANT(RESERVE_SIZE = 2048 + SIGNATURE_LENGTH);

    /// \brief Create a message accumulator
    SLHDSA_MessageAccumulator() { Restart(); }

    /// \brief Create a message accumulator
    /// \param rng a RandomNumberGenerator (unused, for interface compatibility)
    SLHDSA_MessageAccumulator(RandomNumberGenerator &rng) {
        CRYPTOPP_UNUSED(rng);
        Restart();
    }

    /// \brief Add data to the accumulator
    /// \param msg pointer to message data
    /// \param len length of message data in bytes
    void Update(const byte *msg, size_t len) {
        if (len == 0) return;
        if (!msg)
            throw InvalidArgument("SLH-DSA: Update called with null pointer and non-zero length");
        m_msg.insert(m_msg.end(), msg, msg + len);
    }

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
};

// ******************** SLH-DSA Private Key ************************* //

/// \brief SLH-DSA private key
/// \tparam PARAMS parameter set (e.g., SLHDSA_SHA2_128f)
/// \details SLHDSAPrivateKey holds the secret key material for signing messages.
///  It also contains the embedded public key for convenience.
template <class PARAMS>
struct SLHDSAPrivateKey : public PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~SLHDSAPrivateKey() {}

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

    /// \brief Get the private key size
    size_t GetPrivateKeySize() const { return SECRET_KEYLENGTH; }

    /// \brief Get the public key size
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

protected:
    FixedSizeSecBlock<byte, SECRET_KEYLENGTH> m_sk;
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

// ******************** SLH-DSA Public Key ************************* //

/// \brief SLH-DSA public key
/// \tparam PARAMS parameter set (e.g., SLHDSA_SHA2_128f)
/// \details SLHDSAPublicKey holds the public key material for verifying signatures.
template <class PARAMS>
struct SLHDSAPublicKey : public PublicKey
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~SLHDSAPublicKey() {}

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

    /// \brief Get the public key size
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

protected:
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

// ******************** SLH-DSA Signer ************************* //

/// \brief SLH-DSA signature scheme signer
/// \tparam PARAMS parameter set (e.g., SLHDSA_SHA2_128f)
/// \details SLHDSASigner provides digital signature generation using the
///  SLH-DSA (SPHINCS+) algorithm. The signer holds both the secret key
///  and public key.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   SLHDSASigner<SLHDSA_SHA2_128f> signer;
///   signer.AccessPrivateKey().GenerateRandom(rng, MakeParameters());
///
///   std::string message = "Message to sign";
///   SecByteBlock signature(signer.MaxSignatureLength());
///   size_t sigLen = signer.SignMessage(rng,
///       (const byte*)message.data(), message.size(), signature.begin());
/// \endcode
/// \sa SLHDSAVerifier, <A HREF="https://csrc.nist.gov/pubs/fips/205/final">FIPS 205</A>
template <class PARAMS>
struct SLHDSASigner : public PK_Signer
{
    typedef PARAMS Parameters;
    typedef SLHDSAPrivateKey<PARAMS> PrivateKeyType;
    typedef SLHDSA_MessageAccumulator<PARAMS> MessageAccumulatorType;

    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~SLHDSASigner() {}

    /// \brief Create an uninitialized signer
    SLHDSASigner() {}

    /// \brief Create a signer with a new random key pair
    SLHDSASigner(RandomNumberGenerator &rng);

    /// \brief Create a signer from existing private key bytes
    SLHDSASigner(const byte *privateKey, size_t privateKeyLen);

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
        throw NotImplemented("SLHDSASigner: recoverable messages not supported");
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

// ******************** SLH-DSA Verifier ************************* //

/// \brief SLH-DSA signature scheme verifier
/// \tparam PARAMS parameter set (e.g., SLHDSA_SHA2_128f)
/// \details SLHDSAVerifier provides digital signature verification using the
///  SLH-DSA (SPHINCS+) algorithm. The verifier holds only the public key.
/// \par Example
/// \code
///   SLHDSAVerifier<SLHDSA_SHA2_128f> verifier;
///   verifier.AccessPublicKey().SetPublicKey(publicKey, publicKeyLen);
///
///   bool valid = verifier.VerifyMessage(
///       (const byte*)message.data(), message.size(),
///       signature, signatureLen);
/// \endcode
/// \sa SLHDSASigner, <A HREF="https://csrc.nist.gov/pubs/fips/205/final">FIPS 205</A>
template <class PARAMS>
struct SLHDSAVerifier : public PK_Verifier
{
    typedef PARAMS Parameters;
    typedef SLHDSAPublicKey<PARAMS> PublicKeyType;
    typedef SLHDSA_MessageAccumulator<PARAMS> MessageAccumulatorType;

    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SIGNATURE_LENGTH = PARAMS::SIGNATURE_SIZE);

    virtual ~SLHDSAVerifier() {}

    /// \brief Create an uninitialized verifier
    SLHDSAVerifier() {}

    /// \brief Create a verifier from public key bytes
    SLHDSAVerifier(const byte *publicKey, size_t publicKeyLen);

    /// \brief Create a verifier from a signer
    SLHDSAVerifier(const SLHDSASigner<PARAMS> &signer);

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
        throw NotImplemented("SLHDSAVerifier: recoverable messages not supported");
    }

    /// \brief Access the public key
    PublicKeyType& AccessKey() { return m_key; }

    /// \brief Get the public key
    const PublicKeyType& GetKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** SLH-DSA Scheme ************************* //

/// \brief SLH-DSA signature scheme
/// \tparam PARAMS parameter set
template <class PARAMS>
struct SLHDSA
{
    typedef SLHDSASigner<PARAMS> Signer;
    typedef SLHDSAVerifier<PARAMS> Verifier;
    typedef SLHDSAPrivateKey<PARAMS> PrivateKey;
    typedef SLHDSAPublicKey<PARAMS> PublicKey;

    static std::string StaticAlgorithmName() { return PARAMS::StaticAlgorithmName(); }
};

// ******************** Convenience Typedefs ************************* //

/// \name SHA-256 Based Schemes
//@{
typedef SLHDSA<SLHDSA_SHA2_128f> SLHDSA_SHA2_128f_Scheme;
typedef SLHDSA<SLHDSA_SHA2_128s> SLHDSA_SHA2_128s_Scheme;
typedef SLHDSA<SLHDSA_SHA2_192f> SLHDSA_SHA2_192f_Scheme;
typedef SLHDSA<SLHDSA_SHA2_192s> SLHDSA_SHA2_192s_Scheme;
typedef SLHDSA<SLHDSA_SHA2_256f> SLHDSA_SHA2_256f_Scheme;
typedef SLHDSA<SLHDSA_SHA2_256s> SLHDSA_SHA2_256s_Scheme;
//@}

/// \name SHAKE-256 Based Schemes
//@{
typedef SLHDSA<SLHDSA_SHAKE_128f> SLHDSA_SHAKE_128f_Scheme;
typedef SLHDSA<SLHDSA_SHAKE_128s> SLHDSA_SHAKE_128s_Scheme;
typedef SLHDSA<SLHDSA_SHAKE_192f> SLHDSA_SHAKE_192f_Scheme;
typedef SLHDSA<SLHDSA_SHAKE_192s> SLHDSA_SHAKE_192s_Scheme;
typedef SLHDSA<SLHDSA_SHAKE_256f> SLHDSA_SHAKE_256f_Scheme;
typedef SLHDSA<SLHDSA_SHAKE_256s> SLHDSA_SHAKE_256s_Scheme;
//@}

/// \name SHA-256 Based Signers
//@{
typedef SLHDSASigner<SLHDSA_SHA2_128f> SLHDSA_SHA2_128f_Signer;
typedef SLHDSASigner<SLHDSA_SHA2_128s> SLHDSA_SHA2_128s_Signer;
typedef SLHDSASigner<SLHDSA_SHA2_192f> SLHDSA_SHA2_192f_Signer;
typedef SLHDSASigner<SLHDSA_SHA2_192s> SLHDSA_SHA2_192s_Signer;
typedef SLHDSASigner<SLHDSA_SHA2_256f> SLHDSA_SHA2_256f_Signer;
typedef SLHDSASigner<SLHDSA_SHA2_256s> SLHDSA_SHA2_256s_Signer;
//@}

/// \name SHA-256 Based Verifiers
//@{
typedef SLHDSAVerifier<SLHDSA_SHA2_128f> SLHDSA_SHA2_128f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHA2_128s> SLHDSA_SHA2_128s_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHA2_192f> SLHDSA_SHA2_192f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHA2_192s> SLHDSA_SHA2_192s_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHA2_256f> SLHDSA_SHA2_256f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHA2_256s> SLHDSA_SHA2_256s_Verifier;
//@}

/// \name SHAKE-256 Based Signers
//@{
typedef SLHDSASigner<SLHDSA_SHAKE_128f> SLHDSA_SHAKE_128f_Signer;
typedef SLHDSASigner<SLHDSA_SHAKE_128s> SLHDSA_SHAKE_128s_Signer;
typedef SLHDSASigner<SLHDSA_SHAKE_192f> SLHDSA_SHAKE_192f_Signer;
typedef SLHDSASigner<SLHDSA_SHAKE_192s> SLHDSA_SHAKE_192s_Signer;
typedef SLHDSASigner<SLHDSA_SHAKE_256f> SLHDSA_SHAKE_256f_Signer;
typedef SLHDSASigner<SLHDSA_SHAKE_256s> SLHDSA_SHAKE_256s_Signer;
//@}

/// \name SHAKE-256 Based Verifiers
//@{
typedef SLHDSAVerifier<SLHDSA_SHAKE_128f> SLHDSA_SHAKE_128f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHAKE_128s> SLHDSA_SHAKE_128s_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHAKE_192f> SLHDSA_SHAKE_192f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHAKE_192s> SLHDSA_SHAKE_192s_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHAKE_256f> SLHDSA_SHAKE_256f_Verifier;
typedef SLHDSAVerifier<SLHDSA_SHAKE_256s> SLHDSA_SHAKE_256s_Verifier;
//@}

NAMESPACE_END

#endif // CRYPTOPP_SLHDSA_H
