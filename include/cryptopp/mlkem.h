// mlkem.h - written and placed in the public domain by Colin Brown
//           ML-KEM (FIPS 203) Module-Lattice Key Encapsulation Mechanism
//           Based on CRYSTALS-Kyber reference implementation (public domain)

/// \file mlkem.h
/// \brief ML-KEM (FIPS 203) module-lattice key encapsulation mechanism
/// \details ML-KEM is a key encapsulation mechanism standardized in FIPS 203,
///  based on the CRYSTALS-Kyber algorithm. It provides IND-CCA2 secure key
///  encapsulation resistant to attacks by quantum computers.
/// \details ML-KEM is suitable for key exchange in protocols like TLS, secure
///  messaging, and hybrid encryption schemes. It offers the best balance of
///  security, key sizes, and performance among NIST PQC standards.
/// \details Parameter sets are named ML-KEM-{SIZE} where SIZE indicates the
///  security strength: 512 (128-bit), 768 (192-bit), or 1024 (256-bit).
/// \sa <A HREF="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</A>
/// \since cryptopp-modern 2026.3.0

#ifndef CRYPTOPP_MLKEM_H
#define CRYPTOPP_MLKEM_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/misc.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Parameter Sets ************************* //

/// \brief ML-KEM-512 parameters (NIST security level 1)
/// \details Provides approximately 128-bit security against classical and
///  quantum attacks. Minimum security level; prefer ML-KEM-768 for most applications.
struct MLKEM_512
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 800);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 1632);
    CRYPTOPP_CONSTANT(CIPHERTEXT_SIZE = 768);
    CRYPTOPP_CONSTANT(SHARED_SECRET_SIZE = 32);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 1);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-KEM-512"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_kem_512(); }
};

/// \brief ML-KEM-768 parameters (NIST security level 3)
/// \details Provides approximately 192-bit security against classical and
///  quantum attacks. Good balance of security and performance.
struct MLKEM_768
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 1184);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 2400);
    CRYPTOPP_CONSTANT(CIPHERTEXT_SIZE = 1088);
    CRYPTOPP_CONSTANT(SHARED_SECRET_SIZE = 32);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 3);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-KEM-768"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_kem_768(); }
};

/// \brief ML-KEM-1024 parameters (NIST security level 5)
/// \details Provides approximately 256-bit security against classical and
///  quantum attacks. Highest security level available.
struct MLKEM_1024
{
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 1568);
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 3168);
    CRYPTOPP_CONSTANT(CIPHERTEXT_SIZE = 1568);
    CRYPTOPP_CONSTANT(SHARED_SECRET_SIZE = 32);
    CRYPTOPP_CONSTANT(SECURITY_LEVEL = 5);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "ML-KEM-1024"; }
    /// \brief Algorithm OID
    static OID StaticAlgorithmOID() { return ASN1::id_ml_kem_1024(); }
};

// ******************** ML-KEM Private Key ************************* //

/// \brief ML-KEM private key (decapsulation key)
/// \tparam PARAMS parameter set (MLKEM_512, MLKEM_768, or MLKEM_1024)
/// \details MLKEMPrivateKey holds the secret key material for decapsulation.
///  It also contains the embedded public key and implicit rejection seed.
template <class PARAMS>
struct MLKEMPrivateKey : public PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);

    virtual ~MLKEMPrivateKey() {}

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

    /// \brief Get pointer to public key bytes (embedded in secret key)
    const byte* GetPublicKeyBytePtr() const;

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
};

// ******************** ML-KEM Public Key ************************* //

/// \brief ML-KEM public key (encapsulation key)
/// \tparam PARAMS parameter set (MLKEM_512, MLKEM_768, or MLKEM_1024)
/// \details MLKEMPublicKey holds the public key material for encapsulation.
template <class PARAMS>
struct MLKEMPublicKey : public PublicKey
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);

    virtual ~MLKEMPublicKey() {}

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

// ******************** ML-KEM Encapsulator ************************* //

/// \brief ML-KEM encapsulation (sender side)
/// \tparam PARAMS parameter set (MLKEM_512, MLKEM_768, or MLKEM_1024)
/// \details MLKEMEncapsulator generates a shared secret and ciphertext using
///  the recipient's public key. The ciphertext is sent to the recipient who
///  can decapsulate it to recover the same shared secret.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   MLKEMEncapsulator<MLKEM_768> encapsulator;
///   encapsulator.AccessPublicKey().SetPublicKey(recipientPubKey, pubKeyLen);
///
///   SecByteBlock ciphertext(encapsulator.CiphertextLength());
///   SecByteBlock sharedSecret(encapsulator.SharedSecretLength());
///   encapsulator.Encapsulate(rng, ciphertext.begin(), sharedSecret.begin());
/// \endcode
/// \sa MLKEMDecapsulator, <A HREF="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</A>
template <class PARAMS>
struct MLKEMEncapsulator
{
    typedef PARAMS Parameters;
    typedef MLKEMPublicKey<PARAMS> PublicKeyType;

    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(CIPHERTEXT_LENGTH = PARAMS::CIPHERTEXT_SIZE);
    CRYPTOPP_CONSTANT(SHARED_SECRET_LENGTH = PARAMS::SHARED_SECRET_SIZE);

    virtual ~MLKEMEncapsulator() {}

    /// \brief Create an uninitialized encapsulator
    MLKEMEncapsulator() {}

    /// \brief Create an encapsulator from public key bytes
    MLKEMEncapsulator(const byte *publicKey, size_t publicKeyLen);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return PARAMS::StaticAlgorithmName(); }

    /// \brief Get the ciphertext length
    size_t CiphertextLength() const { return CIPHERTEXT_LENGTH; }

    /// \brief Get the shared secret length
    size_t SharedSecretLength() const { return SHARED_SECRET_LENGTH; }

    /// \brief Encapsulate to generate ciphertext and shared secret
    /// \param rng random number generator
    /// \param ciphertext output buffer for ciphertext (CIPHERTEXT_LENGTH bytes)
    /// \param sharedSecret output buffer for shared secret (SHARED_SECRET_LENGTH bytes)
    void Encapsulate(RandomNumberGenerator &rng, byte *ciphertext, byte *sharedSecret) const;

    /// \brief Access the public key
    PublicKeyType& AccessPublicKey() { return m_key; }

    /// \brief Get the public key
    const PublicKeyType& GetPublicKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** ML-KEM Decapsulator ************************* //

/// \brief ML-KEM decapsulation (recipient side)
/// \tparam PARAMS parameter set (MLKEM_512, MLKEM_768, or MLKEM_1024)
/// \details MLKEMDecapsulator recovers the shared secret from a ciphertext
///  using the recipient's private key. The shared secret can then be used
///  for symmetric encryption.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   MLKEMDecapsulator<MLKEM_768> decapsulator(rng);  // Generate new key pair
///
///   // Share public key with sender...
///   const byte* pubKey = decapsulator.GetKey().GetPublicKeyBytePtr();
///
///   // After receiving ciphertext from sender:
///   SecByteBlock sharedSecret(decapsulator.SharedSecretLength());
///   (void)decapsulator.Decapsulate(ciphertext.begin(), sharedSecret.begin());
/// \endcode
/// \sa MLKEMEncapsulator, <A HREF="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</A>
template <class PARAMS>
struct MLKEMDecapsulator
{
    typedef PARAMS Parameters;
    typedef MLKEMPrivateKey<PARAMS> PrivateKeyType;

    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = PARAMS::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = PARAMS::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(CIPHERTEXT_LENGTH = PARAMS::CIPHERTEXT_SIZE);
    CRYPTOPP_CONSTANT(SHARED_SECRET_LENGTH = PARAMS::SHARED_SECRET_SIZE);

    virtual ~MLKEMDecapsulator() {}

    /// \brief Create an uninitialized decapsulator
    MLKEMDecapsulator() {}

    /// \brief Create a decapsulator with a new random key pair
    MLKEMDecapsulator(RandomNumberGenerator &rng);

    /// \brief Create a decapsulator from existing private key bytes
    MLKEMDecapsulator(const byte *privateKey, size_t privateKeyLen);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return PARAMS::StaticAlgorithmName(); }

    /// \brief Get the ciphertext length
    size_t CiphertextLength() const { return CIPHERTEXT_LENGTH; }

    /// \brief Get the shared secret length
    size_t SharedSecretLength() const { return SHARED_SECRET_LENGTH; }

    /// \brief Decapsulate to recover shared secret from ciphertext
    /// \param ciphertext input ciphertext (CIPHERTEXT_LENGTH bytes)
    /// \param sharedSecret output buffer for shared secret (SHARED_SECRET_LENGTH bytes)
    /// \returns true on success (always returns true for ML-KEM due to implicit rejection)
    /// \details ML-KEM uses implicit rejection: if decapsulation fails internally,
    ///  a pseudorandom value is returned instead. This prevents side-channel attacks.
    bool Decapsulate(const byte *ciphertext, byte *sharedSecret) const;

    /// \brief Access the private key
    PrivateKeyType& AccessPrivateKey() { return m_key; }

    /// \brief Get the private key
    const PrivateKeyType& GetPrivateKey() const { return m_key; }

    /// \brief Get the private key (alias)
    const PrivateKeyType& GetKey() const { return m_key; }

protected:
    PrivateKeyType m_key;
};

// ******************** ML-KEM Scheme ************************* //

/// \brief ML-KEM key encapsulation scheme
/// \tparam PARAMS parameter set
template <class PARAMS>
struct MLKEM
{
    typedef MLKEMEncapsulator<PARAMS> Encapsulator;
    typedef MLKEMDecapsulator<PARAMS> Decapsulator;
    typedef MLKEMPrivateKey<PARAMS> PrivateKey;
    typedef MLKEMPublicKey<PARAMS> PublicKey;

    static std::string StaticAlgorithmName() { return PARAMS::StaticAlgorithmName(); }
};

// ******************** Convenience Typedefs ************************* //

/// \name Scheme Typedefs
//@{
typedef MLKEM<MLKEM_512>  MLKEM512;
typedef MLKEM<MLKEM_768>  MLKEM768;
typedef MLKEM<MLKEM_1024> MLKEM1024;
//@}

/// \name Encapsulator Typedefs
//@{
typedef MLKEMEncapsulator<MLKEM_512>  MLKEM512_Encapsulator;
typedef MLKEMEncapsulator<MLKEM_768>  MLKEM768_Encapsulator;
typedef MLKEMEncapsulator<MLKEM_1024> MLKEM1024_Encapsulator;
//@}

/// \name Decapsulator Typedefs
//@{
typedef MLKEMDecapsulator<MLKEM_512>  MLKEM512_Decapsulator;
typedef MLKEMDecapsulator<MLKEM_768>  MLKEM768_Decapsulator;
typedef MLKEMDecapsulator<MLKEM_1024> MLKEM1024_Decapsulator;
//@}

NAMESPACE_END

#endif // CRYPTOPP_MLKEM_H
