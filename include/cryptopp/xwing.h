// xwing.h - written and placed in the public domain by Colin Brown
//           X-Wing hybrid KEM combining X25519 and ML-KEM-768
//           Based on IETF draft-connolly-cfrg-xwing-kem-09

/// \file xwing.h
/// \brief X-Wing hybrid key encapsulation mechanism (X25519 + ML-KEM-768)
/// \details X-Wing is a hybrid KEM that combines X25519 (classical ECDH) with
///  ML-KEM-768 (post-quantum KEM) to provide security against both classical
///  and quantum adversaries. The security is at least as strong as the stronger
///  of the two components.
/// \details X-Wing provides 128-bit classical security (from X25519) and 192-bit
///  post-quantum security (from ML-KEM-768). The shared secret is derived using
///  SHA3-256 with domain separation.
/// \details The specification follows IETF draft-connolly-cfrg-xwing-kem.
/// \sa <A HREF="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">X-Wing IETF Draft</A>
/// \since cryptopp-modern 2026.3.0

#ifndef CRYPTOPP_XWING_H
#define CRYPTOPP_XWING_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/mlkem.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/sha3.h>

NAMESPACE_BEGIN(CryptoPP)

// ******************** X-Wing Constants ************************* //

/// \brief X-Wing key sizes and constants
struct XWING_Constants
{
    /// \brief Size of the X-Wing public key (encapsulation key)
    /// \details PUBLIC_KEY_SIZE = ML-KEM-768 public key (1184) + X25519 public key (32)
    CRYPTOPP_CONSTANT(PUBLIC_KEY_SIZE = 1216);

    /// \brief Size of the X-Wing secret key (decapsulation key) - expanded form
    /// \details SECRET_KEY_SIZE = ML-KEM-768 secret key (2400) + X25519 secret key (32) + X25519 public key (32)
    CRYPTOPP_CONSTANT(SECRET_KEY_SIZE = 2464);

    /// \brief Size of the X-Wing seed (compact private key form)
    /// \details The seed can be expanded via SHAKE256 to derive both component keys
    CRYPTOPP_CONSTANT(SEED_SIZE = 32);

    /// \brief Size of the X-Wing ciphertext
    /// \details CIPHERTEXT_SIZE = ML-KEM-768 ciphertext (1088) + X25519 ephemeral public key (32)
    CRYPTOPP_CONSTANT(CIPHERTEXT_SIZE = 1120);

    /// \brief Size of the shared secret
    CRYPTOPP_CONSTANT(SHARED_SECRET_SIZE = 32);

    /// \brief Algorithm name
    static std::string StaticAlgorithmName() { return "X-Wing"; }
};

// ******************** X-Wing Private Key ************************* //

/// \brief X-Wing private key (decapsulation key)
/// \details XWingPrivateKey holds the secret key material for decapsulation.
///  Internally it stores the expanded form containing both the ML-KEM-768
///  and X25519 private keys for efficient decapsulation.
/// \details The key can be generated from a 32-byte seed or generated randomly.
struct XWingPrivateKey : public PrivateKey
{
    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = XWING_Constants::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = XWING_Constants::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(SEED_LENGTH = XWING_Constants::SEED_SIZE);

    virtual ~XWingPrivateKey() {}

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

    /// \brief Generate a random key pair
    /// \param rng a RandomNumberGenerator to produce keying material
    /// \param params additional initialization parameters (unused)
    void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params);

    /// \brief Generate key pair from a 32-byte seed
    /// \param seed pointer to 32-byte seed
    /// \details Expands the seed using SHAKE256 to derive ML-KEM-768 and X25519 keys
    void GenerateFromSeed(const byte seed[SEED_LENGTH]);

    /// \brief Get pointer to ML-KEM-768 private key bytes
    const byte* GetMLKEMPrivateKeyPtr() const { return m_mlkem_sk.begin(); }

    /// \brief Get pointer to X25519 private key bytes
    const byte* GetX25519PrivateKeyPtr() const { return m_x25519_sk.begin(); }

    /// \brief Get pointer to X25519 public key bytes (stored with private key)
    const byte* GetX25519PublicKeyPtr() const { return m_x25519_pk.begin(); }

    /// \brief Get pointer to ML-KEM-768 public key bytes (embedded in secret key)
    const byte* GetMLKEMPublicKeyPtr() const;

    /// \brief Get the combined public key
    /// \param publicKey output buffer (PUBLIC_KEYLENGTH bytes)
    void GetPublicKey(byte *publicKey) const;

    /// \brief Get the private key size
    size_t GetPrivateKeySize() const { return SECRET_KEYLENGTH; }

    /// \brief Get the public key size
    size_t GetPublicKeySize() const { return PUBLIC_KEYLENGTH; }

protected:
    /// ML-KEM-768 secret key (2400 bytes)
    FixedSizeSecBlock<byte, MLKEM_768::SECRET_KEY_SIZE> m_mlkem_sk;
    /// X25519 secret key (32 bytes)
    FixedSizeSecBlock<byte, 32> m_x25519_sk;
    /// X25519 public key (32 bytes) - stored for combiner
    FixedSizeSecBlock<byte, 32> m_x25519_pk;
};

// ******************** X-Wing Public Key ************************* //

/// \brief X-Wing public key (encapsulation key)
/// \details XWingPublicKey holds the public key material for encapsulation.
///  It contains both the ML-KEM-768 public key and X25519 public key.
struct XWingPublicKey : public PublicKey
{
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = XWING_Constants::PUBLIC_KEY_SIZE);

    virtual ~XWingPublicKey() {}

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

    /// \brief Get pointer to ML-KEM-768 public key bytes
    const byte* GetMLKEMPublicKeyPtr() const { return m_pk.begin(); }

    /// \brief Get pointer to X25519 public key bytes
    const byte* GetX25519PublicKeyPtr() const { return m_pk.begin() + MLKEM_768::PUBLIC_KEY_SIZE; }

    /// \brief Get pointer to full public key bytes
    const byte* GetPublicKeyBytePtr() const { return m_pk.begin(); }

    /// \brief Get the public key size
    size_t GetPublicKeySize() const { return PUBLIC_KEYLENGTH; }

protected:
    /// Combined public key: ML-KEM-768 (1184 bytes) || X25519 (32 bytes)
    FixedSizeSecBlock<byte, PUBLIC_KEYLENGTH> m_pk;
};

// ******************** X-Wing Encapsulator ************************* //

/// \brief X-Wing encapsulation (sender side)
/// \details XWingEncapsulator generates a shared secret and ciphertext using
///  the recipient's public key. The ciphertext is sent to the recipient who
///  can decapsulate it to recover the same shared secret.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   XWingEncapsulator encapsulator;
///   encapsulator.AccessPublicKey().SetPublicKey(recipientPubKey, pubKeyLen);
///
///   SecByteBlock ciphertext(encapsulator.CiphertextLength());
///   SecByteBlock sharedSecret(encapsulator.SharedSecretLength());
///   encapsulator.Encapsulate(rng, ciphertext, sharedSecret);
/// \endcode
/// \sa XWingDecapsulator, <A HREF="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">X-Wing IETF Draft</A>
struct XWingEncapsulator
{
    typedef XWingPublicKey PublicKeyType;

    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = XWING_Constants::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(CIPHERTEXT_LENGTH = XWING_Constants::CIPHERTEXT_SIZE);
    CRYPTOPP_CONSTANT(SHARED_SECRET_LENGTH = XWING_Constants::SHARED_SECRET_SIZE);

    virtual ~XWingEncapsulator() {}

    /// \brief Create an uninitialized encapsulator
    XWingEncapsulator() {}

    /// \brief Create an encapsulator from public key bytes
    /// \param publicKey pointer to public key (1216 bytes)
    /// \param publicKeyLen length of public key
    XWingEncapsulator(const byte *publicKey, size_t publicKeyLen);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return XWING_Constants::StaticAlgorithmName(); }

    /// \brief Get the ciphertext length
    size_t CiphertextLength() const { return CIPHERTEXT_LENGTH; }

    /// \brief Get the shared secret length
    size_t SharedSecretLength() const { return SHARED_SECRET_LENGTH; }

    /// \brief Encapsulate to generate ciphertext and shared secret
    /// \param rng random number generator
    /// \param ciphertext output buffer for ciphertext (CIPHERTEXT_LENGTH bytes)
    /// \param sharedSecret output buffer for shared secret (SHARED_SECRET_LENGTH bytes)
    /// \details Performs ML-KEM-768 encapsulation and X25519 key exchange, then
    ///  combines the shared secrets using SHA3-256 with the X-Wing domain separator.
    void Encapsulate(RandomNumberGenerator &rng, byte *ciphertext, byte *sharedSecret) const;

    /// \brief Access the public key
    PublicKeyType& AccessPublicKey() { return m_key; }

    /// \brief Get the public key
    const PublicKeyType& GetPublicKey() const { return m_key; }

protected:
    PublicKeyType m_key;
};

// ******************** X-Wing Decapsulator ************************* //

/// \brief X-Wing decapsulation (recipient side)
/// \details XWingDecapsulator recovers the shared secret from a ciphertext
///  using the recipient's private key. The shared secret can then be used
///  for symmetric encryption.
/// \par Example
/// \code
///   AutoSeededRandomPool rng;
///   XWingDecapsulator decapsulator(rng);  // Generate new key pair
///
///   // Share public key with sender...
///   SecByteBlock pubKey(decapsulator.GetKey().GetPublicKeySize());
///   decapsulator.GetKey().GetPublicKey(pubKey);
///
///   // After receiving ciphertext from sender:
///   SecByteBlock sharedSecret(decapsulator.SharedSecretLength());
///   bool success = decapsulator.Decapsulate(ciphertext, sharedSecret);
/// \endcode
/// \sa XWingEncapsulator, <A HREF="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">X-Wing IETF Draft</A>
struct XWingDecapsulator
{
    typedef XWingPrivateKey PrivateKeyType;

    CRYPTOPP_CONSTANT(SECRET_KEYLENGTH = XWING_Constants::SECRET_KEY_SIZE);
    CRYPTOPP_CONSTANT(PUBLIC_KEYLENGTH = XWING_Constants::PUBLIC_KEY_SIZE);
    CRYPTOPP_CONSTANT(CIPHERTEXT_LENGTH = XWING_Constants::CIPHERTEXT_SIZE);
    CRYPTOPP_CONSTANT(SHARED_SECRET_LENGTH = XWING_Constants::SHARED_SECRET_SIZE);

    virtual ~XWingDecapsulator() {}

    /// \brief Create an uninitialized decapsulator
    XWingDecapsulator() {}

    /// \brief Create a decapsulator with a new random key pair
    /// \param rng random number generator
    XWingDecapsulator(RandomNumberGenerator &rng);

    /// \brief Get the algorithm name
    std::string AlgorithmName() const { return XWING_Constants::StaticAlgorithmName(); }

    /// \brief Get the ciphertext length
    size_t CiphertextLength() const { return CIPHERTEXT_LENGTH; }

    /// \brief Get the shared secret length
    size_t SharedSecretLength() const { return SHARED_SECRET_LENGTH; }

    /// \brief Decapsulate to recover shared secret from ciphertext
    /// \param ciphertext input ciphertext (CIPHERTEXT_LENGTH bytes)
    /// \param sharedSecret output buffer for shared secret (SHARED_SECRET_LENGTH bytes)
    /// \returns true (always succeeds per X-Wing spec; implicit rejection via combiner)
    /// \details Performs ML-KEM-768 decapsulation and X25519 key exchange, then
    ///  combines the shared secrets using SHA3-256 with the X-Wing domain separator.
    ///  Per the X-Wing spec, decapsulation never fails -- if either component
    ///  encounters an invalid ciphertext, a pseudorandom shared secret is produced.
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

// ******************** X-Wing Scheme ************************* //

/// \brief X-Wing hybrid key encapsulation scheme
/// \details X-Wing combines X25519 and ML-KEM-768 for hybrid classical/post-quantum
///  security. Use XWing::Encapsulator for the sender and XWing::Decapsulator for
///  the recipient.
struct XWing
{
    typedef XWingEncapsulator Encapsulator;
    typedef XWingDecapsulator Decapsulator;
    typedef XWingPrivateKey PrivateKey;
    typedef XWingPublicKey PublicKey;

    static std::string StaticAlgorithmName() { return XWING_Constants::StaticAlgorithmName(); }
};

// ******************** Internal Combiner Function ************************* //

namespace XWingInternal {

/// \brief X-Wing domain separation label
/// \details ASCII art representation: `\.//^\` encoded as bytes
/// \details Value: 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c
static const byte XWING_LABEL[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

/// \brief Combine shared secrets using X-Wing combiner
/// \param output 32-byte output buffer for combined shared secret
/// \param ss_M ML-KEM-768 shared secret (32 bytes)
/// \param ss_X X25519 shared secret (32 bytes)
/// \param ct_X X25519 ciphertext/ephemeral public key (32 bytes)
/// \param pk_X X25519 recipient public key (32 bytes)
/// \details Computes: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
void Combiner(byte *output, const byte *ss_M, const byte *ss_X,
              const byte *ct_X, const byte *pk_X);

} // namespace XWingInternal

NAMESPACE_END

#endif // CRYPTOPP_XWING_H
