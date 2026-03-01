// xwing.cpp - written and placed in the public domain by Colin Brown
//           X-Wing hybrid KEM combining X25519 and ML-KEM-768
//           Based on IETF draft-connolly-cfrg-xwing-kem-09

#include <cryptopp/pch.h>
#include <cryptopp/xwing.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>
#include <cryptopp/misc.h>

#include "mlkem_params.h"  // For MLKEM_Internal::mlkem_keypair_deterministic

NAMESPACE_BEGIN(CryptoPP)

// ******************** Internal Combiner ************************* //

namespace XWingInternal {

void Combiner(byte *output, const byte *ss_M, const byte *ss_X,
              const byte *ct_X, const byte *pk_X)
{
    // X-Wing combiner per IETF draft-connolly-cfrg-xwing-kem:
    // SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    // Total input: 32 + 32 + 32 + 32 + 6 = 134 bytes
    SHA3_256 hash;
    hash.Update(ss_M, 32);
    hash.Update(ss_X, 32);
    hash.Update(ct_X, 32);
    hash.Update(pk_X, 32);
    hash.Update(XWING_LABEL, sizeof(XWING_LABEL));
    hash.Final(output);
}

} // namespace XWingInternal

// ******************** X-Wing Private Key ************************* //

bool XWingPrivateKey::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);

    // Basic validation: key data exists and has correct sizes
    return m_mlkem_sk.size() == MLKEM_768::SECRET_KEY_SIZE &&
           m_x25519_sk.size() == 32 &&
           m_x25519_pk.size() == 32;
}

bool XWingPrivateKey::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

void XWingPrivateKey::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

void XWingPrivateKey::GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params)
{
    CRYPTOPP_UNUSED(params);

    // Generate ML-KEM-768 key pair
    MLKEMDecapsulator<MLKEM_768> mlkem_decaps(rng);
    std::memcpy(m_mlkem_sk.begin(), mlkem_decaps.GetKey().GetPrivateKeyBytePtr(), MLKEM_768::SECRET_KEY_SIZE);

    // Generate X25519 key pair using SimpleKeyAgreementDomain interface
    x25519 x25519_agreement;
    x25519_agreement.GeneratePrivateKey(rng, m_x25519_sk.begin());
    x25519_agreement.GeneratePublicKey(rng, m_x25519_sk.begin(), m_x25519_pk.begin());
}

void XWingPrivateKey::GenerateFromSeed(const byte seed[SEED_LENGTH])
{
    // Expand seed using SHAKE256 per IETF draft-connolly-cfrg-xwing-kem:
    // expanded = SHAKE256(seed, 96)
    // d = expanded[0:32]   - ML-KEM-768 seed for polynomial generation
    // z = expanded[32:64]  - ML-KEM-768 implicit rejection seed
    // sk_X = expanded[64:96] - X25519 private key

    SHAKE256 shake;
    shake.Update(seed, SEED_LENGTH);

    // Generate 96 bytes: 64 for ML-KEM (d || z) + 32 for X25519
    SecByteBlock expanded(96);
    shake.TruncatedFinal(expanded.begin(), 96);

    // Generate ML-KEM-768 key pair deterministically from d and z
    byte pk[MLKEM_768::PUBLIC_KEY_SIZE];
    MLKEM_Internal::mlkem_keypair_deterministic<MLKEM_768>(
        pk, m_mlkem_sk.begin(),
        expanded.begin(),        // d (32 bytes)
        expanded.begin() + 32);  // z (32 bytes)

    // Use expanded[64:96] as X25519 private key
    std::memcpy(m_x25519_sk.begin(), expanded.begin() + 64, 32);

    // Generate X25519 public key from private key
    x25519 x25519_agreement;
    x25519_agreement.GeneratePublicKey(NullRNG(), m_x25519_sk.begin(), m_x25519_pk.begin());
}

const byte* XWingPrivateKey::GetMLKEMPublicKeyPtr() const
{
    // ML-KEM-768 secret key format: sk || pk || H(pk) || z
    // Public key starts at offset SECRET_KEY_SIZE - PUBLIC_KEY_SIZE - 32 - 32
    // Actually for ML-KEM-768: sk (1152) || pk (1184) || H(pk) (32) || z (32) = 2400
    // Public key is at offset 1152
    return m_mlkem_sk.begin() + (MLKEM_768::SECRET_KEY_SIZE - MLKEM_768::PUBLIC_KEY_SIZE - 32 - 32);
}

void XWingPrivateKey::GetPublicKey(byte *publicKey) const
{
    // Copy ML-KEM-768 public key (1184 bytes)
    std::memcpy(publicKey, GetMLKEMPublicKeyPtr(), MLKEM_768::PUBLIC_KEY_SIZE);
    // Copy X25519 public key (32 bytes)
    std::memcpy(publicKey + MLKEM_768::PUBLIC_KEY_SIZE, m_x25519_pk.begin(), 32);
}

// ******************** X-Wing Public Key ************************* //

bool XWingPublicKey::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    CRYPTOPP_UNUSED(rng);
    CRYPTOPP_UNUSED(level);

    // Basic validation: key data exists and has correct size
    return m_pk.size() == PUBLIC_KEYLENGTH;
}

bool XWingPublicKey::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name);
    CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);
    return false;
}

void XWingPublicKey::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);
}

void XWingPublicKey::SetPublicKey(const byte *key, size_t len)
{
    CRYPTOPP_ASSERT(len == PUBLIC_KEYLENGTH);
    if (len != PUBLIC_KEYLENGTH)
        throw InvalidArgument("XWingPublicKey: public key must be " + IntToString(static_cast<size_t>(PUBLIC_KEYLENGTH)) + " bytes");

    std::memcpy(m_pk.begin(), key, PUBLIC_KEYLENGTH);
}

// ******************** X-Wing Encapsulator ************************* //

XWingEncapsulator::XWingEncapsulator(const byte *publicKey, size_t publicKeyLen)
{
    m_key.SetPublicKey(publicKey, publicKeyLen);
}

void XWingEncapsulator::Encapsulate(RandomNumberGenerator &rng, byte *ciphertext, byte *sharedSecret) const
{
    // 1. ML-KEM-768 encapsulation
    MLKEMEncapsulator<MLKEM_768> mlkem_encaps;
    mlkem_encaps.AccessPublicKey().SetPublicKey(m_key.GetMLKEMPublicKeyPtr(), MLKEM_768::PUBLIC_KEY_SIZE);

    SecByteBlock mlkem_ct(MLKEM_768::CIPHERTEXT_SIZE);
    SecByteBlock mlkem_ss(32);
    mlkem_encaps.Encapsulate(rng, mlkem_ct.begin(), mlkem_ss.begin());

    // 2. X25519 ephemeral key generation and key exchange
    SecByteBlock x25519_ek(32);  // ephemeral private key
    SecByteBlock x25519_ct(32);  // ephemeral public key (ciphertext)
    SecByteBlock x25519_ss(32);  // shared secret

    // Generate ephemeral X25519 key pair
    x25519 x25519_agreement;
    x25519_agreement.GeneratePrivateKey(rng, x25519_ek.begin());
    x25519_agreement.GeneratePublicKey(rng, x25519_ek.begin(), x25519_ct.begin());

    // Compute X25519 shared secret: DH(ephemeral_private, recipient_public)
    if (!x25519_agreement.Agree(x25519_ss.begin(), x25519_ek.begin(), m_key.GetX25519PublicKeyPtr()))
        throw InvalidArgument("X-Wing: recipient X25519 public key is invalid (small-order point)");

    // 3. Assemble ciphertext: ML-KEM ciphertext || X25519 ephemeral public key
    std::memcpy(ciphertext, mlkem_ct.begin(), MLKEM_768::CIPHERTEXT_SIZE);
    std::memcpy(ciphertext + MLKEM_768::CIPHERTEXT_SIZE, x25519_ct.begin(), 32);

    // 4. Combine shared secrets using X-Wing combiner
    XWingInternal::Combiner(sharedSecret, mlkem_ss.begin(), x25519_ss.begin(),
                           x25519_ct.begin(), m_key.GetX25519PublicKeyPtr());
}

// ******************** X-Wing Decapsulator ************************* //

XWingDecapsulator::XWingDecapsulator(RandomNumberGenerator &rng)
{
    m_key.GenerateRandom(rng, g_nullNameValuePairs);
}

bool XWingDecapsulator::Decapsulate(const byte *ciphertext, byte *sharedSecret) const
{
    CRYPTOPP_ASSERT(ciphertext != NULLPTR);
    CRYPTOPP_ASSERT(sharedSecret != NULLPTR);

    // 1. Parse ciphertext
    const byte *mlkem_ct = ciphertext;
    const byte *x25519_ct = ciphertext + MLKEM_768::CIPHERTEXT_SIZE;  // ephemeral public key

    // 2. ML-KEM-768 decapsulation
    MLKEMDecapsulator<MLKEM_768> mlkem_decaps;
    mlkem_decaps.AccessPrivateKey().SetPrivateKey(m_key.GetMLKEMPrivateKeyPtr(), MLKEM_768::SECRET_KEY_SIZE);

    SecByteBlock mlkem_ss(32);
    mlkem_decaps.Decapsulate(mlkem_ct, mlkem_ss.begin());

    // 3. X25519 key exchange: DH(recipient_private, ephemeral_public)
    // Per X-Wing spec Section 6.2: decapsulation MUST NOT return a failure.
    // Always proceed through the combiner regardless of X25519 result.
    // If the ephemeral key is small-order, Agree() returns false and x25519_ss
    // is all-zeros; the combiner still produces a pseudorandom shared secret.
    SecByteBlock x25519_ss(32);

    x25519 x25519_agreement;
    x25519_agreement.Agree(x25519_ss.begin(), m_key.GetX25519PrivateKeyPtr(), x25519_ct);

    // 4. Combine shared secrets using X-Wing combiner
    XWingInternal::Combiner(sharedSecret, mlkem_ss.begin(), x25519_ss.begin(),
                           x25519_ct, m_key.GetX25519PublicKeyPtr());

    return true;
}

NAMESPACE_END
