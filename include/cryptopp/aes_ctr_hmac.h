// aes_ctr_hmac.h - written and placed in the public domain by Colin Brown

/// \file aes_ctr_hmac.h
/// \brief AES-CTR-HMAC authenticated encryption mode
/// \details AES-CTR-HMAC is an Encrypt-then-MAC (EtM) authenticated encryption
///  scheme combining AES in CTR mode with HMAC for authentication.
///
/// \par Key Derivation
/// A single master key is expanded via HKDF into separate encryption and MAC keys.
/// The master key length determines the AES variant used:
/// - 16 bytes → AES-128
/// - 24 bytes → AES-192
/// - 32 bytes → AES-256
///
/// Key lengths are validated against the block cipher's valid key lengths.
/// The derived keys are:
/// - Encryption key: same size as the (validated) master key length
/// - MAC key: T_HashFunction::DIGESTSIZE bytes (e.g. 32 bytes for SHA-256)
///
/// The HKDF info parameter includes the hash algorithm name for domain separation
/// (e.g. "AES-CTR-HMAC-SHA256").
///
/// \par IV/Nonce Requirements
/// - Fixed 12-byte IV (unique per message under the same key)
/// - Counter block format: IV || 0x00000001 (big-endian, 16 bytes total)
/// - Counter starts at 1, reserving block 0
/// - IVs must never repeat for a given master key; reuse under AES-CTR
///   catastrophically breaks confidentiality
///
/// \par MAC Input Layout
/// The HMAC is computed over the following concatenation:
/// 1. Domain string: "AES-CTR-HMAC-{HashName}" (ASCII)
/// 2. Separator: 0x00 (1 byte)
/// 3. IV: 12 bytes
/// 4. AAD: Additional authenticated data (variable length)
/// 5. Ciphertext: Encrypted message (variable length)
/// 6. Length block: len(AAD) || len(Ciphertext) as two 64-bit big-endian integers
///
/// \par Tag Size
/// Default tag size is 16 bytes. Tag size must be between 12 bytes and
/// the full HMAC digest size (32 bytes for SHA-256, 64 bytes for SHA-512).
/// Values outside this range throw InvalidArgument.
///
/// \since cryptopp-modern 2025.12

#ifndef CRYPTOPP_AES_CTR_HMAC_H
#define CRYPTOPP_AES_CTR_HMAC_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/authenc.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/misc.h>

NAMESPACE_BEGIN(CryptoPP)

/// \brief AES-CTR-HMAC block cipher base implementation
/// \details Base implementation of the AuthenticatedSymmetricCipher interface
/// \since cryptopp-modern 2025.12
template <class T_BlockCipher, class T_HashFunction>
class CRYPTOPP_NO_VTABLE AES_CTR_HMAC_Base : public AuthenticatedSymmetricCipherBase
{
public:
	CRYPTOPP_COMPILE_ASSERT(T_BlockCipher::BLOCKSIZE == 16);
	CRYPTOPP_CONSTANT(MIN_TAG_SIZE = 12);

	virtual ~AES_CTR_HMAC_Base()
	{
		// IV is public, but wipe for hygiene
		SecureWipeArray(m_iv, sizeof(m_iv));
		// m_encKey and m_macKey are SecByteBlock and use cleaning allocator
	}

	// AuthenticatedSymmetricCipher
	std::string AlgorithmName() const
		{return std::string(T_BlockCipher::StaticAlgorithmName()) + "/CTR-HMAC(" +
		        std::string(T_HashFunction::StaticAlgorithmName()) + ")";}
	std::string AlgorithmProvider() const
		{return m_ctr.AlgorithmProvider();}
	size_t MinKeyLength() const
		{return T_BlockCipher::DEFAULT_KEYLENGTH;}
	size_t MaxKeyLength() const
		{return T_BlockCipher::MAX_KEYLENGTH;}
	size_t DefaultKeyLength() const
		{return T_BlockCipher::DEFAULT_KEYLENGTH;}
	size_t GetValidKeyLength(size_t n) const
		{return T_BlockCipher::StaticGetValidKeyLength(n);}
	bool IsValidKeyLength(size_t n) const
		{return T_BlockCipher::StaticGetValidKeyLength(n) == n;}
	IV_Requirement IVRequirement() const
		{return UNIQUE_IV;}
	unsigned int IVSize() const
		{return 12;}
	unsigned int MinIVLength() const
		{return 12;}
	unsigned int MaxIVLength() const
		{return 12;}
	unsigned int DigestSize() const
		{return T_HashFunction::DIGESTSIZE;}
	unsigned int TagSize() const
		{return 16;}
	lword MaxHeaderLength() const
		{return LWORD_MAX;}
	lword MaxMessageLength() const
		{return LWORD_MAX;}
	lword MaxFooterLength() const
		{return 0;}
	bool NeedsPrespecifiedDataLengths() const
		{return false;}

	void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *message, size_t messageLength);
	bool DecryptAndVerify(byte *message, const byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *ciphertext, size_t ciphertextLength);

	// Enforce tag size bounds for all usage paths, including streaming
	void TruncatedFinal(byte *mac, size_t macSize)
	{
		if (macSize < MIN_TAG_SIZE)
			throw InvalidArgument(AlgorithmName() + ": tag size " +
				IntToString(macSize) + " is less than minimum " +
				IntToString(static_cast<unsigned int>(MIN_TAG_SIZE)));
		if (macSize > static_cast<size_t>(DigestSize()))
			throw InvalidArgument(AlgorithmName() + ": tag size " +
				IntToString(macSize) + " exceeds maximum " +
				IntToString(static_cast<unsigned int>(DigestSize())));
		AuthenticatedSymmetricCipherBase::TruncatedFinal(mac, macSize);
	}

	bool TruncatedVerify(const byte *mac, size_t macSize)
	{
		if (macSize < MIN_TAG_SIZE)
			throw InvalidArgument(AlgorithmName() + ": tag size " +
				IntToString(macSize) + " is less than minimum " +
				IntToString(static_cast<unsigned int>(MIN_TAG_SIZE)));
		if (macSize > static_cast<size_t>(DigestSize()))
			throw InvalidArgument(AlgorithmName() + ": tag size " +
				IntToString(macSize) + " exceeds maximum " +
				IntToString(static_cast<unsigned int>(DigestSize())));
		return AuthenticatedSymmetricCipherBase::TruncatedVerify(mac, macSize);
	}

protected:
	// AuthenticatedSymmetricCipherBase
	bool AuthenticationIsOnPlaintext() const
		{return false;}
	unsigned int AuthenticationBlockSize() const
		{return 1;}
	void SetKeyWithoutResync(const byte *userKey, size_t keylength, const NameValuePairs &params);
	void Resync(const byte *iv, size_t len);
	size_t AuthenticateBlocks(const byte *data, size_t len);
	void AuthenticateLastHeaderBlock();
	void AuthenticateLastConfidentialBlock();
	void AuthenticateLastFooterBlock(byte *mac, size_t macSize);
	SymmetricCipher & AccessSymmetricCipher() {return m_ctr;}

	virtual const MessageAuthenticationCode & GetMAC() const =0;
	virtual MessageAuthenticationCode & AccessMAC() =0;

	void DeriveKeys(const byte *masterKey, size_t masterKeyLen);

	std::string DomainString() const {
		return std::string("AES-CTR-HMAC-") + T_HashFunction::StaticAlgorithmName();
	}

	SecByteBlock m_encKey;
	SecByteBlock m_macKey;
	CRYPTOPP_ALIGN_DATA(16) byte m_iv[12];
	typename CTR_Mode<T_BlockCipher>::Encryption m_ctr;
	lword m_aadLength;
	lword m_ciphertextLength;
};

/// \brief AES-CTR-HMAC block cipher final implementation
/// \tparam T_BlockCipher block cipher
/// \tparam T_HashFunction hash function for HMAC
/// \tparam T_IsEncryption direction in which to operate the cipher
/// \since cryptopp-modern 2025.12
template <class T_BlockCipher, class T_HashFunction, bool T_IsEncryption>
class AES_CTR_HMAC_Final : public AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>
{
public:
	static std::string StaticAlgorithmName()
		{return std::string(T_BlockCipher::StaticAlgorithmName()) + "/CTR-HMAC(" +
		        std::string(T_HashFunction::StaticAlgorithmName()) + ")";}
	bool IsForwardTransformation() const
		{return T_IsEncryption;}

private:
	const MessageAuthenticationCode & GetMAC() const
		{return const_cast<AES_CTR_HMAC_Final*>(this)->AccessMAC();}
	MessageAuthenticationCode & AccessMAC()
		{return m_mac;}

	HMAC<T_HashFunction> m_mac;
};

/// \brief AES-CTR-HMAC block cipher mode of operation
/// \tparam T_BlockCipher block cipher
/// \tparam T_HashFunction hash function for HMAC
/// \details \p AES_CTR_HMAC provides the \p Encryption and \p Decryption typedef.
///  See AES_CTR_HMAC_Base and AES_CTR_HMAC_Final for the AuthenticatedSymmetricCipher
///  implementation.
/// \details The AES variant (128/192/256) is determined by the master key length
///  passed to SetKey (16, 24, or 32 bytes respectively).
/// \since cryptopp-modern 2025.12
template <class T_BlockCipher = AES, class T_HashFunction = SHA256>
struct AES_CTR_HMAC : public AuthenticatedSymmetricCipherDocumentation
{
	typedef AES_CTR_HMAC_Final<T_BlockCipher, T_HashFunction, true> Encryption;
	typedef AES_CTR_HMAC_Final<T_BlockCipher, T_HashFunction, false> Decryption;
};

/// \brief Convenience typedef for AES-CTR-HMAC with SHA-256
/// \details Use a 16-byte key for AES-128, 24-byte for AES-192, or 32-byte for AES-256
typedef AES_CTR_HMAC<AES, SHA256> AES_CTR_HMAC_SHA256;

/// \brief Convenience typedef for AES-CTR-HMAC with SHA-512
/// \details Use a 16-byte key for AES-128, 24-byte for AES-192, or 32-byte for AES-256
typedef AES_CTR_HMAC<AES, SHA512> AES_CTR_HMAC_SHA512;

// Template implementation

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::DeriveKeys(
	const byte *masterKey, size_t masterKeyLen)
{
	HKDF<T_HashFunction> hkdf;

	// masterKeyLen is already validated by SetKey/GetValidKeyLength,
	// so it directly determines the AES key size (16, 24, or 32 bytes)
	size_t encKeyLen = masterKeyLen;
	size_t macKeyLen = T_HashFunction::DIGESTSIZE;

	m_encKey.resize(encKeyLen);
	m_macKey.resize(macKeyLen);

	SecByteBlock derived(encKeyLen + macKeyLen);

	std::string domain = DomainString();
	hkdf.DeriveKey(derived, derived.size(),
	               masterKey, masterKeyLen,
	               NULLPTR, 0,
	               reinterpret_cast<const byte*>(domain.data()), domain.size());

	std::memcpy(m_encKey, derived, encKeyLen);
	std::memcpy(m_macKey, derived + encKeyLen, macKeyLen);
	// derived is SecByteBlock - auto-wipes on destruction
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::SetKeyWithoutResync(
	const byte *userKey, size_t keylength, const NameValuePairs& /*params*/)
{
	DeriveKeys(userKey, keylength);
	AccessMAC().SetKey(m_macKey, m_macKey.size());
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::Resync(
	const byte *iv, size_t len)
{
	CRYPTOPP_ASSERT(len == 12);
	if (len != 12)
		throw InvalidArgument(AlgorithmName() + ": IV length must be 12 bytes");

	std::memcpy(m_iv, iv, 12);

	// Build 16-byte counter block: IV || 0x00000001 (big-endian)
	CRYPTOPP_ALIGN_DATA(16) byte counterBlock[16];
	std::memcpy(counterBlock, m_iv, 12);
	counterBlock[12] = 0;
	counterBlock[13] = 0;
	counterBlock[14] = 0;
	counterBlock[15] = 1;

	m_ctr.SetKeyWithIV(m_encKey, m_encKey.size(), counterBlock, 16);

	// Initialize HMAC with domain separation and IV
	AccessMAC().Restart();
	std::string domain = DomainString();
	AccessMAC().Update(reinterpret_cast<const byte*>(domain.data()), domain.size());
	const byte sep = 0x00;
	AccessMAC().Update(&sep, 1);
	AccessMAC().Update(m_iv, 12);

	m_aadLength = 0;
	m_ciphertextLength = 0;
}

template <class T_BlockCipher, class T_HashFunction>
size_t AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::AuthenticateBlocks(
	const byte *data, size_t len)
{
	AccessMAC().Update(data, len);
	return 0;
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::AuthenticateLastHeaderBlock()
{
	m_aadLength = this->m_totalHeaderLength;
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::AuthenticateLastConfidentialBlock()
{
	m_ciphertextLength = this->m_totalMessageLength;
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::AuthenticateLastFooterBlock(
	byte *mac, size_t macSize)
{
	CRYPTOPP_ALIGN_DATA(8) byte lengthBlock[16];
	PutWord<word64>(false, BIG_ENDIAN_ORDER, lengthBlock, m_aadLength);
	PutWord<word64>(false, BIG_ENDIAN_ORDER, lengthBlock + 8, m_ciphertextLength);
	AccessMAC().Update(lengthBlock, 16);

	SecByteBlock fullTag(AccessMAC().DigestSize());
	AccessMAC().Final(fullTag);

	// macSize is already validated by TruncatedFinal/TruncatedVerify
	std::memcpy(mac, fullTag, macSize);
	// fullTag is SecByteBlock - auto-wipes on destruction
	// lengthBlock is raw stack array - wipe explicitly
	SecureWipeArray(lengthBlock, sizeof(lengthBlock));
}

template <class T_BlockCipher, class T_HashFunction>
void AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::EncryptAndAuthenticate(
	byte *ciphertext, byte *mac, size_t macSize,
	const byte *iv, int ivLength,
	const byte *aad, size_t aadLength,
	const byte *message, size_t messageLength)
{
	size_t len = (ivLength < 0) ? IVSize() : static_cast<size_t>(ivLength);
	Resync(iv, len);
	this->SpecifyDataLengths(aadLength, messageLength, 0);
	if (aadLength)
		this->Update(aad, aadLength);
	if (messageLength)
		this->ProcessString(ciphertext, message, messageLength);
	TruncatedFinal(mac, macSize);
}

template <class T_BlockCipher, class T_HashFunction>
bool AES_CTR_HMAC_Base<T_BlockCipher, T_HashFunction>::DecryptAndVerify(
	byte *message, const byte *mac, size_t macSize,
	const byte *iv, int ivLength,
	const byte *aad, size_t aadLength,
	const byte *ciphertext, size_t ciphertextLength)
{
	size_t len = (ivLength < 0) ? IVSize() : static_cast<size_t>(ivLength);
	Resync(iv, len);
	this->SpecifyDataLengths(aadLength, ciphertextLength, 0);
	if (aadLength)
		this->Update(aad, aadLength);
	if (ciphertextLength)
		this->ProcessString(message, ciphertext, ciphertextLength);
	return TruncatedVerify(mac, macSize);
}

NAMESPACE_END

#endif  // CRYPTOPP_AES_CTR_HMAC_H
