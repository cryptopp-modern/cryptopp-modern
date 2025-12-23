// xaes_256_gcm.h - written and placed in the public domain by Colin Brown
//                  C2SP XAES-256-GCM, https://c2sp.org/XAES-256-GCM

/// \file xaes_256_gcm.h
/// \brief XAES-256-GCM authenticated encryption mode
/// \details XAES-256-GCM is an extended-nonce variant of AES-256-GCM that enables
///  safe random nonce generation for a virtually unlimited number of messages.
///  The scheme is specified by C2SP and uses NIST SP 800-108r1 key derivation
///  with standard AES-256-GCM.
/// \details XAES-256-GCM requires exactly a 256-bit (32 byte) key and a 192-bit
///  (24 byte) nonce. The extended nonce is safe for random generation with up to
///  2^80 messages at 2^-32 collision probability. The first 96 bits of the nonce
///  are used for key derivation, and the last 96 bits are used as the GCM nonce.
/// \details The scheme adds only 2 AES-256 block encryptions per message compared
///  to standard GCM. One additional block encryption (L computation for CMAC subkey)
///  is precomputed once per master key and cached.
///
/// \par Nonce Generation
/// Nonces MUST be unique for each message under the same key. The 192-bit nonce
/// space allows safe random generation via \p GetNextIV() with a cryptographically
/// secure RNG (e.g., \p AutoSeededRandomPool). Do not use weak or predictable RNGs.
/// Nonce reuse completely compromises message confidentiality and authenticity.
///
/// \par Streaming Interface
/// When using the streaming interface, call \p Resynchronize() with a fresh random
/// nonce before each message. Do not use \p Restart() to process multiple messages
/// as it does not change the nonce and would result in catastrophic nonce reuse.
///
/// \sa <A HREF="https://c2sp.org/XAES-256-GCM">C2SP XAES-256-GCM specification</A>
/// \since cryptopp-modern 2025.12.0

#ifndef CRYPTOPP_XAES_256_GCM_H
#define CRYPTOPP_XAES_256_GCM_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/misc.h>

#include <cstring>
#include <string>
#include <type_traits>

NAMESPACE_BEGIN(CryptoPP)

/// \brief XAES-256-GCM block cipher final implementation
/// \tparam T_IsEncryption direction in which to operate the cipher
/// \details XAES_256_GCM_Final provides the \p Encryption and \p Decryption
///  implementations of XAES-256-GCM authenticated encryption.
/// \sa XAES_256_GCM, <A HREF="https://c2sp.org/XAES-256-GCM">C2SP XAES-256-GCM
///  specification</A>
/// \since cryptopp-modern 2025.12
template <bool T_IsEncryption>
class XAES_256_GCM_Final : public AuthenticatedSymmetricCipher
{
public:
	CRYPTOPP_CONSTANT(KEY_SIZE = 32);
	CRYPTOPP_CONSTANT(IV_SIZE = 24);
	CRYPTOPP_CONSTANT(TAG_SIZE = 16);
	CRYPTOPP_CONSTANT(BLOCK_SIZE = 16);

	XAES_256_GCM_Final() : m_keySet(false), m_ivSet(false) {}
	virtual ~XAES_256_GCM_Final();

	static std::string StaticAlgorithmName()
		{return "XAES-256-GCM";}

	// AuthenticatedSymmetricCipher interface
	std::string AlgorithmName() const
		{return "XAES-256-GCM";}
	std::string AlgorithmProvider() const
		{return m_gcm.AlgorithmProvider();}
	size_t MinKeyLength() const
		{return KEY_SIZE;}
	size_t MaxKeyLength() const
		{return KEY_SIZE;}
	size_t DefaultKeyLength() const
		{return KEY_SIZE;}
	size_t GetValidKeyLength(size_t n) const
		{return n == KEY_SIZE ? KEY_SIZE : 0;}
	bool IsValidKeyLength(size_t n) const
		{return n == KEY_SIZE;}
	IV_Requirement IVRequirement() const
		{return RANDOM_IV;}
	unsigned int IVSize() const
		{return IV_SIZE;}
	unsigned int MinIVLength() const
		{return IV_SIZE;}
	unsigned int MaxIVLength() const
		{return IV_SIZE;}
	unsigned int DigestSize() const
		{return TAG_SIZE;}
	unsigned int TagSize() const
		{return TAG_SIZE;}
	lword MaxHeaderLength() const
		{return m_gcm.MaxHeaderLength();}
	lword MaxMessageLength() const
		{return m_gcm.MaxMessageLength();}
	lword MaxFooterLength() const
		{return 0;}
	bool NeedsPrespecifiedDataLengths() const
		{return false;}
	bool IsForwardTransformation() const
		{return T_IsEncryption;}
	unsigned int MandatoryBlockSize() const
		{return 1;}
	bool IsRandomAccess() const
		{return false;}
	bool IsSelfInverting() const
		{return false;}

	// Key and IV setup
	void SetKey(const byte *userKey, size_t keylength, const NameValuePairs &params = g_nullNameValuePairs);
	void SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength = IV_SIZE);
	void Resynchronize(const byte *iv, int ivLength = -1);
	void GetNextIV(RandomNumberGenerator &rng, byte *iv);
	void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params)
		{SetKey(key, length, params);}

	// Streaming interface - delegated to GCM with IV state enforcement
	void Update(const byte *input, size_t length)
	{
		ThrowIfNoKey();
		ThrowIfNoIV();
		if (length > 0 && input == NULLPTR)
			throw InvalidArgument(AlgorithmName() + ": null input with non-zero length");
		m_gcm.Update(input, length);
	}
	void ProcessData(byte *outString, const byte *inString, size_t length)
	{
		ThrowIfNoKey();
		ThrowIfNoIV();
		if (length > 0 && (inString == NULLPTR || outString == NULLPTR))
			throw InvalidArgument(AlgorithmName() + ": null buffer with non-zero length");
		m_gcm.ProcessData(outString, inString, length);
	}
	void TruncatedFinal(byte *mac, size_t macSize)
	{
		ThrowIfNoKey();
		ThrowIfNoIV();
		if (macSize != TAG_SIZE)
			throw InvalidArgument(AlgorithmName() + ": tag size must be " +
				IntToString(static_cast<unsigned int>(TAG_SIZE)) + " bytes");
		try {
			m_gcm.TruncatedFinal(mac, macSize);
		} catch (...) {
			m_ivSet = false;
			throw;
		}
		m_ivSet = false;
	}
	bool TruncatedVerify(const byte *mac, size_t macSize)
	{
		ThrowIfNoKey();
		ThrowIfNoIV();
		if (macSize != TAG_SIZE)
			throw InvalidArgument(AlgorithmName() + ": tag size must be " +
				IntToString(static_cast<unsigned int>(TAG_SIZE)) + " bytes");
		bool result;
		try {
			result = m_gcm.TruncatedVerify(mac, macSize);
		} catch (...) {
			m_ivSet = false;
			throw;
		}
		m_ivSet = false;
		return result;
	}
	void Restart()
		{
			// XAES-256-GCM does not support Restart() between messages.
			// Use Resynchronize() with a fresh 24-byte IV instead.
			throw BadState(AlgorithmName(), "Restart");
		}

	/// \brief Encrypts and calculates a MAC in one call
	/// \param ciphertext the encryption buffer
	/// \param mac the MAC buffer
	/// \param macSize the size of the MAC buffer, in bytes
	/// \param iv the 24-byte nonce buffer
	/// \param ivLength the size of the IV buffer, in bytes (must be 24)
	/// \param aad the AAD buffer
	/// \param aadLength the size of the AAD buffer, in bytes
	/// \param message the plaintext buffer
	/// \param messageLength the size of the plaintext buffer, in bytes
	/// \details EncryptAndAuthenticate() encrypts and generates the MAC in one call.
	void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *message, size_t messageLength);

	/// \brief Decrypts and verifies a MAC in one call
	/// \param message the decryption buffer
	/// \param mac the MAC buffer
	/// \param macSize the size of the MAC buffer, in bytes
	/// \param iv the 24-byte nonce buffer
	/// \param ivLength the size of the IV buffer, in bytes (must be 24)
	/// \param aad the AAD buffer
	/// \param aadLength the size of the AAD buffer, in bytes
	/// \param ciphertext the ciphertext buffer
	/// \param ciphertextLength the size of the ciphertext buffer, in bytes
	/// \return true if the MAC is valid and decryption succeeded, false otherwise
	/// \details DecryptAndVerify() decrypts and verifies the MAC in one call.
	///  The message buffer should be at least as large as the ciphertext buffer.
	bool DecryptAndVerify(byte *message, const byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *ciphertext, size_t ciphertextLength);

	// byte processing - not supported, use block processing
	byte ProcessByte(byte input)
		{byte output; ProcessData(&output, &input, 1); return output;}
	size_t ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength)
		{CRYPTOPP_UNUSED(outLength); ProcessData(outString, inString, inLength); return inLength;}
	unsigned int MinLastBlockSize() const
		{return 0;}

protected:
	void DeriveKey(const byte *nonce12, byte *derivedKey);
	void ThrowIfNoKey() const;
	void ThrowIfNoIV() const;

	SecByteBlock m_key;
	CRYPTOPP_ALIGN_DATA(16) byte m_L[BLOCK_SIZE];
	CRYPTOPP_ALIGN_DATA(16) byte m_K1[BLOCK_SIZE];
	AES::Encryption m_aes;
	typename std::conditional<T_IsEncryption,
		GCM<AES>::Encryption, GCM<AES>::Decryption>::type m_gcm;
	SecByteBlock m_derivedKey;
	bool m_keySet;
	bool m_ivSet;
};

/// \brief XAES-256-GCM authenticated encryption scheme
/// \details XAES_256_GCM provides the \p Encryption and \p Decryption typedef.
///  See XAES_256_GCM_Final for the AuthenticatedSymmetricCipher implementation.
/// \sa XAES_256_GCM_Final, <A HREF="https://c2sp.org/XAES-256-GCM">C2SP XAES-256-GCM
///  specification</A>
/// \since cryptopp-modern 2025.12
struct XAES_256_GCM : public AuthenticatedSymmetricCipherDocumentation
{
	/// \brief XAES-256-GCM encryption
	typedef XAES_256_GCM_Final<true> Encryption;
	/// \brief XAES-256-GCM decryption
	typedef XAES_256_GCM_Final<false> Decryption;
};

// Template implementation

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::ThrowIfNoKey() const
{
	if (!m_keySet)
		throw BadState(AlgorithmName(), "SetKey");
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::ThrowIfNoIV() const
{
	if (!m_ivSet)
		throw BadState(AlgorithmName(), "Resynchronize");
}

template <bool T_IsEncryption>
XAES_256_GCM_Final<T_IsEncryption>::~XAES_256_GCM_Final()
{
	// Zeroize key material and derived state
	if (m_key.size())
		SecureWipeArray(m_key.data(), m_key.size());
	if (m_derivedKey.size())
		SecureWipeArray(m_derivedKey.data(), m_derivedKey.size());

	SecureWipeArray(m_L, BLOCK_SIZE);
	SecureWipeArray(m_K1, BLOCK_SIZE);
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::SetKey(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	if (userKey == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": key is null");
	CRYPTOPP_ASSERT(keylength == KEY_SIZE);
	if (keylength != KEY_SIZE)
		throw InvalidKeyLength(AlgorithmName(), keylength);

	// Store the master key
	m_key.Assign(userKey, keylength);
	m_derivedKey.resize(KEY_SIZE);

	// Set up the AES cipher for key derivation
	m_aes.SetKey(userKey, keylength);

	// Precompute L = AES-256(key, 0^128)
	std::memset(m_L, 0, BLOCK_SIZE);
	m_aes.ProcessBlock(m_L);

	// Compute K1 = L << 1, with conditional XOR of 0x87 if MSB was set
	// This is the CMAC subkey derivation from NIST SP 800-38B
	// Use constant-time mask to avoid secret-dependent branch
	byte msb = m_L[0] >> 7;
	for (unsigned int i = 0; i < BLOCK_SIZE - 1; ++i)
		m_K1[i] = (m_L[i] << 1) | (m_L[i + 1] >> 7);
	m_K1[BLOCK_SIZE - 1] = m_L[BLOCK_SIZE - 1] << 1;

	// Constant-time conditional XOR: mask is 0xFF if msb==1, 0x00 otherwise
	const byte mask = static_cast<byte>(0 - msb);
	m_K1[BLOCK_SIZE - 1] ^= (0x87 & mask);

	m_keySet = true;
	m_ivSet = false;

	// Check for IV in params
	size_t ivLength;
	const byte *iv = GetIVAndThrowIfInvalid(params, ivLength);
	if (iv)
		Resynchronize(iv, (int)ivLength);
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength)
{
	SetKey(key, length);
	Resynchronize(iv, (int)ivLength);
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::DeriveKey(const byte *nonce12, byte *derivedKey)
{
	// XAES-256-GCM key derivation per C2SP spec:
	// M1 = 0x00 || 0x01 || "X" || 0x00 || nonce[0:12]  (16 bytes)
	// M2 = 0x00 || 0x02 || "X" || 0x00 || nonce[0:12]  (16 bytes)
	// derived_key = AES-256(key, M1 XOR K1) || AES-256(key, M2 XOR K1)

	CRYPTOPP_ALIGN_DATA(16) byte M[BLOCK_SIZE];

	// Build M1: 0x00 || counter=0x01 || label="X" || 0x00 || nonce[0:12]
	M[0] = 0x00;
	M[1] = 0x01;
	M[2] = 'X';
	M[3] = 0x00;
	std::memcpy(M + 4, nonce12, 12);

	// XOR with K1 and encrypt to get first half of derived key
	xorbuf(M, m_K1, BLOCK_SIZE);
	m_aes.ProcessBlock(M, derivedKey);

	// Build M2: 0x00 || counter=0x02 || label="X" || 0x00 || nonce[0:12]
	M[0] = 0x00;
	M[1] = 0x02;
	M[2] = 'X';
	M[3] = 0x00;
	std::memcpy(M + 4, nonce12, 12);

	// XOR with K1 and encrypt to get second half of derived key
	xorbuf(M, m_K1, BLOCK_SIZE);
	m_aes.ProcessBlock(M, derivedKey + BLOCK_SIZE);

	// Wipe local buffer
	SecureWipeArray(M, BLOCK_SIZE);
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::Resynchronize(const byte *iv, int ivLength)
{
	ThrowIfNoKey();

	if (iv == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": IV is null");

	size_t len = (ivLength < 0) ? IVSize() : static_cast<size_t>(ivLength);
	CRYPTOPP_ASSERT(len == IV_SIZE);
	if (len != IV_SIZE)
		throw InvalidArgument(AlgorithmName() + ": IV length " + IntToString(len) + " is not " + IntToString(static_cast<unsigned int>(IV_SIZE)));

	// Derive per-message key from first 12 bytes of nonce
	DeriveKey(iv, m_derivedKey);

	// Set up GCM with derived key and last 12 bytes of nonce
	m_gcm.SetKeyWithIV(m_derivedKey, KEY_SIZE, iv + 12, 12);

	m_ivSet = true;
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::GetNextIV(RandomNumberGenerator &rng, byte *iv)
{
	if (iv == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": IV buffer is null");
	rng.GenerateBlock(iv, IV_SIZE);
}

template <bool T_IsEncryption>
void XAES_256_GCM_Final<T_IsEncryption>::EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize,
	const byte *iv, int ivLength, const byte *aad, size_t aadLength,
	const byte *message, size_t messageLength)
{
	ThrowIfNoKey();

	// Enforce fixed 16-byte tag for interoperability
	if (macSize != TAG_SIZE)
		throw InvalidArgument(AlgorithmName() + ": tag size must be " +
			IntToString(static_cast<unsigned int>(TAG_SIZE)) + " bytes");

	// Null pointer checks for non-zero lengths
	if (messageLength > 0 && (message == NULLPTR || ciphertext == NULLPTR))
		throw InvalidArgument(AlgorithmName() + ": null buffer with non-zero length");
	if (aadLength > 0 && aad == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": null AAD with non-zero length");
	if (mac == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": MAC buffer is null");

	Resynchronize(iv, ivLength);
	try {
		m_gcm.EncryptAndAuthenticate(ciphertext, mac, macSize,
			iv + 12, 12, aad, aadLength, message, messageLength);
	} catch (...) {
		m_ivSet = false;
		throw;
	}
	m_ivSet = false;
}

template <bool T_IsEncryption>
bool XAES_256_GCM_Final<T_IsEncryption>::DecryptAndVerify(byte *message, const byte *mac, size_t macSize,
	const byte *iv, int ivLength, const byte *aad, size_t aadLength,
	const byte *ciphertext, size_t ciphertextLength)
{
	ThrowIfNoKey();

	// Enforce fixed 16-byte tag for interoperability
	if (macSize != TAG_SIZE)
		throw InvalidArgument(AlgorithmName() + ": tag size must be " +
			IntToString(static_cast<unsigned int>(TAG_SIZE)) + " bytes");

	// Null pointer checks for non-zero lengths
	if (ciphertextLength > 0 && (ciphertext == NULLPTR || message == NULLPTR))
		throw InvalidArgument(AlgorithmName() + ": null buffer with non-zero length");
	if (aadLength > 0 && aad == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": null AAD with non-zero length");
	if (mac == NULLPTR)
		throw InvalidArgument(AlgorithmName() + ": MAC buffer is null");

	Resynchronize(iv, ivLength);
	bool result;
	try {
		result = m_gcm.DecryptAndVerify(message, mac, macSize,
			iv + 12, 12, aad, aadLength, ciphertext, ciphertextLength);
	} catch (...) {
		m_ivSet = false;
		throw;
	}
	m_ivSet = false;
	return result;
}

NAMESPACE_END

#endif  // CRYPTOPP_XAES_256_GCM_H
