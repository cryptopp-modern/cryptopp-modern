// xaes_256_gcm.h - written and placed in the public domain by Colin Brown
//                  C2SP XAES-256-GCM, https://c2sp.org/XAES-256-GCM
//
// STUB VERSION: declarations + placeholder bodies (non-functional).
// Implement the TODO sections to make this a working XAES-256-GCM mode.

#ifndef CRYPTOPP_XAES_256_GCM_H
#define CRYPTOPP_XAES_256_GCM_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/misc.h>

#include <cstring>

NAMESPACE_BEGIN(CryptoPP)

template <bool T_IsEncryption>
class XAES_256_GCM_Final : public AuthenticatedSymmetricCipher
{
public:
	CRYPTOPP_CONSTANT(KEY_SIZE = 32);
	CRYPTOPP_CONSTANT(IV_SIZE  = 24);
	CRYPTOPP_CONSTANT(TAG_SIZE = 16);
	CRYPTOPP_CONSTANT(BLOCK_SIZE = 16);

	XAES_256_GCM_Final() : m_keySet(false) {}
	virtual ~XAES_256_GCM_Final() {}

	static std::string StaticAlgorithmName() { return "XAES-256-GCM"; }

	std::string AlgorithmName() const override { return "XAES-256-GCM"; }
	std::string AlgorithmProvider() const override { return m_gcm.AlgorithmProvider(); }

	size_t MinKeyLength() const override { return KEY_SIZE; }
	size_t MaxKeyLength() const override { return KEY_SIZE; }
	size_t DefaultKeyLength() const override { return KEY_SIZE; }
	size_t GetValidKeyLength(size_t n) const override { return n == KEY_SIZE ? KEY_SIZE : 0; }
	bool IsValidKeyLength(size_t n) const override { return n == KEY_SIZE; }

	IV_Requirement IVRequirement() const override { return RANDOM_IV; }
	unsigned int IVSize() const override { return IV_SIZE; }
	unsigned int MinIVLength() const override { return IV_SIZE; }
	unsigned int MaxIVLength() const override { return IV_SIZE; }

	unsigned int DigestSize() const override { return TAG_SIZE; }
	unsigned int TagSize() const override { return TAG_SIZE; }

	lword MaxHeaderLength() const override { return m_gcm.MaxHeaderLength(); }
	lword MaxMessageLength() const override { return m_gcm.MaxMessageLength(); }
	lword MaxFooterLength() const override { return 0; }

	bool NeedsPrespecifiedDataLengths() const override { return false; }
	bool IsForwardTransformation() const override { return T_IsEncryption; }
	unsigned int MandatoryBlockSize() const override { return 1; }

	bool IsRandomAccess() const override { return false; }
	bool IsSelfInverting() const override { return false; }

	void SetKey(const byte *userKey, size_t keylength,
		const NameValuePairs &params = g_nullNameValuePairs) override
	{
		CRYPTOPP_UNUSED(userKey);
		CRYPTOPP_UNUSED(keylength);
		CRYPTOPP_UNUSED(params);

		throw NotImplemented(AlgorithmName(), "SetKey");
	}

	void SetKeyWithIV(const byte *key, size_t length,
		const byte *iv, size_t ivLength = IV_SIZE)
	{
		CRYPTOPP_UNUSED(key);
		CRYPTOPP_UNUSED(length);
		CRYPTOPP_UNUSED(iv);
		CRYPTOPP_UNUSED(ivLength);

		throw NotImplemented(AlgorithmName(), "SetKeyWithIV");
	}

	void Resynchronize(const byte *iv, int ivLength = -1) override
	{
		CRYPTOPP_UNUSED(iv);
		CRYPTOPP_UNUSED(ivLength);

		throw NotImplemented(AlgorithmName(), "Resynchronize");
	}

	void GetNextIV(RandomNumberGenerator &rng, byte *iv) override
	{
		CRYPTOPP_UNUSED(rng);
		CRYPTOPP_UNUSED(iv);

		throw NotImplemented(AlgorithmName(), "GetNextIV");
	}

	void UncheckedSetKey(const byte *key, unsigned int length,
		const NameValuePairs &params) override
	{
		SetKey(key, length, params);
	}

	void Update(const byte *input, size_t length) override
	{
		CRYPTOPP_UNUSED(input);
		CRYPTOPP_UNUSED(length);

		throw NotImplemented(AlgorithmName(), "Update");
	}

	void ProcessData(byte *outString, const byte *inString, size_t length) override
	{
		CRYPTOPP_UNUSED(outString);
		CRYPTOPP_UNUSED(inString);
		CRYPTOPP_UNUSED(length);

		throw NotImplemented(AlgorithmName(), "ProcessData");
	}

	void TruncatedFinal(byte *mac, size_t macSize) override
	{
		CRYPTOPP_UNUSED(mac);
		CRYPTOPP_UNUSED(macSize);

		throw NotImplemented(AlgorithmName(), "TruncatedFinal");
	}

	bool TruncatedVerify(const byte *mac, size_t length) override
	{
		CRYPTOPP_UNUSED(mac);
		CRYPTOPP_UNUSED(length);

		throw NotImplemented(AlgorithmName(), "TruncatedVerify");
	}

	void Restart() override
	{
		throw BadState(AlgorithmName(), "Restart");
	}

	void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *message, size_t messageLength) override
	{
		CRYPTOPP_UNUSED(ciphertext);
		CRYPTOPP_UNUSED(mac);
		CRYPTOPP_UNUSED(macSize);
		CRYPTOPP_UNUSED(iv);
		CRYPTOPP_UNUSED(ivLength);
		CRYPTOPP_UNUSED(aad);
		CRYPTOPP_UNUSED(aadLength);
		CRYPTOPP_UNUSED(message);
		CRYPTOPP_UNUSED(messageLength);

		throw NotImplemented(AlgorithmName(), "EncryptAndAuthenticate");
	}

	bool DecryptAndVerify(byte *message, const byte *mac, size_t macSize,
		const byte *iv, int ivLength, const byte *aad, size_t aadLength,
		const byte *ciphertext, size_t ciphertextLength) override
	{
		CRYPTOPP_UNUSED(message);
		CRYPTOPP_UNUSED(mac);
		CRYPTOPP_UNUSED(macSize);
		CRYPTOPP_UNUSED(iv);
		CRYPTOPP_UNUSED(ivLength);
		CRYPTOPP_UNUSED(aad);
		CRYPTOPP_UNUSED(aadLength);
		CRYPTOPP_UNUSED(ciphertext);
		CRYPTOPP_UNUSED(ciphertextLength);

		throw NotImplemented(AlgorithmName(), "DecryptAndVerify");
	}

	byte ProcessByte(byte input) override
	{
		byte output = 0;
		ProcessData(&output, &input, 1);
		return output;
	}

	size_t ProcessLastBlock(byte *outString, size_t outLength,
		const byte *inString, size_t inLength) override
	{
		CRYPTOPP_UNUSED(outLength);
		ProcessData(outString, inString, inLength);
		return inLength;
	}

	unsigned int MinLastBlockSize() const override { return 0; }

protected:
	void DeriveKey(const byte *nonce12, byte *derivedKey)
	{
		CRYPTOPP_UNUSED(nonce12);
		CRYPTOPP_UNUSED(derivedKey);

		throw NotImplemented(AlgorithmName(), "DeriveKey");
	}

	void ThrowIfNoKey() const
	{
		if (!m_keySet)
			throw BadState(AlgorithmName(), "SetKey");
	}

protected:
	SecByteBlock m_key;
	CRYPTOPP_ALIGN_DATA(16) byte m_L[BLOCK_SIZE] = {0};
	CRYPTOPP_ALIGN_DATA(16) byte m_K1[BLOCK_SIZE] = {0};

	AES::Encryption m_aes;
	typename std::conditional<T_IsEncryption,
		GCM<AES>::Encryption, GCM<AES>::Decryption>::type m_gcm;

	SecByteBlock m_derivedKey;
	bool m_keySet;
};

struct XAES_256_GCM : public AuthenticatedSymmetricCipherDocumentation
{
	typedef XAES_256_GCM_Final<true>  Encryption;
	typedef XAES_256_GCM_Final<false> Decryption;
};

NAMESPACE_END

#endif  // CRYPTOPP_XAES_256_GCM_H
