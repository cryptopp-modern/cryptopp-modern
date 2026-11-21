// validat8.cpp - originally written and placed in the public domain by Wei Dai
//                CryptoPP::Test namespace added by JW in February 2017.
//                Source files split in July 2018 to expedite compiles.

#include <cryptopp/pch.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/cryptlib.h>
#include <cryptopp/cpu.h>
#include <cryptopp/validate.h>

#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/nbtheory.h>

#include <cryptopp/luc.h>
#include <cryptopp/rsa.h>
#include <cryptopp/xtr.h>
#include <cryptopp/rabin.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/xtrcrypt.h>
#include <cryptopp/eccrypto.h>

#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

#include <iostream>
#include <iomanip>
#include <sstream>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

ANONYMOUS_NAMESPACE_BEGIN

inline byte* C2B(char* ptr) {
    return reinterpret_cast<byte*>(ptr);
}

inline const byte* C2B(const char* ptr) {
    return reinterpret_cast<const byte*>(ptr);
}

inline bool operator==(const RSA::PrivateKey& lhs, const RSA::PrivateKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetPublicExponent() == rhs.GetPublicExponent() &&
		lhs.GetPrivateExponent() == rhs.GetPrivateExponent();
}

inline bool operator!=(const RSA::PrivateKey& lhs, const RSA::PrivateKey& rhs) {
	return !operator==(lhs, rhs);
}

inline bool operator==(const RSA::PublicKey& lhs, const RSA::PublicKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetPublicExponent() == rhs.GetPublicExponent();
}

inline bool operator!=(const RSA::PublicKey& lhs, const RSA::PublicKey& rhs) {
	return !operator==(lhs, rhs);
}

inline bool operator==(const LUC::PrivateKey& lhs, const LUC::PrivateKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetPublicExponent() == rhs.GetPublicExponent() &&
		lhs.GetPrime1() == rhs.GetPrime1() &&
		lhs.GetPrime2() == rhs.GetPrime2() &&
		lhs.GetMultiplicativeInverseOfPrime2ModPrime1() == rhs.GetMultiplicativeInverseOfPrime2ModPrime1();
}

inline bool operator!=(const LUC::PrivateKey& lhs, const LUC::PrivateKey& rhs) {
	return !operator==(lhs, rhs);
}

inline bool operator==(const LUC::PublicKey& lhs, const LUC::PublicKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetPublicExponent() == rhs.GetPublicExponent();
}

inline bool operator!=(const LUC::PublicKey& lhs, const LUC::PublicKey& rhs) {
	return !operator==(lhs, rhs);
}

inline bool operator==(const Rabin::PrivateKey& lhs, const Rabin::PrivateKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetQuadraticResidueModPrime1() == rhs.GetQuadraticResidueModPrime1() &&
		lhs.GetQuadraticResidueModPrime2() == rhs.GetQuadraticResidueModPrime2() &&
		lhs.GetPrime1() == rhs.GetPrime1() &&
		lhs.GetPrime2() == rhs.GetPrime2() &&
		lhs.GetMultiplicativeInverseOfPrime2ModPrime1() == rhs.GetMultiplicativeInverseOfPrime2ModPrime1();
}

inline bool operator!=(const Rabin::PrivateKey& lhs, const Rabin::PrivateKey& rhs) {
	return !operator==(lhs, rhs);
}

inline bool operator==(const Rabin::PublicKey& lhs, const Rabin::PublicKey& rhs) {
	return lhs.GetModulus() == rhs.GetModulus() &&
		lhs.GetQuadraticResidueModPrime1() == rhs.GetQuadraticResidueModPrime1() &&
		lhs.GetQuadraticResidueModPrime2() == rhs.GetQuadraticResidueModPrime2();
}

inline bool operator!=(const Rabin::PublicKey& lhs, const Rabin::PublicKey& rhs) {
	return !operator==(lhs, rhs);
}

// separatorIndex 0 means no separator.
void BuildPKCSBlock(byte* block, size_t blockLen, size_t separatorIndex, byte blockType)
{
	for (size_t j = 0; j < blockLen; j++)
		block[j] = (byte)(0x41 + (j % 0x3d));

	block[0] = blockType;
	if (separatorIndex != 0)
		block[separatorIndex] = 0;
}

struct PKCSUnpadCase
{
	size_t separatorIndex;
	byte blockType;
	bool valid;
};

// Final-byte separator gives an empty message.
const size_t PKCS_SEPARATOR_LAST = (size_t)-1;

// The separator must follow at least eight padding bytes.
const PKCSUnpadCase pkcsUnpadCases[] = {
	{1, 2, false}, {2, 2, false}, {3, 2, false}, {4, 2, false},
	{5, 2, false}, {6, 2, false}, {7, 2, false}, {8, 2, false},
	{9, 2, true}, {10, 2, true}, {12, 2, true},
	{PKCS_SEPARATOR_LAST, 2, true},
	{0, 2, false},
	{9, 3, false}
};

size_t PKCSSeparatorIndex(const PKCSUnpadCase& testCase, size_t blockLen)
{
	return testCase.separatorIndex == PKCS_SEPARATOR_LAST ?
		blockLen - 1 : testCase.separatorIndex;
}

bool PKCSGuardIntact(const SecByteBlock& buffer, size_t outputLen)
{
	for (size_t j = outputLen; j < buffer.size(); j++)
	{
		if (buffer[j] != 0xCC)
			return false;
	}
	return true;
}

bool TestPKCSUnpadBounds()
{
	// Keep the block byte-aligned so Unpad does not skip a leading byte.
	const size_t blockBits = 1024;
	const size_t blockLen = blockBits / 8;
	const size_t guardLen = 16;

	PKCS_EncryptionPaddingScheme padding;
	const size_t maxOutputLen = padding.MaxUnpaddedLength(blockBits);

	bool pass = true;
	for (size_t k = 0; k < COUNTOF(pkcsUnpadCases); k++)
	{
		const PKCSUnpadCase& testCase = pkcsUnpadCases[k];
		const size_t separatorIndex = PKCSSeparatorIndex(testCase, blockLen);

		SecByteBlock block(blockLen);
		BuildPKCSBlock(block, blockLen, separatorIndex, testCase.blockType);

		SecByteBlock output(maxOutputLen + guardLen);
		std::memset(output, 0xCC, output.size());

		DecodingResult result = padding.Unpad(block, blockBits, output, g_nullNameValuePairs);

		bool fail = (result.isValidCoding != testCase.valid);
		fail = fail || !PKCSGuardIntact(output, maxOutputLen);
		if (testCase.valid)
			fail = fail || (result.messageLength != blockLen - separatorIndex - 1);

		pass = pass && !fail;
	}

	std::cout << (pass ? "passed    " : "FAILED    ");
	std::cout << "PKCS 1.5 unpad separator positions (" << COUNTOF(pkcsUnpadCases) << " cases)\n";
	return pass;
}

bool TestPKCSChosenCiphertextBounds()
{
	FileSource keyFile(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
	RSAES_PKCS1v15_Decryptor rsaPriv(keyFile);

	FileSource pubKeyFile(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
	RSA::PrivateKey rawPriv; rawPriv.Load(pubKeyFile);
	RSA::PublicKey rsaPub(rawPriv);

	const size_t ciphertextLen = rsaPriv.FixedCiphertextLength();
	const size_t maxOutputLen = rsaPriv.MaxPlaintextLength(ciphertextLen);
	// Unpad sees the type byte, eight padding bytes and the separator.
	const size_t blockLen = maxOutputLen + 10;
	const size_t guardLen = 16;

	bool pass = true;
	for (size_t k = 0; k < COUNTOF(pkcsUnpadCases); k++)
	{
		const PKCSUnpadCase& testCase = pkcsUnpadCases[k];
		const size_t separatorIndex = PKCSSeparatorIndex(testCase, blockLen);

		SecByteBlock block(blockLen);
		BuildPKCSBlock(block, blockLen, separatorIndex, testCase.blockType);

		// Encrypt the chosen block so decryption passes it to Unpad.
		Integer chosen(block, blockLen);
		SecByteBlock ciphertext(ciphertextLen);
		rsaPub.ApplyFunction(chosen).Encode(ciphertext, ciphertextLen);

		SecByteBlock output(maxOutputLen + guardLen);
		std::memset(output, 0xCC, output.size());

		DecodingResult result = rsaPriv.Decrypt(GlobalRNG(), ciphertext, ciphertextLen, output);

		bool fail = (result.isValidCoding != testCase.valid);
		fail = fail || !PKCSGuardIntact(output, maxOutputLen);
		if (testCase.valid)
			fail = fail || (result.messageLength != blockLen - separatorIndex - 1);

		pass = pass && !fail;
	}

	std::cout << (pass ? "passed    " : "FAILED    ");
	std::cout << "PKCS 1.5 chosen ciphertext bounds (" << COUNTOF(pkcsUnpadCases) << " cases)\n";
	return pass;
}

struct PKCSMinBlockCase
{
	size_t blockBits;
	bool leadingZero;
	size_t psLen;
	bool valid;
};

// The minimum valid block is 0x02 || PS(8) || 0x00, ten bytes after the
// leading 0x00 is accounted for. Shorter blocks are rejected; the byte-aligned
// (72, 80) and non-byte-aligned (79, 87) lengths exercise both conversions.
const PKCSMinBlockCase pkcsMinBlockCases[] = {
	{72, false, 7, false},
	{79, true,  7, false},
	{80, false, 8, true},
	{87, true,  8, true}
};

bool TestPKCSMinBlockSize()
{
	PKCS_EncryptionPaddingScheme padding;

	bool pass = true;
	for (size_t k = 0; k < COUNTOF(pkcsMinBlockCases); k++)
	{
		const PKCSMinBlockCase& testCase = pkcsMinBlockCases[k];
		const size_t bufLen = BitsToBytes(testCase.blockBits);

		SecByteBlock block(bufLen);
		std::memset(block, 0x41, bufLen);   // nonzero padding filler

		size_t pos = 0;
		if (testCase.leadingZero)
			block[pos++] = 0x00;
		block[pos++] = 0x02;                // block type
		pos += testCase.psLen;              // PS filler already nonzero
		block[pos] = 0x00;                  // separator, empty message

		const size_t maxOutputLen = padding.MaxUnpaddedLength(testCase.blockBits);
		SecByteBlock output(maxOutputLen ? maxOutputLen : 1);

		DecodingResult result = padding.Unpad(block, testCase.blockBits, output, g_nullNameValuePairs);

		bool fail = (result.isValidCoding != testCase.valid);
		if (testCase.valid)
			fail = fail || (result.messageLength != 0);
		pass = pass && !fail;
	}

	std::cout << (pass ? "passed    " : "FAILED    ");
	std::cout << "PKCS 1.5 minimum block size (" << COUNTOF(pkcsMinBlockCases) << " cases)\n";
	return pass;
}

bool TestPKCSUndersizedKey()
{
	// 8-bit modulus n = 221 (p = 13, q = 17), e = 5, d = 77, dp = 5, dq = 13,
	// u = 10. Full CRT parameters so the private operation reaches Unpad. Such
	// a key is cryptographically unusable; decryption must reject the block
	// rather than read past the recovered buffer.
	RSA::PrivateKey priv;
	priv.Initialize(Integer("221"), Integer("5"), Integer("77"),
		Integer("13"), Integer("17"), Integer("5"), Integer("13"), Integer("10"));
	RSAES_PKCS1v15_Decryptor dec(priv);

	const size_t ctLen = dec.FixedCiphertextLength();
	const size_t maxPt = dec.MaxPlaintextLength(ctLen);

	SecByteBlock ciphertext(ctLen ? ctLen : 1);
	if (ctLen) ciphertext[0] = 0x07;   // value below the modulus
	SecByteBlock output(maxPt ? maxPt : 1);

	DecodingResult result = dec.Decrypt(GlobalRNG(), ciphertext, ctLen, output);

	// This regression path requires a one-byte ciphertext.
	bool pass = (ctLen == 1) && !result.isValidCoding;

	std::cout << (pass ? "passed    " : "FAILED    ");
	std::cout << "PKCS 1.5 undersized modulus rejected\n";
	return pass;
}

ANONYMOUS_NAMESPACE_END

bool ValidateRSA_Encrypt()
{
	// Must be large enough for RSA-3072 to test SHA3_256
	byte out[256], outPlain[128];
	bool pass = true, fail;

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	{
		FileSource keys(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
		RSA::PrivateKey rsaPriv; rsaPriv.Load(keys);
		RSA::PublicKey rsaPub(rsaPriv);

		const Integer& n = rsaPriv.GetModulus();
		const Integer& e = rsaPriv.GetPublicExponent();
		const Integer& d = rsaPriv.GetPrivateExponent();

		RSA::PrivateKey rsaPriv2;
		rsaPriv2.Initialize(n, e, d);

		fail = (rsaPriv != rsaPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "RSA::PrivateKey initialization\n";

		RSA::PublicKey rsaPub2;
		rsaPub2.Initialize(n, e);

		fail = (rsaPub != rsaPub2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "RSA::PublicKey initialization\n";
	}
	{
		FileSource keys(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
		RSA::PrivateKey rsaPriv; rsaPriv.Load(keys);

		ByteQueue q;
		rsaPriv.DEREncodePrivateKey(q);

		RSA::PrivateKey rsaPriv2;
		rsaPriv2.BERDecodePrivateKey(q, true, (size_t)q.MaxRetrievable());

		fail = (rsaPriv != rsaPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "RSA::PrivateKey encoding and decoding\n";
	}
#endif

	{
		FileSource keys(DataDir("TestData/rsa1024.dat").c_str(), true, new HexDecoder);
		RSAES_PKCS1v15_Decryptor rsaPriv(keys);
		RSAES_PKCS1v15_Encryptor rsaPub(rsaPriv);

		fail = !CryptoSystemValidate(rsaPriv, rsaPub);
		pass = pass && !fail;
	}
	{
		fail = !TestPKCSUnpadBounds();
		pass = pass && !fail;

		fail = !TestPKCSChosenCiphertextBounds();
		pass = pass && !fail;

		fail = !TestPKCSMinBlockSize();
		pass = pass && !fail;

		fail = !TestPKCSUndersizedKey();
		pass = pass && !fail;
	}
	{
		RSAES_OAEP_SHA_Decryptor rsaPriv(GlobalRNG(), 512);
		RSAES_OAEP_SHA_Encryptor rsaPub(rsaPriv);

		fail = !CryptoSystemValidate(rsaPriv, rsaPub);
		pass = pass && !fail;
	}
	{
		RSAES_OAEP_SHA256_Decryptor rsaPriv(GlobalRNG(), 1024);
		RSAES_OAEP_SHA256_Encryptor rsaPub(rsaPriv);

		fail = !CryptoSystemValidate(rsaPriv, rsaPub);
		pass = pass && !fail;
	}
	{
		const byte plain[] =
			"\x54\x85\x9b\x34\x2c\x49\xea\x2a";
		const byte encrypted[] =
			"\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
			"\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
			"\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
			"\x62\x51";
		const byte oaepSeed[] =
			"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2"
			"\xf0\x6c\xb5\x8f";
		ByteQueue bq;
		bq.Put(oaepSeed, 20);
		FixedRNG rng(bq);

		FileSource privFile(DataDir("TestData/rsa400pv.dat").c_str(), true, new HexDecoder);
		FileSource pubFile(DataDir("TestData/rsa400pb.dat").c_str(), true, new HexDecoder);
		RSAES_OAEP_SHA_Decryptor rsaPriv;
		rsaPriv.AccessKey().BERDecodePrivateKey(privFile, false, 0);
		RSAES_OAEP_SHA_Encryptor rsaPub(pubFile);

		std::memset(out, 0, 50);
		std::memset(outPlain, 0, 8);
		rsaPub.Encrypt(rng, plain, 8, out);
		DecodingResult result = rsaPriv.FixedLengthDecrypt(GlobalRNG(), encrypted, outPlain);
		fail = !result.isValidCoding || (result.messageLength!=8) || std::memcmp(out, encrypted, 50) || std::memcmp(plain, outPlain, 8);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "PKCS 2.0 encryption and decryption\n";
	}
	{
		// A block shorter than a seed, a digest and a separator cannot carry an
		// OAEP encoding. Both directions must reject it rather than compute a
		// length that underflows and walk off the block.
		OAEP<SHA512> oaep;
		const size_t hLen = SHA512::DIGESTSIZE;
		const size_t blockLen = 2*hLen - 1;
		SecByteBlock block(blockLen), recovered(blockLen), message(1);
		std::memset(block, 0xa5, block.size());
		std::memset(recovered, 0, recovered.size());
		std::memset(message, 0x2a, message.size());

		DecodingResult result = oaep.Unpad(block, 8*blockLen, recovered, g_nullNameValuePairs);
		fail = result.isValidCoding || (result.messageLength != 0);

		fail = (FindIfNot(recovered.begin(), recovered.end(), byte(0)) != recovered.end()) || fail;

		try
		{
			oaep.Pad(GlobalRNG(), message, message.size(), block, 8*blockLen, g_nullNameValuePairs);
			fail = true;
		}
		catch (const InvalidArgument&) {}

		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "OAEP undersized block rejection\n";
	}
	{
		// The smallest legal block is a seed, a digest and the separator, and
		// carries an empty message. It must round trip, while one byte less is
		// rejected in both directions.
		OAEP<SHA512> oaep;
		const size_t hLen = SHA512::DIGESTSIZE;
		const size_t minLen = 2*hLen + 1;
		SecByteBlock block(minLen), recovered(minLen), message(1);
		std::memset(block, 0, block.size());
		std::memset(recovered, 0xa5, recovered.size());
		std::memset(message, 0x2a, message.size());

		oaep.Pad(GlobalRNG(), message, 0, block, 8*minLen, g_nullNameValuePairs);
		DecodingResult result = oaep.Unpad(block, 8*minLen, recovered, g_nullNameValuePairs);
		fail = !result.isValidCoding || (result.messageLength != 0);

		SecByteBlock shortBlock(minLen-1);
		std::memset(shortBlock, 0, shortBlock.size());
		std::memset(recovered, 0xa5, recovered.size());

		result = oaep.Unpad(shortBlock, 8*(minLen-1), recovered, g_nullNameValuePairs);
		fail = result.isValidCoding || (result.messageLength != 0) || fail;
		fail = (FindIfNot(recovered.begin(), recovered.end(), byte(0xa5)) != recovered.end()) || fail;

		try
		{
			oaep.Pad(GlobalRNG(), message, 0, shortBlock, 8*(minLen-1), g_nullNameValuePairs);
			fail = true;
		}
		catch (const InvalidArgument&) {}

		// A message one byte too long for the smallest legal block exercises
		// the input-length half of the Pad guard rather than the block size.
		try
		{
			oaep.Pad(GlobalRNG(), message, 1, block, 8*minLen, g_nullNameValuePairs);
			fail = true;
		}
		catch (const InvalidArgument&) {}

		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "OAEP minimum block size\n";
	}
	{
		// The same defect through the public API: a modulus too small for
		// SHA-512 OAEP reaches Unpad on every decrypt, valid ciphertext or not.
		RSAES<OAEP<SHA512> >::Decryptor rsaPriv(GlobalRNG(), 1024);
		SecByteBlock ct(rsaPriv.FixedCiphertextLength());
		SecByteBlock pt(rsaPriv.MaxPlaintextLength(ct.size()) + 1);

		// A small integer, so the value stays below the modulus and the private
		// key operation does not fail its own consistency check.
		std::memset(ct, 0, ct.size());
		ct[ct.size()-1] = 2;
		std::memset(pt, 0, pt.size());

		DecodingResult result = rsaPriv.Decrypt(GlobalRNG(), ct, ct.size(), pt);
		fail = result.isValidCoding || (result.messageLength != 0);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "OAEP decryption with an undersized modulus\n";
	}

	return pass;
}

bool ValidateLUC_Encrypt()
{
	bool pass = true, fail;

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	{
		FileSource keys(DataDir("TestData/luc1024.dat").c_str(), true, new HexDecoder);
		LUC::PrivateKey lucPriv; lucPriv.BERDecode(keys);
		LUC::PublicKey lucPub(lucPriv);

		const Integer& n = lucPriv.GetModulus();
		const Integer& e = lucPriv.GetPublicExponent();
		const Integer& p = lucPriv.GetPrime1();
		const Integer& q = lucPriv.GetPrime2();
		const Integer& u = lucPriv.GetMultiplicativeInverseOfPrime2ModPrime1();

		LUC::PrivateKey lucPriv2;
		lucPriv2.Initialize(n, e, p, q, u);

		fail = (lucPriv != lucPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "LUC::PrivateKey initialization\n";

		LUC::PublicKey lucPub2;
		lucPub2.Initialize(n, e);

		fail = (lucPub != lucPub2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "LUC::PublicKey initialization\n";
	}
	{
		FileSource keys(DataDir("TestData/luc1024.dat").c_str(), true, new HexDecoder);
		LUC::PrivateKey lucPriv; lucPriv.BERDecode(keys);

		ByteQueue q;
		lucPriv.DEREncode(q);

		LUC::PrivateKey lucPriv2;
		lucPriv2.BERDecode(q);

		fail = (lucPriv != lucPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "LUC::PrivateKey encoding and decoding\n";
	}
	{
		FileSource keys(DataDir("TestData/luc1024.dat").c_str(), true, new HexDecoder);
		LUC::PrivateKey lucPriv; lucPriv.BERDecode(keys);
		LUC::PublicKey lucPub(lucPriv);

		ByteQueue q;
		lucPub.DEREncode(q);

		LUC::PublicKey lucPub2;
		lucPub2.BERDecode(q);

		fail = (lucPub != lucPub2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "LUC::PublicKey encoding and decoding\n";
	}
#endif

	LUCES_OAEP_SHA_Decryptor priv(GlobalRNG(), 512);
	LUCES_OAEP_SHA_Encryptor pub(priv);
	fail = !CryptoSystemValidate(priv, pub);
	pass = pass && !fail;

	return pass;
}

bool ValidateLUC_DL_Encrypt()
{
	std::cout << "\nLUC-IES validation suite running...\n\n";

	FileSource fc(DataDir("TestData/lucc512.dat").c_str(), true, new HexDecoder);
	LUC_IES<>::Decryptor privC(fc);
	LUC_IES<>::Encryptor pubC(privC);
	return CryptoSystemValidate(privC, pubC);
}

static bool TestRabinBERDecodePrimality()
{
	std::cout << "\nRabin BERDecode primality tests running...\n\n";
	bool pass = true;

	// Non-prime m_p. BERDecode must reject.
	{
		ByteQueue q;
		DERSequenceEncoder seq(q);
			Integer(63).DEREncode(seq);  // m_n
			Integer(2).DEREncode(seq);   // m_r
			Integer(3).DEREncode(seq);   // m_s
			Integer(9).DEREncode(seq);   // m_p, non-prime
			Integer(7).DEREncode(seq);   // m_q, prime
			Integer(1).DEREncode(seq);   // m_u
		seq.MessageEnd();

		bool threw = false;
		try
		{
			InvertibleRabinFunction key;
			key.BERDecode(q);
		}
		catch (const Exception&)
		{
			threw = true;
		}

		std::cout << (threw ? "passed    " : "FAILED    ") << "non-prime m_p rejected\n";
		pass = threw && pass;
	}

	// Non-prime m_q. BERDecode must reject.
	{
		ByteQueue q;
		DERSequenceEncoder seq(q);
			Integer(63).DEREncode(seq);  // m_n
			Integer(2).DEREncode(seq);   // m_r
			Integer(3).DEREncode(seq);   // m_s
			Integer(7).DEREncode(seq);   // m_p, prime
			Integer(9).DEREncode(seq);   // m_q, non-prime
			Integer(1).DEREncode(seq);   // m_u
		seq.MessageEnd();

		bool threw = false;
		try
		{
			InvertibleRabinFunction key;
			key.BERDecode(q);
		}
		catch (const Exception&)
		{
			threw = true;
		}

		std::cout << (threw ? "passed    " : "FAILED    ") << "non-prime m_q rejected\n";
		pass = threw && pass;
	}

	// Valid round-trip: rabi1024.dat -> DEREncode -> BERDecode.
	{
		bool ok = false;
		try
		{
			FileSource keys(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
			InvertibleRabinFunction priv;
			priv.BERDecode(keys);

			ByteQueue q;
			priv.DEREncode(q);

			InvertibleRabinFunction priv2;
			priv2.BERDecode(q);
			ok = true;
		}
		catch (const Exception&) {}

		std::cout << (ok ? "passed    " : "FAILED    ") << "valid Rabin key round-trip\n";
		pass = ok && pass;
	}

	return pass;
}

static bool TestModularSquareRootCap()
{
	std::cout << "\nModularSquareRoot iteration cap tests running...\n\n";
	bool pass = true;

	// p = 9 (non-prime perfect square). Jacobi(n, 9) = (n/3)^2 >= 0 for
	// all n coprime to 9, so the non-residue search runs to the cap.
	{
		bool threw = false;
		try
		{
			ModularSquareRoot(Integer(4), Integer(9));
		}
		catch (const InvalidArgument&)
		{
			threw = true;
		}
		std::cout << (threw ? "passed    " : "FAILED    ") << "p = 9 (non-prime) trips the cap\n";
		pass = threw && pass;
	}

	// Regression with prime p where p%4 != 3, so the (p+1)/4 shortcut does
	// not apply and the non-residue search and Tonelli-Shanks step both run.
	{
		const Integer p(17), a(4);
		bool ok = false;
		try
		{
			Integer x = ModularSquareRoot(a, p);
			ok = (x.Squared() % p == a);
		}
		catch (const Exception&) {}
		std::cout << (ok ? "passed    " : "FAILED    ") << "p = 17, sqrt(4) round-trips\n";
		pass = ok && pass;
	}

	return pass;
}

bool ValidateRabin_Encrypt()
{
	bool pass = true, fail;

	pass = TestRabinBERDecodePrimality() && pass;
	pass = TestModularSquareRootCap() && pass;

#if defined(CRYPTOPP_EXTENDED_VALIDATION)
	{
		FileSource keys(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
		Rabin::PrivateKey rabinPriv; rabinPriv.BERDecode(keys);
		Rabin::PublicKey rabinPub(rabinPriv);

		const Integer& n = rabinPriv.GetModulus();
		const Integer& r = rabinPriv.GetQuadraticResidueModPrime1();
		const Integer& s = rabinPriv.GetQuadraticResidueModPrime2();
		const Integer& p = rabinPriv.GetPrime1();
		const Integer& q = rabinPriv.GetPrime2();
		const Integer& u = rabinPriv.GetMultiplicativeInverseOfPrime2ModPrime1();

		Rabin::PrivateKey rabinPriv2;
		rabinPriv2.Initialize(n, r, s, p, q, u);

		fail = (rabinPriv != rabinPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "Rabin::PrivateKey initialization\n";

		Rabin::PublicKey rabinPub2;
		rabinPub2.Initialize(n, r, s);

		fail = (rabinPub != rabinPub2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "Rabin::PublicKey initialization\n";
	}
	{
		FileSource keys(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
		Rabin::PrivateKey rabinPriv; rabinPriv.BERDecode(keys);

		ByteQueue q;
		rabinPriv.DEREncode(q);

		Rabin::PrivateKey rabinPriv2;
		rabinPriv2.BERDecode(q);

		fail = (rabinPriv != rabinPriv2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "Rabin::PrivateKey encoding and decoding\n";
	}
	{
		FileSource keys(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
		Rabin::PrivateKey rabinPriv; rabinPriv.BERDecode(keys);
		Rabin::PublicKey rabinPub(rabinPriv);

		ByteQueue q;
		rabinPub.DEREncode(q);

		Rabin::PublicKey rabinPub2;
		rabinPub2.BERDecode(q);

		fail = (rabinPub != rabinPub2);
		pass = pass && !fail;

		std::cout << (fail ? "FAILED    " : "passed    ");
		std::cout << "Rabin::PublicKey encoding and decoding\n";
	}
#endif

	FileSource f(DataDir("TestData/rabi1024.dat").c_str(), true, new HexDecoder);
	RabinES<OAEP<SHA1> >::Decryptor priv(f);
	RabinES<OAEP<SHA1> >::Encryptor pub(priv);
	fail = !CryptoSystemValidate(priv, pub);
	pass = pass && !fail;

	return pass;
}

bool ValidateECP_Encrypt()
{
	ECIES<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp192r1());
	ECIES<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);

	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

// https://github.com/weidai11/cryptopp/issues/856
// Not to be confused with NullHash in trunhash.h.
class NULL_Hash : public CryptoPP::IteratedHashWithStaticTransform
    <CryptoPP::word32, CryptoPP::BigEndian, 32, 0, NULL_Hash, 0>
{
public:
    static void InitState(HashWordType *state) {
        CRYPTOPP_UNUSED(state);
    }
    static void Transform(CryptoPP::word32 *digest, const CryptoPP::word32 *data) {
        CRYPTOPP_UNUSED(digest); CRYPTOPP_UNUSED(data);
    }
    static const char *StaticAlgorithmName() {
        return "NULL_Hash";
    }
};

// https://github.com/weidai11/cryptopp/issues/856
template <class EC, class HASH = SHA1, class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true, bool LABEL_OCTETS = false>
struct ECIES_NULLDigest
	: public DL_ES<
		DL_Keys_EC<EC>,
		DL_KeyAgreementAlgorithm_DH<typename EC::Point, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<typename EC::Point, DHAES_MODE, P1363_KDF2<HASH> >,
		DL_EncryptionAlgorithm_Xor<HMAC<NULL_Hash>, DHAES_MODE, LABEL_OCTETS>,
		ECIES<EC> >
{
	// TODO: fix this after name is standardized
	CRYPTOPP_STATIC_CONSTEXPR const char* CRYPTOPP_API StaticAlgorithmName() {return "ECIES-NULLDigest";}
};

bool ValidateECP_NULLDigest_Encrypt()
{
	ECIES_NULLDigest<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp256k1());
	ECIES_NULLDigest<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);

	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

// Ensure interop with Crypto++ 5.6.4 and earlier
bool ValidateECP_Legacy_Encrypt()
{
	std::cout << "\nLegacy ECIES ECP validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/ecies_p160.dat").c_str(), true, new HexDecoder);
		ECIES<ECP,SHA1,NoCofactorMultiplication,false,true>::Decryptor privC(fc);
		ECIES<ECP,SHA1,NoCofactorMultiplication,false,true>::Encryptor pubC(privC);

		pass = CryptoSystemValidate(privC, pubC) && pass;

		// Test data generated by Crypto++ 5.6.2.
		// Also see https://github.com/weidai11/cryptopp/pull/857.
		const std::string plain = "Yoda said, Do or do not. There is no try.";
		const std::string cipher =
			"\x04\xF6\xC1\xB1\xFA\xAC\x8A\xD5\xD3\x96\xE7\x13\xAE\xBD\x0C\xCE"
			"\x15\xCF\x44\x54\x08\x63\xCC\xBF\x89\x4D\xD0\xB8\x38\xA1\x3A\xB2"
			"\x90\x75\x86\x82\x7F\x9D\x95\x26\xA5\x74\x13\x3A\x74\x63\x11\x71"
			"\x70\x4C\x01\xA4\x08\x04\x95\x69\x6A\x91\xF0\xC0\xA4\xBD\x1E\xAA"
			"\x59\x57\xB8\xA9\xD2\xF7\x7C\x98\xE3\xC5\xE3\xF4\x4F\xA7\x6E\x73"
			"\x83\xF3\x1E\x05\x73\xA4\xEE\x63\x55\xFD\x6D\x31\xBB\x9E\x36\x4C"
			"\x79\xD0\x76\xC0\x0D\xE9";

		std::string recover;
		recover.resize(privC.MaxPlaintextLength(cipher.size()));

		DecodingResult result = privC.Decrypt(GlobalRNG(), C2B(&cipher[0]), cipher.size(), C2B(&recover[0]));
		if (result.isValidCoding)
			recover.resize(result.messageLength);
		else
			recover.resize(0);

		pass = (plain == recover) && pass;
		std::cout << (pass ? "passed    " : "FAILED    ");
		std::cout << "decryption known answer\n";
	}
	return pass;
}

// Ensure interop with Crypto++ 5.6.4 and earlier
bool ValidateEC2N_Legacy_Encrypt()
{
	std::cout << "\nLegacy ECIES EC2N validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/ecies_t163.dat").c_str(), true, new HexDecoder);
		ECIES<EC2N,SHA1,NoCofactorMultiplication,false,true>::Decryptor privC(fc);
		ECIES<EC2N,SHA1,NoCofactorMultiplication,false,true>::Encryptor pubC(privC);

		pass = CryptoSystemValidate(privC, pubC) && pass;

		// Test data generated by Crypto++ 5.6.2.
		// Also see https://github.com/weidai11/cryptopp/pull/857.
		const std::string plain = "Yoda said, Do or do not. There is no try.";
		const std::string cipher =
			"\x04\x01\x3F\x64\x94\x6A\xBE\x2B\x7E\x48\x67\x63\xA2\xD4\x01\xEF"
			"\x2B\x13\x1C\x9A\x1B\x7C\x07\x4B\x89\x78\x6C\x65\x51\x1C\x1A\x4E"
			"\x20\x7F\xB5\xBF\x12\x3B\x6E\x0A\x87\xFD\xB7\x94\xEF\x4B\xED\x40"
			"\xD4\x7A\xCF\xB6\xFC\x9B\x6D\xB0\xB8\x43\x99\x7E\x37\xC1\xF0\xC0"
			"\x95\xD4\x80\xE1\x8B\x84\xAE\x64\x9F\xA5\xBA\x32\x95\x8A\xD1\xBE"
			"\x7F\xDE\x7E\xA9\xE6\x59\xBF\x89\xA6\xE9\x9F\x5B\x64\xB4\xDD\x0E"
			"\x76\xB6\x82\xF6\xA9\xAD\xB5\xC4";

		std::string recover;
		recover.resize(privC.MaxPlaintextLength(cipher.size()));

		DecodingResult result = privC.Decrypt(GlobalRNG(), C2B(&cipher[0]), cipher.size(), C2B(&recover[0]));
		if (result.isValidCoding)
			recover.resize(result.messageLength);
		else
			recover.resize(0);

		pass = (plain == recover) && pass;
		std::cout << (pass ? "passed    " : "FAILED    ");
		std::cout << "decryption known answer\n";
	}
	return pass;
}

bool ValidateEC2N_Encrypt()
{
	// DEREncode() changed to Save() at Issue 569.
	ECIES<EC2N>::Decryptor cpriv(GlobalRNG(), ASN1::sect193r1());
	ECIES<EC2N>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.AccessMaterial().Save(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.AccessMaterial().Save(bq);
	bool pass = CryptoSystemValidate(cpriv, cpub);

	std::cout << "Turning on point compression..." << std::endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;

	return pass;
}

bool ValidateElGamal()
{
	std::cout << "\nElGamal validation suite running...\n\n";
	bool pass = true;
	{
		// Data from https://github.com/weidai11/cryptopp/issues/876.
		const std::string encodedPublicKey =
			"MHYwTwYGKw4HAgEBMEUCIQDebUvQDd9UPMmD27BJ ovZSIgWfexL0SWkfJQPMLsJvMwIgDy/kEthwO6Q+"
			"L8XHnzumnEKs+txH8QkQD+M/8u82ql0DIwACIAY6 rfW+BTcRZ9QAJovgoB8DgNLJ8ocqOeF4nEBB0DHH";
		StringSource decodedPublicKey(encodedPublicKey, true, new Base64Decoder);

		ElGamal::PublicKey publicKey;
		publicKey.Load(decodedPublicKey);
		pass = publicKey.Validate(GlobalRNG(), 3) && pass;
	}
	{
		// Data from https://github.com/weidai11/cryptopp/issues/876.
		const std::string encodedPrivateKey =
			"MHkCAQAwTwYGKw4HAgEBMEUCIQDebUvQDd9UPMmD 27BJovZSIgWfexL0SWkfJQPMLsJvMwIgDy/kEthw"
			"O6Q+L8XHnzumnEKs+txH8QkQD+M/8u82ql0EIwIh AJb0S4TZLvApTVjXZyocPJ5tUgWgRqScXm5vNqu2"
			"YqdM";
		StringSource decodedPrivateKey(encodedPrivateKey, true, new Base64Decoder);

		ElGamal::PrivateKey privateKey;
		privateKey.Load(decodedPrivateKey);
		pass = privateKey.Validate(GlobalRNG(), 3) && pass;
	}
	{
		FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
		ElGamalDecryptor privC(fc);
		ElGamalEncryptor pubC(privC);
		privC.AccessKey().Precompute();
		ByteQueue queue;
		privC.AccessKey().SavePrecomputation(queue);
		privC.AccessKey().LoadPrecomputation(queue);

		pass = CryptoSystemValidate(privC, pubC) && pass;

		// Messages past FixedMaxPlaintextLength() must be rejected by
		// Encrypt(), the encryption filter and SymmetricEncrypt().
		const size_t maxLen = pubC.FixedMaxPlaintextLength();
		const size_t modulusLen = privC.GetKey().GetGroupParameters().GetModulus().ByteCount();
		const size_t lengths[] = {maxLen+1, modulusLen-1, 1000};
		bool ok = (maxLen == modulusLen-3);

		for (size_t i = 0; i < COUNTOF(lengths); ++i)
		{
			const std::string message(lengths[i], 'A');
			const byte *ptr = reinterpret_cast<const byte *>(message.data());
			SecByteBlock ciphertext(pubC.FixedCiphertextLength());
			ok = (pubC.CiphertextLength(lengths[i]) == 0) && ok;

			bool threw = false;
			try { pubC.Encrypt(GlobalRNG(), ptr, message.size(), ciphertext); }
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;

			threw = false;
			try
			{
				std::string sink;
				StringSource(message, true, new PK_EncryptorFilter(GlobalRNG(), pubC, new StringSink(sink)));
			}
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;

			threw = false;
			try
			{
				SecByteBlock key(modulusLen);
				pubC.SymmetricEncrypt(GlobalRNG(), key, ptr, message.size(), ciphertext, g_nullNameValuePairs);
			}
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;
		}

		// A message of exactly the maximum length still round trips.
		{
			const std::string message(maxLen, 'A');
			std::string ciphertext, recovered;
			StringSource(message, true, new PK_EncryptorFilter(GlobalRNG(), pubC, new StringSink(ciphertext)));
			StringSource(ciphertext, true, new PK_DecryptorFilter(GlobalRNG(), privC, new StringSink(recovered)));
			ok = (recovered == message) && ok;
		}

		// A modulus of 258 bytes or more caps the maximum length at 255.
		// This is the 3072-bit MODP group from RFC 3526.
		{
			const Integer p("0x"
				"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
				"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
				"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
				"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
				"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
				"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
				"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
				"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
				"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
				"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
				"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
				"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
			ElGamalDecryptor priv;
			priv.AccessKey().Initialize(p, Integer(2), Integer(GlobalRNG(), Integer::One(), (p-1)/2-1));
			ElGamalEncryptor pub(priv);
			ok = (pub.FixedMaxPlaintextLength() == 255) && ok;

			const std::string message(255, 'A');
			std::string ciphertext, recovered;
			StringSource(message, true, new PK_EncryptorFilter(GlobalRNG(), pub, new StringSink(ciphertext)));
			StringSource(ciphertext, true, new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(recovered)));
			ok = (recovered == message) && ok;

			bool threw = false;
			try
			{
				std::string sink;
				StringSource(message + "A", true, new PK_EncryptorFilter(GlobalRNG(), pub, new StringSink(sink)));
			}
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;
		}

		// A modulus shorter than 3 bytes cannot encrypt anything, not even
		// an empty message.
		const word32 primes[] = {23, 467};
		for (size_t i = 0; i < COUNTOF(primes); ++i)
		{
			ElGamalDecryptor priv;
			priv.AccessKey().Initialize(Integer(primes[i]), Integer(4), Integer(7));
			ElGamalEncryptor pub(priv);
			ok = (pub.CiphertextLength(0) == 0 && pub.FixedMaxPlaintextLength() == 0) && ok;

			byte ciphertext[8];
			bool threw = false;
			try { pub.Encrypt(GlobalRNG(), NULLPTR, 0, ciphertext); }
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;

			threw = false;
			try { pub.SymmetricEncrypt(GlobalRNG(), ciphertext, NULLPTR, 0, ciphertext, g_nullNameValuePairs); }
			catch (const InvalidArgument&) { threw = true; }
			ok = threw && ok;
		}

		std::cout << (ok ? "passed    " : "FAILED    ") << "messages past the maximum length are rejected\n";
		pass = ok && pass;
	}
	return pass;
}

bool ValidateDLIES()
{
	std::cout << "\nDLIES validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc(DataDir("TestData/dlie1024.dat").c_str(), true, new HexDecoder);
		DLIES<>::Decryptor privC(fc);
		DLIES<>::Encryptor pubC(privC);
		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	{
		std::cout << "Generating new encryption key..." << std::endl;
		DLIES<>::GroupParameters gp;
		gp.GenerateRandomWithKeySize(GlobalRNG(), 128);
		DLIES<>::Decryptor decryptor;
		decryptor.AccessKey().GenerateRandom(GlobalRNG(), gp);
		DLIES<>::Encryptor encryptor(decryptor);

		pass = CryptoSystemValidate(decryptor, encryptor) && pass;
	}
	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
