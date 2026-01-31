// validat_cve_2024_28285.cpp - CVE-2024-28285 security validation tests
// Tests for no-write-on-failure guarantees in hybrid DL decryption (ElGamal, ECIES)
//
// Written by Colin Brown

#include <cryptopp/pch.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/misc.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/validate.h>

#include <algorithm>
#include <iostream>
#include <cstring>

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

// Sentinel value for no-write-on-failure tests
static const byte SENTINEL_VALUE = 0xAA;

/// \brief Check if entire buffer contains only the specified value
static bool BufferIsAll(const SecByteBlock& b, byte v)
{
	for (size_t i = 0; i < b.size(); ++i)
		if (b[i] != v) return false;
	return true;
}

/// \brief Validate CVE-2024-28285 mitigations for ElGamal
/// \details Tests no-write-on-failure guarantee and normal operation
bool ValidateCVE_2024_28285_ElGamal()
{
	std::cout << "\nCVE-2024-28285 ElGamal validation suite running...\n\n";
	bool pass = true;

	// Load ElGamal key pair from test data (same as ValidateElGamal)
	FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
	ElGamalDecryptor decryptor(fc);
	ElGamalEncryptor encryptor(decryptor);

	// Test 1: Normal encryption/decryption still works
	{
		const byte message[] = "test message";
		const int messageLen = 12;
		SecByteBlock ciphertext(decryptor.CiphertextLength(messageLen));
		SecByteBlock plaintext(decryptor.MaxPlaintextLength(ciphertext.size()));

		encryptor.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
		bool testPass = decryptor.Decrypt(GlobalRNG(), ciphertext, ciphertext.size(), plaintext) == DecodingResult(messageLen);
		testPass = testPass && !std::memcmp(message, plaintext, messageLen);

		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ElGamal normal encryption/decryption\n";
	}

	// Test 2: No-write-on-failure with invalid ciphertext length
	{
		const size_t bufferSize = 512;
		SecByteBlock outputBuffer(bufferSize);
		std::memset(outputBuffer, SENTINEL_VALUE, bufferSize);

		// Create invalid ciphertext (too short to contain valid element)
		byte invalidCiphertext[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};

		DecodingResult result = decryptor.Decrypt(GlobalRNG(), invalidCiphertext, sizeof(invalidCiphertext), outputBuffer);

		bool testPass = !result.isValidCoding && BufferIsAll(outputBuffer, SENTINEL_VALUE);
		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ElGamal no-write-on-failure (invalid length)\n";
	}

	// Test 3: No-write-on-failure with invalid ephemeral public key
	{
		const byte message[] = "test message";
		const int messageLen = 12;
		SecByteBlock ciphertext(decryptor.CiphertextLength(messageLen));

		encryptor.Encrypt(GlobalRNG(), message, messageLen, ciphertext);

		// Overwrite the ephemeral public key with 0xFF bytes to create invalid element
		const size_t modulusLen = decryptor.GetGroupParameters().GetModulus().ByteCount();
		const size_t overwriteLen = std::min(modulusLen, ciphertext.size());
		std::memset(ciphertext.data(), 0xFF, overwriteLen);

		const size_t outLen = decryptor.MaxPlaintextLength(ciphertext.size());
		SecByteBlock outputBuffer(outLen);
		std::memset(outputBuffer, SENTINEL_VALUE, outLen);

		DecodingResult result = decryptor.Decrypt(GlobalRNG(), ciphertext, ciphertext.size(), outputBuffer);

		bool testPass = !result.isValidCoding && BufferIsAll(outputBuffer, SENTINEL_VALUE);
		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ElGamal no-write-on-failure (invalid ephemeral key)\n";
	}

	return pass;
}

/// \brief Validate CVE-2024-28285 mitigations for ECIES
/// \details Tests no-write-on-failure guarantee and normal operation
bool ValidateCVE_2024_28285_ECIES()
{
	std::cout << "\nCVE-2024-28285 ECIES validation suite running...\n\n";
	bool pass = true;

	// Generate ECIES key pair
	ECIES<ECP>::Decryptor decryptor(GlobalRNG(), ASN1::secp256r1());
	ECIES<ECP>::Encryptor encryptor(decryptor);

	// Test 1: Normal encryption/decryption still works
	{
		const byte message[] = "test message";
		const int messageLen = 12;
		SecByteBlock ciphertext(encryptor.CiphertextLength(messageLen));
		SecByteBlock plaintext(decryptor.MaxPlaintextLength(ciphertext.size()));

		encryptor.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
		bool testPass = decryptor.Decrypt(GlobalRNG(), ciphertext, ciphertext.size(), plaintext) == DecodingResult(messageLen);
		testPass = testPass && !std::memcmp(message, plaintext, messageLen);

		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ECIES normal encryption/decryption\n";
	}

	// Test 2: No-write-on-failure with invalid ciphertext length
	{
		const size_t bufferSize = 512;
		SecByteBlock outputBuffer(bufferSize);
		std::memset(outputBuffer, SENTINEL_VALUE, bufferSize);

		byte invalidCiphertext[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};

		DecodingResult result = decryptor.Decrypt(GlobalRNG(), invalidCiphertext, sizeof(invalidCiphertext), outputBuffer);

		bool testPass = !result.isValidCoding && BufferIsAll(outputBuffer, SENTINEL_VALUE);
		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ECIES no-write-on-failure (invalid length)\n";
	}

	// Test 3: No-write-on-failure with corrupted MAC
	{
		const byte message[] = "test message";
		const int messageLen = 12;
		SecByteBlock ciphertext(encryptor.CiphertextLength(messageLen));

		encryptor.Encrypt(GlobalRNG(), message, messageLen, ciphertext);

		// Corrupt the MAC (last bytes of ciphertext)
		if (ciphertext.size() > 0)
			ciphertext[ciphertext.size() - 1] ^= 0xFF;

		const size_t outLen = decryptor.MaxPlaintextLength(ciphertext.size());
		SecByteBlock outputBuffer(outLen);
		std::memset(outputBuffer, SENTINEL_VALUE, outLen);

		DecodingResult result = decryptor.Decrypt(GlobalRNG(), ciphertext, ciphertext.size(), outputBuffer);

		bool testPass = !result.isValidCoding && BufferIsAll(outputBuffer, SENTINEL_VALUE);
		pass = pass && testPass;
		std::cout << (testPass ? "passed    " : "FAILED    ");
		std::cout << "ECIES no-write-on-failure (corrupted MAC)\n";
	}

	return pass;
}

/// \brief Diagnostic test for blinding math - investigate intermittent comparison failures
/// \details Tests the mathematical foundation: ephemeralPub^(x+k*order) should equal ephemeralPub^x
bool DiagnoseBlindingMath_ElGamal()
{
	std::cout << "\n=== ElGamal Blinding Math Diagnostic ===\n";
	bool allPass = true;
	const int NUM_ITERATIONS = 100;

	FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
	ElGamalDecryptor decryptor(fc);
	ElGamalEncryptor encryptor(decryptor);

	const DL_GroupParameters_GFP &params = decryptor.GetGroupParameters();
	const Integer &p = params.GetModulus();
	const Integer &order = params.GetSubgroupOrder();
	// Access private exponent via AccessKey().GetPrivateExponent()
	const Integer &x = decryptor.AccessKey().GetPrivateExponent();

	std::cout << "Modulus bits: " << p.BitCount() << "\n";
	std::cout << "Order bits: " << order.BitCount() << "\n";
	std::cout << "Private exp bits: " << x.BitCount() << "\n\n";

	int passCount = 0;
	int failCount = 0;

	for (int iter = 0; iter < NUM_ITERATIONS; iter++)
	{
		// Generate a valid ephemeral public key by encrypting something
		const byte message[] = "test";
		SecByteBlock ciphertext(decryptor.CiphertextLength(4));
		encryptor.Encrypt(GlobalRNG(), message, 4, ciphertext);

		// Extract ephemeral public key (first element in ciphertext)
		Integer ephemeralPub(ciphertext, params.GetEncodedElementSize(true));

		// Verify ephemeralPub is in subgroup: ephemeralPub^order should equal 1 mod p
		Integer orderCheck = a_exp_b_mod_c(ephemeralPub, order, p);
		bool inSubgroup = (orderCheck == Integer::One());

		// Compute z = ephemeralPub^x mod p
		Integer z = a_exp_b_mod_c(ephemeralPub, x, p);

		// Generate random blinding factor k
		Integer k(GlobalRNG(), Integer::One(), order);

		// Compute blinded exponent: x + k*order
		Integer blindExp = x + k * order;

		// Compute z2 = ephemeralPub^(x+k*order) mod p
		Integer z2 = a_exp_b_mod_c(ephemeralPub, blindExp, p);

		// Compare using various methods
		bool directCompare = (z == z2);
		bool compareMethod = (z.Compare(z2) == 0);

		// Byte-level comparison
		SecByteBlock zBytes(z.ByteCount()), z2Bytes(z2.ByteCount());
		z.Encode(zBytes, zBytes.size());
		z2.Encode(z2Bytes, z2Bytes.size());
		bool byteCompare = (zBytes.size() == z2Bytes.size()) &&
		                   (std::memcmp(zBytes, z2Bytes, zBytes.size()) == 0);

		bool testPass = directCompare && compareMethod && byteCompare && inSubgroup;

		if (testPass)
		{
			passCount++;
		}
		else
		{
			failCount++;
			if (failCount <= 5)  // Only print first 5 failures
			{
				std::cout << "FAIL iter " << iter << ":\n";
				std::cout << "  inSubgroup: " << (inSubgroup ? "YES" : "NO") << "\n";
				std::cout << "  z == z2: " << (directCompare ? "YES" : "NO") << "\n";
				std::cout << "  Compare: " << (compareMethod ? "YES" : "NO") << "\n";
				std::cout << "  Bytes: " << (byteCompare ? "YES" : "NO") << "\n";
				std::cout << "  z.WordCount: " << z.WordCount() << ", z2.WordCount: " << z2.WordCount() << "\n";
				std::cout << "  z.ByteCount: " << z.ByteCount() << ", z2.ByteCount: " << z2.ByteCount() << "\n";
				std::cout << "  k bits: " << k.BitCount() << "\n";
				std::cout << "  blindExp bits: " << blindExp.BitCount() << "\n";
			}
		}
	}

	std::cout << "\nResults: " << passCount << "/" << NUM_ITERATIONS << " passed";
	if (failCount > 0)
		std::cout << " (" << failCount << " failures)";
	std::cout << "\n";

	allPass = (failCount == 0);
	return allPass;
}

/// \brief Diagnostic test for blinding math using ExponentiateElement (group operations)
bool DiagnoseBlindingMath_GroupOps()
{
	std::cout << "\n=== ElGamal Blinding via Group Operations Diagnostic ===\n";
	bool allPass = true;
	const int NUM_ITERATIONS = 100;

	FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
	ElGamalDecryptor decryptor(fc);
	ElGamalEncryptor encryptor(decryptor);

	const DL_GroupParameters_GFP &params = decryptor.GetGroupParameters();
	const Integer &order = params.GetSubgroupOrder();
	const Integer &x = decryptor.AccessKey().GetPrivateExponent();

	int passCount = 0;
	int failCount = 0;

	for (int iter = 0; iter < NUM_ITERATIONS; iter++)
	{
		// Generate a valid ephemeral public key
		const byte message[] = "test";
		SecByteBlock ciphertext(decryptor.CiphertextLength(4));
		encryptor.Encrypt(GlobalRNG(), message, 4, ciphertext);

		// Decode ephemeral public key using group's DecodeElement
		Integer ephemeralPub = params.DecodeElement(ciphertext, true);

		// Compute z using ExponentiateElement
		Integer z = params.ExponentiateElement(ephemeralPub, x);

		// Generate random blinding factor k
		Integer k(GlobalRNG(), Integer::One(), order);
		Integer blindExp = x + k * order;

		// Compute z2 using ExponentiateElement
		Integer z2 = params.ExponentiateElement(ephemeralPub, blindExp);

		bool testPass = (z == z2);

		if (testPass)
		{
			passCount++;
		}
		else
		{
			failCount++;
			if (failCount <= 5)
			{
				std::cout << "FAIL iter " << iter << ": z != z2 via ExponentiateElement\n";
				std::cout << "  z.WordCount: " << z.WordCount() << ", z2.WordCount: " << z2.WordCount() << "\n";
			}
		}
	}

	std::cout << "\nGroup ops results: " << passCount << "/" << NUM_ITERATIONS << " passed";
	if (failCount > 0)
		std::cout << " (" << failCount << " failures)";
	std::cout << "\n";

	allPass = (failCount == 0);
	return allPass;
}

/// \brief Stress test blinding with many iterations and edge cases
bool DiagnoseBlindingMath_StressTest()
{
	std::cout << "\n=== Blinding Math Stress Test (1000 iterations) ===\n";
	const int NUM_ITERATIONS = 1000;

	FileSource fc(DataDir("TestData/elgc1024.dat").c_str(), true, new HexDecoder);
	ElGamalDecryptor decryptor(fc);
	ElGamalEncryptor encryptor(decryptor);

	const DL_GroupParameters_GFP &params = decryptor.GetGroupParameters();
	const Integer &order = params.GetSubgroupOrder();
	const Integer &x = decryptor.AccessKey().GetPrivateExponent();

	int passCount = 0;
	int failCount = 0;

	for (int iter = 0; iter < NUM_ITERATIONS; iter++)
	{
		// Generate a valid ephemeral public key
		const byte message[] = "test";
		SecByteBlock ciphertext(decryptor.CiphertextLength(4));
		encryptor.Encrypt(GlobalRNG(), message, 4, ciphertext);

		// Decode ephemeral public key
		Integer ephemeralPub = params.DecodeElement(ciphertext, true);

		// Compute z using ExponentiateElement
		Integer z = params.ExponentiateElement(ephemeralPub, x);

		// Generate random blinding factor k
		Integer k(GlobalRNG(), Integer::One(), order);
		Integer blindExp = x + k * order;

		// Compute z2 using ExponentiateElement with blinded exponent
		Integer z2 = params.ExponentiateElement(ephemeralPub, blindExp);

		bool testPass = (z == z2);

		if (testPass)
		{
			passCount++;
		}
		else
		{
			failCount++;
			if (failCount <= 5)
			{
				std::cout << "FAIL iter " << iter << ":\n";
				std::cout << "  k.BitCount: " << k.BitCount() << "\n";
				std::cout << "  blindExp.BitCount: " << blindExp.BitCount() << "\n";
				std::cout << "  z.ByteCount: " << z.ByteCount() << ", z2.ByteCount: " << z2.ByteCount() << "\n";
			}
		}
	}

	std::cout << "Stress test results: " << passCount << "/" << NUM_ITERATIONS << " passed";
	if (failCount > 0)
		std::cout << " (" << failCount << " failures)";
	std::cout << "\n";

	return (failCount == 0);
}

/// \brief Main CVE-2024-28285 validation entry point
bool ValidateCVE_2024_28285()
{
	std::cout << "\n=== CVE-2024-28285 Security Validation Suite ===\n";
	std::cout << "Testing no-write-on-failure guarantees\n";

	bool pass = true;
	pass = ValidateCVE_2024_28285_ElGamal() && pass;
	pass = ValidateCVE_2024_28285_ECIES() && pass;

	// Run blinding diagnostics
	std::cout << "\n=== Blinding Math Diagnostics ===\n";
	bool blindingPass = true;
	blindingPass = DiagnoseBlindingMath_ElGamal() && blindingPass;
	blindingPass = DiagnoseBlindingMath_GroupOps() && blindingPass;
	blindingPass = DiagnoseBlindingMath_StressTest() && blindingPass;

	if (pass)
		std::cout << "\nAll CVE-2024-28285 security tests passed!\n";
	else
		std::cout << "\nWARNING: Some CVE-2024-28285 security tests FAILED!\n";

	if (blindingPass)
		std::cout << "Blinding math diagnostics: PASSED\n";
	else
		std::cout << "Blinding math diagnostics: FAILED (see details above)\n";

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
