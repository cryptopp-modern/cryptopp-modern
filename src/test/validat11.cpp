// validat11.cpp - written and placed in the public domain by Colin Brown
//                 Post-Quantum Cryptography validation tests (FIPS 203, 204, 205)
//                 Source files split in July 2018 to expedite compiles.

#include <cryptopp/pch.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/validate.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <cryptopp/mlkem.h>
#include <cryptopp/mldsa.h>
#include <cryptopp/slhdsa.h>
#include <cryptopp/xwing.h>
#include <cryptopp/lms.h>

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

// ******************** ML-KEM Validation (FIPS 203) ************************* //

template <class PARAMS>
static bool TestMLKEMKeyGen(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		MLKEMDecapsulator<PARAMS> decapsulator(rng);

		const MLKEMPrivateKey<PARAMS>& privKey = decapsulator.GetPrivateKey();

		if (privKey.GetPrivateKeySize() != PARAMS::SECRET_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " private key size mismatch" << std::endl;
			return false;
		}

		if (privKey.GetPublicKeySize() != PARAMS::PUBLIC_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " public key size mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key generation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " key generation - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestMLKEMEncapsDecaps(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair (recipient)
		MLKEMDecapsulator<PARAMS> decapsulator(rng);

		// Create encapsulator with public key (sender)
		MLKEMEncapsulator<PARAMS> encapsulator(
			decapsulator.GetKey().GetPublicKeyBytePtr(),
			decapsulator.GetKey().GetPublicKeySize());

		// Encapsulate (sender generates shared secret and ciphertext)
		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());

		encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);

		if (ciphertext.size() != PARAMS::CIPHERTEXT_SIZE) {
			std::cout << "FAILED:  " << name << " ciphertext size mismatch" << std::endl;
			return false;
		}

		// Decapsulate (recipient recovers shared secret)
		SecByteBlock sharedSecret2(decapsulator.SharedSecretLength());
		decapsulator.Decapsulate(ciphertext, sharedSecret2);

		// Verify shared secrets match
		if (sharedSecret1.size() != sharedSecret2.size() ||
			std::memcmp(sharedSecret1.begin(), sharedSecret2.begin(), sharedSecret1.size()) != 0) {
			std::cout << "FAILED:  " << name << " shared secrets do not match" << std::endl;
			return false;
		}

		// Test with modified ciphertext (implicit rejection)
		SecByteBlock modifiedCt(ciphertext);
		modifiedCt[0] ^= 0xFF;

		SecByteBlock sharedSecret3(decapsulator.SharedSecretLength());
		decapsulator.Decapsulate(modifiedCt, sharedSecret3);

		// Modified ciphertext should produce different shared secret
		if (std::memcmp(sharedSecret1.begin(), sharedSecret3.begin(), sharedSecret1.size()) == 0) {
			std::cout << "FAILED:  " << name << " implicit rejection failed" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " encapsulation/decapsulation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " encaps/decaps - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestMLKEMSerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate original key pair
		MLKEMDecapsulator<PARAMS> original(rng);

		// Extract key bytes
		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		// Create new instances from bytes
		MLKEMDecapsulator<PARAMS> restored(skBytes.begin(), skBytes.size());
		MLKEMEncapsulator<PARAMS> encapsulator(pkBytes.begin(), pkBytes.size());

		// Verify they work together
		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());
		encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);

		SecByteBlock sharedSecret2(restored.SharedSecretLength());
		restored.Decapsulate(ciphertext, sharedSecret2);

		if (std::memcmp(sharedSecret1.begin(), sharedSecret2.begin(), sharedSecret1.size()) != 0) {
			std::cout << "FAILED:  " << name << " serialization roundtrip failed" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key serialization" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " serialization - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateMLKEM()
{
	std::cout << "\nML-KEM (FIPS 203) validation suite running...\n\n";
	bool pass = true;

	// ML-KEM-512
	pass = TestMLKEMKeyGen<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMSerialization<MLKEM_512>("ML-KEM-512") && pass;

	// ML-KEM-768
	pass = TestMLKEMKeyGen<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMSerialization<MLKEM_768>("ML-KEM-768") && pass;

	// ML-KEM-1024
	pass = TestMLKEMKeyGen<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMSerialization<MLKEM_1024>("ML-KEM-1024") && pass;

	return pass;
}

// ******************** ML-DSA Validation (FIPS 204) ************************* //

template <class PARAMS>
static bool TestMLDSAKeyGen(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		MLDSASigner<PARAMS> signer(rng);

		const MLDSAPrivateKey<PARAMS>& privKey = signer.GetKey();

		if (privKey.GetPrivateKeySize() != PARAMS::SECRET_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " private key size mismatch" << std::endl;
			return false;
		}

		if (privKey.GetPublicKeySize() != PARAMS::PUBLIC_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " public key size mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key generation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " key generation - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestMLDSASignVerify(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair
		MLDSASigner<PARAMS> signer(rng);
		MLDSAVerifier<PARAMS> verifier(signer);

		// Sign a message
		std::string message = "Test message for ML-DSA signature validation";
		SecByteBlock signature(signer.SignatureLength());

		size_t sigLen = signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		if (sigLen != PARAMS::SIGNATURE_SIZE) {
			std::cout << "FAILED:  " << name << " signature size mismatch" << std::endl;
			return false;
		}

		// Verify the signature
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), sigLen);

		if (!valid) {
			std::cout << "FAILED:  " << name << " valid signature rejected" << std::endl;
			return false;
		}

		// Test with modified message (should fail)
		std::string modifiedMessage = "Modified message for ML-DSA signature";
		bool invalidAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(modifiedMessage.data()), modifiedMessage.size(),
			signature.begin(), sigLen);

		if (invalidAccepted) {
			std::cout << "FAILED:  " << name << " modified message incorrectly verified" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " sign/verify" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " sign/verify - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestMLDSASerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate original key pair
		MLDSASigner<PARAMS> original(rng);

		// Extract key bytes
		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		// Create new signer from private key bytes
		MLDSASigner<PARAMS> restoredSigner(skBytes.begin(), skBytes.size());

		// Create verifier from public key bytes
		MLDSAVerifier<PARAMS> verifier(pkBytes.begin(), pkBytes.size());

		// Sign with restored signer
		std::string message = "Test message for serialization";
		SecByteBlock signature(restoredSigner.SignatureLength());

		size_t sigLen = restoredSigner.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		// Verify with restored verifier
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), sigLen);

		if (!valid) {
			std::cout << "FAILED:  " << name << " serialization roundtrip failed" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key serialization" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " serialization - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateMLDSA()
{
	std::cout << "\nML-DSA (FIPS 204) validation suite running...\n\n";
	bool pass = true;

	// ML-DSA-44
	pass = TestMLDSAKeyGen<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASignVerify<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASerialization<MLDSA_44>("ML-DSA-44") && pass;

	// ML-DSA-65
	pass = TestMLDSAKeyGen<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASignVerify<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASerialization<MLDSA_65>("ML-DSA-65") && pass;

	// ML-DSA-87
	pass = TestMLDSAKeyGen<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASignVerify<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASerialization<MLDSA_87>("ML-DSA-87") && pass;

	return pass;
}

// ******************** SLH-DSA Validation (FIPS 205) ************************* //

template <class PARAMS>
static bool TestSLHDSAKeyGen(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		SLHDSAPrivateKey<PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		if (privKey.GetPrivateKeySize() != PARAMS::SECRET_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " private key size mismatch" << std::endl;
			return false;
		}

		if (privKey.GetPublicKeySize() != PARAMS::PUBLIC_KEY_SIZE) {
			std::cout << "FAILED:  " << name << " public key size mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key generation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " key generation - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestSLHDSASignVerify(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair
		SLHDSASigner<PARAMS> signer(rng);
		SLHDSAVerifier<PARAMS> verifier(signer);

		// Sign a message
		std::string message = "Test message for SLH-DSA signature validation";
		SecByteBlock signature(signer.SignatureLength());

		size_t sigLen = signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		if (sigLen != PARAMS::SIGNATURE_SIZE) {
			std::cout << "FAILED:  " << name << " signature size mismatch" << std::endl;
			return false;
		}

		// Verify the signature
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), sigLen);

		if (!valid) {
			std::cout << "FAILED:  " << name << " valid signature rejected" << std::endl;
			return false;
		}

		// Test with modified message (should fail)
		std::string modifiedMessage = "Modified message for SLH-DSA signature";
		bool invalidAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(modifiedMessage.data()), modifiedMessage.size(),
			signature.begin(), sigLen);

		if (invalidAccepted) {
			std::cout << "FAILED:  " << name << " modified message incorrectly verified" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " sign/verify" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " sign/verify - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool TestSLHDSASerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate original key pair
		SLHDSASigner<PARAMS> original(rng);

		// Extract key bytes
		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		// Create new signer from private key bytes
		SLHDSASigner<PARAMS> restoredSigner(skBytes.begin(), skBytes.size());

		// Create verifier from public key bytes
		SLHDSAVerifier<PARAMS> verifier(pkBytes.begin(), pkBytes.size());

		// Sign with restored signer
		std::string message = "Test message for serialization";
		SecByteBlock signature(restoredSigner.SignatureLength());

		size_t sigLen = restoredSigner.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		// Verify with restored verifier
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), sigLen);

		if (!valid) {
			std::cout << "FAILED:  " << name << " serialization roundtrip failed" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key serialization" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " serialization - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateSLHDSA()
{
	std::cout << "\nSLH-DSA (FIPS 205) validation suite running...\n\n";
	bool pass = true;

	// Test fastest variants (128f) for quick validation
	// SHA2 variants
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;

	// SHAKE variants
	pass = TestSLHDSAKeyGen<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;

	// Test one small variant for thoroughness
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;

	// Higher security levels (just key gen to verify sizes)
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_192f>("SLH-DSA-SHA2-192f") && pass;
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_256f>("SLH-DSA-SHA2-256f") && pass;

	return pass;
}

// ******************** X-Wing Validation (Hybrid KEM) ************************* //

static bool TestXWingKeyGen()
{
	AutoSeededRandomPool rng;

	try {
		XWingDecapsulator decapsulator(rng);

		const XWingPrivateKey& privKey = decapsulator.GetPrivateKey();

		if (privKey.GetPrivateKeySize() != XWING_Constants::SECRET_KEY_SIZE) {
			std::cout << "FAILED:  X-Wing private key size mismatch" << std::endl;
			return false;
		}

		if (privKey.GetPublicKeySize() != XWING_Constants::PUBLIC_KEY_SIZE) {
			std::cout << "FAILED:  X-Wing public key size mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  X-Wing key generation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  X-Wing key generation - " << e.what() << std::endl;
		return false;
	}
}

static bool TestXWingEncapsDecaps()
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair (recipient)
		XWingDecapsulator decapsulator(rng);

		// Get public key
		SecByteBlock pubKey(XWING_Constants::PUBLIC_KEY_SIZE);
		decapsulator.GetKey().GetPublicKey(pubKey);

		// Create encapsulator with public key (sender)
		XWingEncapsulator encapsulator(pubKey.begin(), pubKey.size());

		// Encapsulate (sender generates shared secret and ciphertext)
		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());

		encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);

		if (ciphertext.size() != XWING_Constants::CIPHERTEXT_SIZE) {
			std::cout << "FAILED:  X-Wing ciphertext size mismatch" << std::endl;
			return false;
		}

		// Decapsulate (recipient recovers shared secret)
		SecByteBlock sharedSecret2(decapsulator.SharedSecretLength());
		bool success = decapsulator.Decapsulate(ciphertext, sharedSecret2);

		if (!success) {
			std::cout << "FAILED:  X-Wing decapsulation failed" << std::endl;
			return false;
		}

		// Compare shared secrets
		if (std::memcmp(sharedSecret1.begin(), sharedSecret2.begin(), sharedSecret1.size()) != 0) {
			std::cout << "FAILED:  X-Wing shared secrets do not match" << std::endl;
			return false;
		}

		std::cout << "passed:  X-Wing encapsulation/decapsulation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  X-Wing encaps/decaps - " << e.what() << std::endl;
		return false;
	}
}

static bool TestXWingMultipleRounds()
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair (recipient)
		XWingDecapsulator decapsulator(rng);

		// Get public key
		SecByteBlock pubKey(XWING_Constants::PUBLIC_KEY_SIZE);
		decapsulator.GetKey().GetPublicKey(pubKey);

		// Create encapsulator
		XWingEncapsulator encapsulator(pubKey.begin(), pubKey.size());

		// Test multiple encapsulations with same key pair
		for (int i = 0; i < 5; i++) {
			SecByteBlock ciphertext(encapsulator.CiphertextLength());
			SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());
			SecByteBlock sharedSecret2(decapsulator.SharedSecretLength());

			encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);
			decapsulator.Decapsulate(ciphertext, sharedSecret2);

			if (std::memcmp(sharedSecret1.begin(), sharedSecret2.begin(), sharedSecret1.size()) != 0) {
				std::cout << "FAILED:  X-Wing multiple rounds - round " << i << std::endl;
				return false;
			}
		}

		std::cout << "passed:  X-Wing multiple rounds" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  X-Wing multiple rounds - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateXWing()
{
	std::cout << "\nX-Wing (Hybrid KEM) validation suite running...\n\n";
	bool pass = true;

	pass = TestXWingKeyGen() && pass;
	pass = TestXWingEncapsDecaps() && pass;
	pass = TestXWingMultipleRounds() && pass;

	return pass;
}

// ******************** LMS Validation (SP 800-208) ************************* //

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSKeyGen(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		if (!privKey.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " private key validation" << std::endl;
			return false;
		}

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		if (!pubKey.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " public key validation" << std::endl;
			return false;
		}

		if (pubKey.GetPublicKeyByteLength() !=
			static_cast<size_t>(LMSPublicKey<LMS_PARAMS, OTS_PARAMS>::PUBLIC_KEY_SIZE)) {
			std::cout << "FAILED:  " << name << " public key size mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " key generation" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " key generation - " << e.what() << std::endl;
		return false;
	}
}

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSSignVerify(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		// Create signer with test-only state store
		InsecureMemoryStateStore store(LMS_PARAMS::TOTAL_LEAVES);
		LMSSigner<LMS_PARAMS, OTS_PARAMS> signer(privKey, store);

		// Create verifier
		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		// Sign a message
		std::string message = "Test message for LMS signature validation";
		SecByteBlock signature(signer.SignatureLength());

		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		// Verify the signature
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " valid signature rejected" << std::endl;
			return false;
		}

		// Test with modified message (should fail)
		std::string modifiedMessage = "Modified message for LMS signature";
		bool invalidAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(modifiedMessage.data()), modifiedMessage.size(),
			signature.begin(), signature.size());

		if (invalidAccepted) {
			std::cout << "FAILED:  " << name << " modified message incorrectly verified" << std::endl;
			return false;
		}

		// Test with mutated signature (flip one byte)
		SecByteBlock mutatedSig(signature);
		mutatedSig[mutatedSig.size() / 2] ^= 0x01;

		bool mutatedAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			mutatedSig.begin(), mutatedSig.size());

		if (mutatedAccepted) {
			std::cout << "FAILED:  " << name << " mutated signature incorrectly verified" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " sign/verify" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " sign/verify - " << e.what() << std::endl;
		return false;
	}
}

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSMultipleSignatures(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(LMS_PARAMS::TOTAL_LEAVES);
		LMSSigner<LMS_PARAMS, OTS_PARAMS> signer(privKey, store);
		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		// Sign and verify multiple messages
		const unsigned int count = 5;
		for (unsigned int i = 0; i < count; i++)
		{
			std::string message = "Message number " + std::to_string(i);
			SecByteBlock signature(signer.SignatureLength());

			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(message.data()), message.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(message.data()), message.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " signature " << i << " rejected" << std::endl;
				return false;
			}
		}

		// Verify remaining count
		if (store.RemainingSignatures() != LMS_PARAMS::TOTAL_LEAVES - count) {
			std::cout << "FAILED:  " << name << " remaining signatures mismatch" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " multiple signatures (" << count << ")" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " multiple signatures - " << e.what() << std::endl;
		return false;
	}
}

static bool TestLMSExhaustion()
{
	AutoSeededRandomPool rng;
	const char* name = "LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(LMS_SHA256_M32_H5::TOTAL_LEAVES);  // 32
		LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> signer(privKey, store);
		LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string message = "Exhaustion test message";
		SecByteBlock signature(signer.SignatureLength());

		// Sign all 32 messages
		for (unsigned int i = 0; i < 32; i++)
		{
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(message.data()), message.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(message.data()), message.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " signature " << i << " rejected during exhaustion test" << std::endl;
				return false;
			}
		}

		// Verify exhausted
		if (!signer.IsExhausted()) {
			std::cout << "FAILED:  " << name << " not exhausted after 32 signatures" << std::endl;
			return false;
		}

		if (signer.RemainingSignatures() != 0) {
			std::cout << "FAILED:  " << name << " remaining signatures not zero" << std::endl;
			return false;
		}

		// 33rd signature should throw SignerExhausted
		bool threw = false;
		try {
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(message.data()), message.size(),
				signature.begin());
		}
		catch (const SignerExhausted&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name << " did not throw SignerExhausted on 33rd signature" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " exhaustion (32 sigs, 33rd throws)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " exhaustion - " << e.what() << std::endl;
		return false;
	}
}

static bool TestLMSStoreContract()
{
	const char* name = "InsecureMemoryStateStore";

	try {
		InsecureMemoryStateStore store(4);

		// Reserve returns monotonically increasing indices
		StateReservation r0 = store.ReserveNext();
		StateReservation r1 = store.ReserveNext();
		StateReservation r2 = store.ReserveNext();

		if (r0.LeafIndex() != 0 || r1.LeafIndex() != 1 || r2.LeafIndex() != 2) {
			std::cout << "FAILED:  " << name << " non-monotonic indices" << std::endl;
			return false;
		}

		// RemainingSignatures never overcounts
		if (store.RemainingSignatures() != 1) {
			std::cout << "FAILED:  " << name << " remaining signatures incorrect" << std::endl;
			return false;
		}

		// Commit idempotency (double commit succeeds)
		store.CommitReservation(r0);
		store.CommitReservation(r0);  // second commit - should not throw

		// Abort burns index (does not affect remaining count since already advanced)
		store.AbortReservation(r1);

		// IsHealthy
		if (!store.IsHealthy()) {
			std::cout << "FAILED:  " << name << " reports unhealthy" << std::endl;
			return false;
		}

		// Reserve last index
		StateReservation r3 = store.ReserveNext();
		if (r3.LeafIndex() != 3) {
			std::cout << "FAILED:  " << name << " wrong last index" << std::endl;
			return false;
		}

		// Exhaustion
		if (!store.IsExhausted()) {
			std::cout << "FAILED:  " << name << " not exhausted" << std::endl;
			return false;
		}

		if (store.RemainingSignatures() != 0) {
			std::cout << "FAILED:  " << name << " remaining not zero when exhausted" << std::endl;
			return false;
		}

		// Next reserve should throw
		bool threw = false;
		try {
			store.ReserveNext();
		}
		catch (const SignerExhausted&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name << " did not throw on exhaustion" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " contract tests" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " contract - " << e.what() << std::endl;
		return false;
	}
}

// ******************** NIST ACVP Known-Answer Tests ************************* //

static bool HexDecode(const char *hexStr, byte *out, size_t outLen)
{
	std::string decoded;
	StringSource ss(hexStr, true, new HexDecoder(new StringSink(decoded)));
	if (decoded.size() != outLen)
		return false;
	std::memcpy(out, decoded.data(), outLen);
	return true;
}

static bool TestLMSKeyGenKAT()
{
	const char *name = "LMS ACVP keyGen KAT";

	// NIST ACVP test vectors: LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8
	// Source: https://github.com/usnistgov/ACVP-Server (tgId=24, tcId 76-80)
	struct KeyGenVector {
		const char *seed;
		const char *identifier;
		const char *expectedPubKey;
	};

	static const KeyGenVector vectors[] = {
		{  // tcId 76
			"A2800F6DEA71A09BAA024F2EB15B34C3E8F42D15BF9818B6D3F8D74C40F5A99D",
			"DC4C502EF70640EBA7D9F611FC66E5A9",
			"0000000500000004DC4C502EF70640EBA7D9F611FC66E5A9"
			"335A168B6EA2683E86A8CC2C1173A7A5E120505DE4BAB2E2F0D1B889C486D47F"
		},
		{  // tcId 77
			"473B07B6DF33B2C6F5FC46E5FF60543CBCDAACAD4888F9C2A607C7CF3A469281",
			"CA82E320FC0B289A18B563AA923F6C7D",
			"0000000500000004CA82E320FC0B289A18B563AA923F6C7D"
			"F732C8C157411BA98467FEB47A84D82B60AB43B5E3DB0C295B90FF014C412C47"
		},
		{  // tcId 78
			"FE58EFFD83E9BC5015CDBD1340820C60FE783C3C9E73906FB61074D76549702D",
			"353FE1F380D61D2DCB55489CA4359B90",
			"0000000500000004353FE1F380D61D2DCB55489CA4359B90"
			"BFF9E93AC19537665468D95EA174E97D32FD5EFC7BFB826964427B7A8790C063"
		},
		{  // tcId 79
			"5783FF509B34BAD7D6B9ED9BC4180BB77C5E7563302919ECBEB521EB73CAEC21",
			"9E731302EEA25A573A902D6AD6A350F3",
			"00000005000000049E731302EEA25A573A902D6AD6A350F3"
			"52F3530C0BA3B0BE86FE96C51A60944D111154C3184E9B6D9BDC96D2F6C5E89B"
		},
		{  // tcId 80
			"1BF23A824BBEFEB15E685DCCEE01104B8C3A91AC3E7EFED5FDE8D85482EE97AB",
			"69C9BAC6295EA92792BEC9E07BAC8E56",
			"000000050000000469C9BAC6295EA92792BEC9E07BAC8E56"
			"C64E36A5477133811AC931C33D7BFE0643B8C07DA99A66B36EC429BDADC46642"
		}
	};

	try {
		AutoSeededRandomPool rng;
		unsigned int passed = 0;

		typedef LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> PubKeyType;
		const size_t pkSize = PubKeyType::PUBLIC_KEY_SIZE;

		for (size_t t = 0; t < 5; t++)
		{
			byte seed[32], ident[16];
			SecByteBlock expectedPK(pkSize);

			if (!HexDecode(vectors[t].seed, seed, 32) ||
				!HexDecode(vectors[t].identifier, ident, 16) ||
				!HexDecode(vectors[t].expectedPubKey, expectedPK, pkSize))
			{
				std::cout << "FAILED:  " << name << " tcId " << (76 + t) << " hex decode error" << std::endl;
				return false;
			}

			LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> privKey;
			privKey.SetPrivateKey(seed, 32, ident, 16);

			PubKeyType pubKey;
			privKey.MakePublicKey(pubKey);

			if (pubKey.GetPublicKeyByteLength() != pkSize ||
				!VerifyBufsEqual(pubKey.GetPublicKeyBytePtr(), expectedPK, pkSize))
			{
				std::cout << "FAILED:  " << name << " tcId " << (76 + t) << " public key mismatch" << std::endl;

				// Print expected vs actual for debugging
				std::string actualHex;
				HexEncoder encoder(new StringSink(actualHex), false);
				encoder.Put(pubKey.GetPublicKeyBytePtr(), pkSize);
				encoder.MessageEnd();
				std::cout << "  expected: " << vectors[t].expectedPubKey << std::endl;
				std::cout << "  actual:   " << actualHex << std::endl;
				return false;
			}
			passed++;
		}

		std::cout << "passed:  " << name << " (" << passed << "/5 vectors)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateLMS()
{
	std::cout << "\nLMS (SP 800-208) validation suite running...\n\n";
	bool pass = true;

	// Store contract tests
	pass = TestLMSStoreContract() && pass;

	// NIST ACVP known-answer tests
	pass = TestLMSKeyGenKAT() && pass;

	// Functional tests: LMS-SHA256-M32-H5 / LMOTS-SHA256-N32-W8
	pass = TestLMSKeyGen<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSignVerify<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSMultipleSignatures<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;

	// Exhaustion test (H5 = 32 signatures)
	pass = TestLMSExhaustion() && pass;

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
