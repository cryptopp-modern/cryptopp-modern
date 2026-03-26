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

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSSerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		// Generate key pair
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		// DER encode private key
		std::string privDer;
		StringSink privSink(privDer);
		privKey.DEREncode(privSink);

		if (privDer.empty()) {
			std::cout << "FAILED:  " << name << " private key DER encode produced empty output" << std::endl;
			return false;
		}

		// BER decode private key
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey2;
		StringSource privSource(privDer, true);
		privKey2.BERDecode(privSource);

		// Verify round-trip: seed and identifier match
		if (!VerifyBufsEqual(privKey.GetSeedBytePtr(), privKey2.GetSeedBytePtr(),
			LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::SEED_SIZE) ||
			!VerifyBufsEqual(privKey.GetIdentifierBytePtr(), privKey2.GetIdentifierBytePtr(),
			LMSPrivateKey<LMS_PARAMS, OTS_PARAMS>::I_SIZE))
		{
			std::cout << "FAILED:  " << name << " private key DER round-trip mismatch" << std::endl;
			return false;
		}

		// DER encode public key
		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.DEREncode(pubSink);

		if (pubDer.empty()) {
			std::cout << "FAILED:  " << name << " public key DER encode produced empty output" << std::endl;
			return false;
		}

		// BER decode public key
		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey2;
		StringSource pubSource(pubDer, true);
		pubKey2.BERDecode(pubSource);

		// Verify round-trip: public key bytes match
		typedef LMSPublicKey<LMS_PARAMS, OTS_PARAMS> PubKeyType;
		if (!VerifyBufsEqual(pubKey.GetPublicKeyBytePtr(), pubKey2.GetPublicKeyBytePtr(),
			PubKeyType::PUBLIC_KEY_SIZE))
		{
			std::cout << "FAILED:  " << name << " public key DER round-trip mismatch" << std::endl;
			return false;
		}

		// Verify decoded public key can still verify signatures
		InsecureMemoryStateStore store(LMS_PARAMS::TOTAL_LEAVES);
		LMSSigner<LMS_PARAMS, OTS_PARAMS> signer(privKey2, store);
		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifier(
			pubKey2.GetPublicKeyBytePtr(), pubKey2.GetPublicKeyByteLength());

		std::string message = "Serialization round-trip test message";
		SecByteBlock signature(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " sign/verify after DER round-trip" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " serialization" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " serialization - " << e.what() << std::endl;
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

static bool TestLMSSigVerKAT()
{
	const char *name = "LMS ACVP sigVer KAT";

	// NIST ACVP test vectors: LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8
	// Source: https://github.com/usnistgov/ACVP-Server (tgId=24, tcId 93-96)
	const char *publicKeyHex =
		"000000050000000423200C3449D6A258C1EFAEF4BF1AB4126ECEA938FF64E0D77"
		"17605EDE9CFEDB6E441F26066C10CC84D53E5FA6CEF7D85";

	struct SigVerVector {
		unsigned int tcId;
		bool expectedResult;
		const char *message;
		const char *signature;
	};

	static const SigVerVector vectors[] = {
		{ 93, false,
			"B889A869C70BD644F445075D12EE336AED7CBC516468F3F348272A4F7977B224"
			"712F170A6374D5C528DE05974289FFC7A3BECC5E3BB852D0940BDE9DD1FE23FA"
			"DD49E611B6D629BADAF809B73987FF27C4FB4D9C718F6D5840CEE18C2FB0BE31"
			"963E1F41B0C3C3F15B3EEDA910939E75980D4D8F2FBA38FC8A97D579C785F8C8",
			"0000000E000000040042CA6A8D699135D19008A9C9847BF9925A5787988214B6"
			"25A0A81CCF33E3919419888B0AC472F8FFF5F5B78FA7E1D3A6BD9A69B9B62421"
			"95B8E2DBA419FFDD3C02750183CCC3096160A73F7505EA1B177324F088509512"
			"91C21CFF95BACC6C76863F96C924FBF64880F831106BB103A30D4800C011BFDD"
			"EB2D8D56F19391C5E13E648AF0591C11C77F51561E326DD6D098F2F9417DC4B6"
			"DF7AD7268BAAEC48818794DC8EAF16ED8781F3DB8749C56348507A42F9A3976C"
			"4D11A21F9ED510124B20683D52F6A67104C7F7CF067F50BC1FC0BBF37CCFCCD4"
			"24ABC7DD290B99C08C0001275B906165124D5B72727D6700DDB600D303AB0743"
			"030683C1920538B4B1DFA4D40DA726A131D28E506E0282FD73B295F2AEAB4346"
			"31713BFEAA8D751A01B08A679FCE2C76525B9F22F58D15EAB00ED50287A43751"
			"5D80E9947DFC2D41C609760969A13731144268AF4D8946DBE6BCB4E37181BDA0"
			"5BA9C2D962AC612BA42F374B17FD64488F993893FC5B946A6169C0535250F66E"
			"92044722F678E523037CD2F2FC1D45EBB2B9DF4A8F65329BFB98B84D7CD1BFF5"
			"F822ABB5C785A796C3F9B89A1E45F9A0D594667C93CCD20D77AB5596D80329A8"
			"05A40ABA22EFEF7233E01F44756CA671FF5E052C6546A4422F77E82032843E6B"
			"6D020B89894522A40265D1CF3397B3346D79CADCC83D0CA4FF75C07683274A0F"
			"31F137B6B861319065F33AB543C44811CCADDDCEF2A8C48741B390D137321910"
			"242270436C4211E92D79FD2629C4ADA57200239916C33A04C0C6E404DAA0B118"
			"7C19A9465F4BBD64CF91330CDCD02965AC6F36A931C9B11390AB1CD333120E48"
			"A65D9E1FF467950D5B8EDB1ED7CE545B96750A402221E377874EED599D16DD2F"
			"1B7226C1D740A66C8875FC9D781A18267214F5FA8A71792359EEE84EAD23CDAA"
			"9214205C7FDC4F389E051D2612CDBEB9047E3E0A0B7075F7B0377C09839DE2E3"
			"37B76B515CD371AC3F41C2821B7734AD9661606FCFE4B4B147022E32CBE51579"
			"EFCE6887BCDAA9EAF366F0332C75A4A5B8167CA4B5A626F196C0043DCA878B2A"
			"108D4D38EB4B0A4843C5461D9ACFB3D9C8CFF2B110E79852494E631D877C344D"
			"A60D32B4D17A6D3351F7F639954339BC2A42E4F177E1A4FDFBB17411F35BE3BB"
			"519C7143B13EC2665F0CCFF9A287A107CFF3F8E03D613F29D790BF52CC37895E"
			"E6C7CB392B79277BD3A819EA09276EEAAF63E4F7FFDC81C8FA9C0F03448ECD89"
			"7F03F6FF5921FE81B1931F790C8E8D406CF21404F24441A44F1835C2E61EA63B"
			"1A48DDFB9DA7F89EBA18D800CA5E346CDBD050B3003DA3333F37D0601EE6AD14"
			"9C488CE95718EE1F65A8489D21C7E7F12C3DFA865F5FE6A2ADDE421B61A233A8"
			"FA51CAB0AAD4CFCBAA53DC28231B7FD699733C714B995D0760A8922C6E36A0E7"
			"FEFF56B227A342A6A3152624AD208B8D0C91F8322BC4758C219C7E5A5EFE113A"
			"ABD6298E6823AACDA4D5E4E4C4EA8830C93FFE110B41746E739BCC8F6C9EC341"
			"E5F54A6D1228F52D6EAA74F582DB2B6C7D01A40D2559445D6219469A08591D33"
			"C34FBA4C343C0B8E00000006163F0AF24881A3F8EED95A1EFCF8D1FAB3839570"
			"7350AB26C634A75797D2819A5C9FAE9E8B2CF6E68EF971DD00380C7F1FFCFB12"
			"53321F7ECEDF2EE7A88E2D1FD55980E5EB3E5A23819122AC7FDA6F5A9E082B72"
			"F420C87DD2A8C85EE2E76AF920CE07739869AF8ACDAACAF1750D084B9554F0E5"
			"396DA1646071D52FF55451319232604D6770F1E5917FEE95B87E5FA91A30F07C"
			"279E71D56A6CA3C0A55BFB42"
		},
		{ 94, true,
			"29A7ACEC4EC2C9A60ED511D14F48D0C2F23ADCF6AC28CDBA1FE981D8F4908EC5"
			"E1678C26926CF397D440EE6AE6A14F4040656132399266B5CE3F5941599DE7FD"
			"40F7729F881128546C168812DE9BF9792ADB75DC8ECFBD54061538BAC15FAD5D"
			"52CC06E01A7A1CB641EF01F7E66CCA06FA1AA107FB3ACA46D88D1AA5C869446E",
			"0000001E00000004A61D459C5E18950836C71ACE64E6F817339CD6E83560FE64"
			"9C6C5EDDD65E9B9B7BE55BDB5D9447C09950771DFE55620A711BC69AA952EDAA"
			"DBC1A29D3112458ADCCE0DF6DF4181C43A931B7AC56911BD5DEE955BBF9802CA"
			"12DF2A76B754305CCAD4B8F878F3ECA50E55521988312467C86B13CE735E944D"
			"316C5E5C350552043A43ED24F69070B10C768A10C7FD9E97F827DD99F6758A49"
			"B583E67260363B2FFBAC11D6F60F15DA02E9BBF9B39820B43B7D7AC76A74C3AE"
			"1A8D94F03497C5CD50D5080211A1D869BF205787ECB24BC9FAB6E1A3965E8F20"
			"708023279D5BE649F34E8069B59F3CF4CDFA43FB33FDAA62EBCE9BEF233907CC"
			"746A2C8565854772DB0E763697ABC5B6F24E03CB58A410B9857D4891498D6815"
			"3C2D262977598502EB1D46B6512E3C47297340C8FE0EACB019830A0D782D6E5F"
			"930C91F00CF5A8E88077AF3F152B61A99376BA2086FED8FE46FD16C2AFCC4F28"
			"F09132EA5C7FA0EFBEFBF0110F144E0B85C769A357A2FBBD615428D34D0F7F98"
			"3ED5EBB8C5A9012FBDD00F2E7A5430205382D852CF3DF48BB6960903E44BAC21"
			"D446C346D8944387C2C309EE623E1C3DEA17C636124107CC4C682D82EBC70B26"
			"FCB17FD4F2BBBA6E92FE7F299FFF90333679C23124389C9B0E3363A029866B52"
			"4DCF9F6B76C217CD8029A6689BC39E365175B4078B9A5B933EAB035C36FF7EA3"
			"3955311B5FA36554865F0C7839F599560775B9F476E9463589A842B485ED7918"
			"73ED3063069D30EB0324BCE20EA5CFB589AC599CDBB92748BF22F7BC7CF79225"
			"930C136C89CDF2CB11A83FC157E16514924D3E8A6499BA38EB7B77DBF5D7660E"
			"6B011615C9CD97646C5FE8BA404F6DB4F0D867B593AAE5FB814ACF1CBB2C71EA"
			"C723797132A639F66C1CD14C2DC5F20C7B8B0327232884E53A00758E7022876D"
			"8520BA5AE0B8BFF3D1F4DF06238F048698660736917D787F4876CC42677960EF"
			"48388CFF49BC37C6AB423AEA473AC07C9636541151665EED2E6072ECD758E23C"
			"139CEB45FA98E457255E7ECDCA1EFDF59C5055FA09173D21EDBA70A8BC0D34E0"
			"25A821AFE2FD69E9C418D87262AD42431B66CD0FFCADDD43626561F552B511FC"
			"062868E1AF0EADC7FF149982F05653E565BDF145D0241A6552A44DFB7992C977"
			"2060F9E0AE90B53D57584B851DB7C26B4AD2C3E4403CAE84E0185BBEEA0E8043"
			"E2310FAA319973ACBD2951AF99DC945665F1162016E69F3C1B6E73833F10D397"
			"DDC5BD00F15A8BB335605CAA1BC85FF99D02B279C8E11E1239EEC1A5CA51906A"
			"203438486C6BDEEBE6A9990C67ACEE556722ACA5624024BA01B6ADF8CB0018FE"
			"EDEA03C3C599D30441471E8E560E32B052F09BF48A5603B546999329007E2730"
			"8A126B0E530050CFB95DA96F3E3EB7D8E1511EDB2ECC67A79654E97E85363DDC"
			"5E18DEB6B2F82A4B692E0F9F21EA23554D6FC6F1EE423A70C425C007904862E5"
			"AB85734E33639A7EEE8351BBBA3CF1CE7BADA4C3EF0B4A1504F2E9B27E462029"
			"348F58CD3C7B175560218CC4BA11A89C56F4279AA4C95DB34D60F042A0AA0173"
			"7A7F40F79812841D00000005E13F7FCE86CD341DFCD6601C22DFE9C22C4AC53C"
			"55116846376D1EB32695E9993FF527D4561B11F6EDBCE1CED0E160DB4D41CA62"
			"67C138E71B4CD0D8C7E1C142150EE38450F99C6D13F5772E6355B7F0F1DB45E9"
			"266D91DEF43ADE290CCD52BA3E8AF0A8EF51438008F5D308A259AC328D0AEDDA"
			"7486BF3E1794BE9D0F6767412ED87C37210685D9D0A534967FDAD538930049AB"
			"D61AC1563349235ED14647EA"
		},
		{ 95, false,
			"F1C3D111BB9503C3610672063B637C9E3F060D8688ECF7FD0981FE98DE4CBC08"
			"D34AFC6F0692EC4A0837C10A040780B72F9B5FEC2C8D44EE33D7A3A7DF0BFB23"
			"10760DBC1AAC3A9EF23914CDDA2AD4AC29DEA4D96FCD7EE106161B4130DE841C"
			"049C34D9B4A995D375CFB9AB6E4B054F18D4866328FFBF454FC166B07FAF6EAB",
			"0000001C00000004E0C6B22E29056ABFF904F74B953A580CB479566837D7367C"
			"091A39D451076151E9A9EF559D22A867E9E8EA7C72AC33AE531B60C10B7FDC6C"
			"10C76FCEBA12F57E8926D64AD953CDCC737C8112EC938803D6E84A3BE9EDEB34"
			"29A5B75451C2D5633A0FC6FAB19E5FF292DAE91B8D6BF566F76E6C0087CAAE9F"
			"9BC394E29145AEC30F36B5B0E12340C01911B5E9263E596819EA3F1071E18344A"
			"5FAACAE8C524A55AFFBC9E0D4CC2280495E3E0CF48D2DE870C6B2D091B65597F"
			"E15942408CA66469DA043F23492959380859114A6BFB1B74E18F87825A188F4F"
			"002BA23E29D4B72359EB399574084F3299260A61DD38B67413EFE9A03E7041C1"
			"DA419CB4840BF617133A7C7623D0E3355B24F191A64FF207C97C35C35B9A1B5C"
			"26E85C689F4FB14B8B547C3FA6B1E2884B9B2A8DF7F8C22709DC626C2CC4DD92"
			"03579341AAAC2207D5DCBE82792B935E5DACE182FBD46837ACC505749ACACFBD"
			"E35066B7295ED32DCC8B87DE80B21396681424C9252935A5390AE512960F4019B"
			"E44FFF8D0013AE8F2A8FD1DBB9C839C599C481B88BAE0442E7B98C340C375D07"
			"198C579B860C3D3FD7C8CBCEEC9D804580B55BEB758A47B617F31EEEFC712B95"
			"204044E71BE506E4CF570AB4E46D3745677A586FA6E0BC82FA89CA0D8B0359BC"
			"5901AABEDCC3E1B78F346AB9D2869E55FB02400F156A97352EF1CFF26DA347AB"
			"39C0CCD28611C53F7DECD94A0518B136CD6C717C645DE3B4A2A7459FB79BDBF3"
			"AE11D240831576425D56975C2DA1533A3BE3E3935AA889851B918D9A321F60CA"
			"46FD2534D25C7808D6317BD793CEB8C24227D8DDD16726274308D5F5EFDC54BD"
			"917125ADCC7E0C76E8910C52DD8235DCA57D1E9601A0BB47330D632666EB1657"
			"E4FBBBF3F9CF834B08B1A5BF0A911B542EB3FFF9D656B376D34D015C72BFAFF6"
			"99E6C503F194976CC36A0EF53D5EBAF7BEEFE736F469194AFC140DD0AB508EF1"
			"D9DD01EEC107845EEC83AC38F1577A5A1D90D632FC9443146730F313C704EBC3"
			"6AAEA365ACBAAB908C48EB750807803E003775BFAB2F0E145C4D578C449CF65A"
			"7CCDF62C11C6B638DC029C6AB7ACCB918FB31E212574601B99D093EA0335913481"
			"EB48EE9AFCB4D44B3A0569F315DC9FC136C9667760E251E4F7D363D3B7A543DA"
			"7E06AC4DA1BBDB2E528A3A09146AAA7A31BFA72DEC8B6FF7631E5E220090B525"
			"19C1D38F973FE5DF1D4ABFB6DC91B387AB58DD4AB338ACC4473185528CE9B806"
			"72CF95A90B2F01C63B1370A5DFA16E68B2394806E366831B9F66A731CD4EB103"
			"EFAD060160563A58E1FCAFE60CD68B143FCE4EDF1B4BC471AF3964B633C35374"
			"20C68F238976726E552F64913F01A68E14C06DC00494F7BCF67245F7CF61DA48"
			"D9147F78ABD9B39D01CCE1DAE440C8B58803EB554EB18676BF1D2F7769959871"
			"C22F63B23A0326C32EE4E7C17F2E60CC1B3AAD109F3C4B2A6766C465440930B7"
			"A53CC8A94CDF3445099C0659919FB017228F4337838CE359F9D2E975FE0326CB"
			"263FE8B5F092A83CA1069AABB7C6DFE7C0A09AB6BD815448FE0D9EC20206C3DB"
			"5C6B41770951000000052827CADCD80BEFBDC83FB1ADC143BC0C8880FFD67456"
			"40B738655276E5E0647923A7ADB312339B54D921AC05D59433B13076F9F1C5FB"
			"968AA4D324B3752CB76B150EE38450F99C6D13F5772E6355B7F0F1DB45E9266D"
			"91DEF43ADE290CCD52BA3E8AF0A8EF51438008F5D308A259AC328D0AEDDA7486"
			"BF3E1794BE9D0F6767412ED87C37210685D9D0A534967FDAD538930049ABD61A"
			"C1563349235ED14647EB"
		},
		{ 96, false,
			"1C1362C375DA77C0AA8CFACFA6FE52A1806C8DF6C81E181141E40AD94D53BAD0"
			"9FCB00D588F2CF2325C7FF9FD78D1DF1D0380430AB2E101DE9EBB645FD9C88A9"
			"2BD15CC4F023D9849D3824D83C01FDF72A0776D6FDE6A2FC8FF1F862776C5C49"
			"A03BA0D48447F9470E01164D2A9F0EE14E2DB259E629E5CCA6E10BE96AE886B2",
			"000000040000000413E47927F530CB2B5AF3C567076030B1BDF5F0E5C840077C"
			"823E3ABB51C1CC7BCC2839EFFCD6A189E4228C4805B4CF8DB867E0FB9773E538"
			"89A4F94AEB87FFF5E1CC9968E783E7295DFCBAE40F999F05141F4FA280EB3D73"
			"BBE0A1F6EF88546942C8353C2C7D922BF6AF2B33003FA7150943A97E9DA8C24C"
			"8FF3B2A92ECF6EAE6B0AABD48471A43B3C3F21D5C1158EF9C766544DD5DBAA3"
			"75E9806372950B05A680CF5ED5C1423CD66694A77D6FB55DC93C56E1E42870C2"
			"A6D597B731A56DCC5E96384A8281C262530F37AA53A20A29223069355F84DC3F"
			"0B78794E47E15C5A73CAE211E853F45CD8833E0F72D6AA64DB7CFF89B20644CA"
			"6B38714B5CAAED8570BC7165224C9656ECB88C7C29F639F18AC4B183EA96F865"
			"BD92FBE6425E4198F388F7A4CD6CE55375F27FBBD39874035A540E3D49AAD685"
			"F5A94320EB3EE98994C52D2F57D6125A347BE2E704097D71D88710265F5AFF16"
			"738410F5D4CFE00CF68A56699F28964E726044FFEA912F2157132B7F4BF93C33"
			"8C50FBAC8B70B2D782293BB1A0A3170D6CD1ABC1AA631B510551CA7DBDEF84C7"
			"8CCA6358900A723517CBA3105BA4428E42E83D8C58B3B68AC37777DBD545AC7A"
			"194994BF2B76925E2C16550AE7700AC03FE94E0F8EB1C4C95C2CF6321CADE712"
			"F61333077D46DB2BECBD1E7E2A9A7678D34B18A61A7C2EE491F9FAA374E2FF9C"
			"863AB373F4C89A4ADB87A3961D1FA12881BF5D63907B7429A4C7D54D836F1721"
			"21DA6F0598B2A9279D7EF677C3DF04AA8DF59691DECAD15CC53B50B3CC23CABA"
			"288A5B80DC6E902BC9936CB28368D5E49CA0F6D6FED677F6061970E6F057B50E"
			"7B73C93BC4E32E00687C5B866BEF1949BCC657E7774727E1FAAFFBB172B6B616"
			"E86984357EFB9650CDE9BF171ACB7006A5EB0F9967EEAA0F9B371C8EE3A234C"
			"77EAD69C20DC2EE686DBCD0AF187E174FDEBC9838A0BB79DC0C8645D94299C89"
			"8CBD6771FDF3C6EFB467C88D762CA92FCF5E5222D4D21A8E16B7EF94B03E89E3"
			"49DFDD87A81F42A58DB8E807CA92DAD1BD92E1286E14550E0C0763E17C19A480"
			"A376D22ECA5585D4C88FDBE2B75FB90A89A986595E665A9E4EEDDD2DB163B84B"
			"8CE6F8174F8AE3897EEFF6AA71AB4F3FD971A001EA96885C91B6B9CDB02C36F7"
			"090640B0E4E69B54DE6CAF7FD1635D84B38027C1368947B7E80B8A162F0965BA"
			"A18AB7C8902F6740B4F9FABBB93D047528D78B76360890DC7A4B0940B7074EF9"
			"264A7B7D79CFE86499E511189DBC799235FB17A1F19012660D832D2109AA2322"
			"FE8ACD601FD7C6754C40C6681E5B03C48C40C4D26ACB25000FF409CE65A90E2D"
			"D4A8A3FE3C063D55B1A32270B623DB66B9A20575EA840FBDE6DE2CD7963827C5"
			"EA40675A30B89815429B3D34788C9205B724661D3881209BADA0343AD607ED58"
			"3158F19367DE4659F69240C94C6F794E34803B1635B0438FAD1010B31F9EA7BE"
			"1349CE2D6EADC3C3E081415CD3D0B15D1FDA1F69550E14FA9AF3E33C743C8C6F"
			"7BBD486363181A839C6E88D64D7769AD13A6E53FADFED3E30B7A038791E953AF"
			"912623A0FFEB976A4D0000000506FB8DB9A44E487419F9EB5433E3C70F5DD7BB"
			"E69DD56668C06FB37DC3C17065D6C592025BB99E8DBDC41012BBD8C56DC7639B"
			"CABF956C90AD4B3D04734BD4BC0A5779F791955F0FEF3BCA464222EEBB590AD1"
			"7EE21933AEBD1048D7C6FE05BC7028E6C0F6D329E2D21475C94A071AFFA2131C"
			"041F87E8CA2691EC8DEBAFF9999232604D6770F1E5917FEE95B87E5FA91A30F0"
			"7C279E71D56A6CA3C0A55BFB42"
		}
	};

	try {
		typedef LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> PubKeyType;
		const size_t pkSize = PubKeyType::PUBLIC_KEY_SIZE;
		const size_t sigSize = 1292;
		const size_t msgSize = 128;

		byte pkBytes[56];
		if (!HexDecode(publicKeyHex, pkBytes, pkSize))
		{
			std::cout << "FAILED:  " << name << " public key hex decode error" << std::endl;
			return false;
		}

		LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> verifier(pkBytes, pkSize);
		unsigned int passed = 0;

		for (size_t t = 0; t < 4; t++)
		{
			SecByteBlock msgBytes(msgSize);
			SecByteBlock sigBytes(sigSize);

			if (!HexDecode(vectors[t].message, msgBytes, msgSize) ||
				!HexDecode(vectors[t].signature, sigBytes, sigSize))
			{
				std::cout << "FAILED:  " << name << " tcId " << vectors[t].tcId
					<< " hex decode error" << std::endl;
				return false;
			}

			bool result = verifier.VerifyMessage(
				msgBytes, msgSize, sigBytes, sigSize);

			if (result != vectors[t].expectedResult)
			{
				std::cout << "FAILED:  " << name << " tcId " << vectors[t].tcId
					<< " expected " << (vectors[t].expectedResult ? "pass" : "fail")
					<< " got " << (result ? "pass" : "fail") << std::endl;
				return false;
			}
			passed++;
		}

		std::cout << "passed:  " << name << " (" << passed << "/4 vectors)" << std::endl;
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
	pass = TestLMSSigVerKAT() && pass;

	// Functional tests: LMS-SHA256-M32-H5 / LMOTS-SHA256-N32-W8
	pass = TestLMSKeyGen<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSignVerify<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSMultipleSignatures<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSerialization<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;

	// Exhaustion test (H5 = 32 signatures)
	pass = TestLMSExhaustion() && pass;

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
