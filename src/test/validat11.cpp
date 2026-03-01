// validat11.cpp - written and placed in the public domain by Colin Brown
//                 Post-Quantum Cryptography validation tests (FIPS 203, 204, 205)
//                 Source files split in July 2018 to expedite compiles.

#include <cryptopp/pch.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/validate.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#include <cryptopp/mlkem.h>
#include <cryptopp/mldsa.h>
#include <cryptopp/slhdsa.h>
#include <cryptopp/xwing.h>

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

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
