// validat11.cpp - written and placed in the public domain by Colin Brown
//                 Stateless post-quantum validation tests (FIPS 203, 204, 205).

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

#include <iostream>
#include <fstream>
#include <map>
#include <utility>

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
		MLKEMDecapsulator<PARAMS> decapsulator(rng);

		MLKEMEncapsulator<PARAMS> encapsulator(
			decapsulator.GetKey().GetPublicKeyBytePtr(),
			decapsulator.GetKey().GetPublicKeySize());

		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());

		encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);

		if (ciphertext.size() != PARAMS::CIPHERTEXT_SIZE) {
			std::cout << "FAILED:  " << name << " ciphertext size mismatch" << std::endl;
			return false;
		}

		SecByteBlock sharedSecret2(decapsulator.SharedSecretLength());
		decapsulator.Decapsulate(ciphertext, sharedSecret2);

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
		MLKEMDecapsulator<PARAMS> original(rng);

		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		MLKEMDecapsulator<PARAMS> restored(skBytes.begin(), skBytes.size());
		MLKEMEncapsulator<PARAMS> encapsulator(pkBytes.begin(), pkBytes.size());

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

template <class PARAMS>
static bool TestMLKEMSaveLoad(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		MLKEMDecapsulator<PARAMS> original(rng);

		SecByteBlock origPk(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(origPk.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		SecByteBlock origSk(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(origSk.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		// Public key Save/Load round-trip (X.509 SubjectPublicKeyInfo)
		MLKEMPublicKey<PARAMS> pubKey;
		pubKey.SetPublicKey(origPk.begin(), origPk.size());

		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.Save(pubSink);

		MLKEMPublicKey<PARAMS> loadedPub;
		StringSource pubSrc(reinterpret_cast<const byte*>(pubDer.data()), pubDer.size(), true);
		loadedPub.Load(pubSrc);

		if (std::memcmp(loadedPub.GetPublicKeyBytePtr(), origPk.begin(), origPk.size()) != 0) {
			std::cout << "FAILED:  " << name << " public key Save/Load roundtrip" << std::endl;
			return false;
		}

		// Private key Save/Load round-trip (PKCS#8 OneAsymmetricKey)
		MLKEMPrivateKey<PARAMS> privKey;
		privKey.SetPrivateKey(origSk.begin(), origSk.size());

		std::string privDer;
		StringSink privSink(privDer);
		privKey.Save(privSink);

		MLKEMPrivateKey<PARAMS> loadedPriv;
		StringSource privSrc(reinterpret_cast<const byte*>(privDer.data()), privDer.size(), true);
		loadedPriv.Load(privSrc);

		if (std::memcmp(loadedPriv.GetPrivateKeyBytePtr(), origSk.begin(), origSk.size()) != 0) {
			std::cout << "FAILED:  " << name << " private key Save/Load roundtrip" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " Save/Load DER roundtrip" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " Save/Load - " << e.what() << std::endl;
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
	pass = TestMLKEMSaveLoad<MLKEM_512>("ML-KEM-512") && pass;

	// ML-KEM-768
	pass = TestMLKEMKeyGen<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMSerialization<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMSaveLoad<MLKEM_768>("ML-KEM-768") && pass;

	// ML-KEM-1024
	pass = TestMLKEMKeyGen<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMSerialization<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMSaveLoad<MLKEM_1024>("ML-KEM-1024") && pass;

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
		MLDSASigner<PARAMS> signer(rng);
		MLDSAVerifier<PARAMS> verifier(signer);

		std::string message = "Test message for ML-DSA signature validation";
		SecByteBlock signature(signer.SignatureLength());

		size_t sigLen = signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		if (sigLen != PARAMS::SIGNATURE_SIZE) {
			std::cout << "FAILED:  " << name << " signature size mismatch" << std::endl;
			return false;
		}

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
		MLDSASigner<PARAMS> original(rng);

		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		MLDSASigner<PARAMS> restoredSigner(skBytes.begin(), skBytes.size());

		MLDSAVerifier<PARAMS> verifier(pkBytes.begin(), pkBytes.size());

		std::string message = "Test message for serialization";
		SecByteBlock signature(restoredSigner.SignatureLength());

		size_t sigLen = restoredSigner.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

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

template <class PARAMS>
static bool TestMLDSASaveLoad(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		MLDSASigner<PARAMS> original(rng);

		SecByteBlock origPk(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(origPk.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		SecByteBlock origSk(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(origSk.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		// Public key Save/Load round-trip (X.509 SubjectPublicKeyInfo)
		MLDSAPublicKey<PARAMS> pubKey;
		pubKey.SetPublicKey(origPk.begin(), origPk.size());

		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.Save(pubSink);

		MLDSAPublicKey<PARAMS> loadedPub;
		StringSource pubSrc(reinterpret_cast<const byte*>(pubDer.data()), pubDer.size(), true);
		loadedPub.Load(pubSrc);

		if (std::memcmp(loadedPub.GetPublicKeyBytePtr(), origPk.begin(), origPk.size()) != 0) {
			std::cout << "FAILED:  " << name << " public key Save/Load roundtrip" << std::endl;
			return false;
		}

		// Private key Save/Load round-trip (PKCS#8 OneAsymmetricKey)
		MLDSAPrivateKey<PARAMS> privKey;
		privKey.SetPrivateKey(origSk.begin(), origSk.size());

		std::string privDer;
		StringSink privSink(privDer);
		privKey.Save(privSink);

		MLDSAPrivateKey<PARAMS> loadedPriv;
		StringSource privSrc(reinterpret_cast<const byte*>(privDer.data()), privDer.size(), true);
		loadedPriv.Load(privSrc);

		if (std::memcmp(loadedPriv.GetPrivateKeyBytePtr(), origSk.begin(), origSk.size()) != 0) {
			std::cout << "FAILED:  " << name << " private key Save/Load roundtrip" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " Save/Load DER roundtrip" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " Save/Load - " << e.what() << std::endl;
		return false;
	}
}

// Context argument bounds.
template <class PARAMS>
static bool TestMLDSAContext(const char* name)
{
	try {
		MLDSA_MessageAccumulator<PARAMS> acc;
		acc.SetContext(NULLPTR, 0);  // empty context is allowed

		bool threw = false;
		try { acc.SetContext(NULLPTR, 1); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " SetContext(NULL, 1) did not throw" << std::endl;
			return false;
		}

		SecByteBlock big(256);
		threw = false;
		try { acc.SetContext(big.begin(), big.size()); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " SetContext(ctx, 256) did not throw" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " context bounds" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " context test - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateMLDSA()
{
	std::cout << "\nML-DSA (FIPS 204) validation suite running...\n\n";
	bool pass = true;

	// Context argument bounds
	pass = TestMLDSAContext<MLDSA_44>("ML-DSA-44") && pass;

	// ML-DSA-44
	pass = TestMLDSAKeyGen<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASignVerify<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASerialization<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASaveLoad<MLDSA_44>("ML-DSA-44") && pass;

	// ML-DSA-65
	pass = TestMLDSAKeyGen<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASignVerify<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASerialization<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASaveLoad<MLDSA_65>("ML-DSA-65") && pass;

	// ML-DSA-87
	pass = TestMLDSAKeyGen<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASignVerify<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASerialization<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASaveLoad<MLDSA_87>("ML-DSA-87") && pass;

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
		SLHDSASigner<PARAMS> signer(rng);
		SLHDSAVerifier<PARAMS> verifier(signer);

		std::string message = "Test message for SLH-DSA signature validation";
		SecByteBlock signature(signer.SignatureLength());

		size_t sigLen = signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		if (sigLen != PARAMS::SIGNATURE_SIZE) {
			std::cout << "FAILED:  " << name << " signature size mismatch" << std::endl;
			return false;
		}

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
		SLHDSASigner<PARAMS> original(rng);

		SecByteBlock skBytes(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(skBytes.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		SecByteBlock pkBytes(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(pkBytes.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		SLHDSASigner<PARAMS> restoredSigner(skBytes.begin(), skBytes.size());

		SLHDSAVerifier<PARAMS> verifier(pkBytes.begin(), pkBytes.size());

		std::string message = "Test message for serialization";
		SecByteBlock signature(restoredSigner.SignatureLength());

		size_t sigLen = restoredSigner.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

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

template <class PARAMS>
static bool TestSLHDSASaveLoad(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		SLHDSASigner<PARAMS> original(rng);

		SecByteBlock origPk(PARAMS::PUBLIC_KEY_SIZE);
		std::memcpy(origPk.begin(), original.GetKey().GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);

		SecByteBlock origSk(PARAMS::SECRET_KEY_SIZE);
		std::memcpy(origSk.begin(), original.GetKey().GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		// Public key Save/Load round-trip (X.509 SubjectPublicKeyInfo)
		SLHDSAPublicKey<PARAMS> pubKey;
		pubKey.SetPublicKey(origPk.begin(), origPk.size());

		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.Save(pubSink);

		SLHDSAPublicKey<PARAMS> loadedPub;
		StringSource pubSrc(reinterpret_cast<const byte*>(pubDer.data()), pubDer.size(), true);
		loadedPub.Load(pubSrc);

		if (std::memcmp(loadedPub.GetPublicKeyBytePtr(), origPk.begin(), origPk.size()) != 0) {
			std::cout << "FAILED:  " << name << " public key Save/Load roundtrip" << std::endl;
			return false;
		}

		// Private key Save/Load round-trip (PKCS#8 OneAsymmetricKey)
		SLHDSAPrivateKey<PARAMS> privKey;
		privKey.SetPrivateKey(origSk.begin(), origSk.size());

		std::string privDer;
		StringSink privSink(privDer);
		privKey.Save(privSink);

		SLHDSAPrivateKey<PARAMS> loadedPriv;
		StringSource privSrc(reinterpret_cast<const byte*>(privDer.data()), privDer.size(), true);
		loadedPriv.Load(privSrc);

		if (std::memcmp(loadedPriv.GetPrivateKeyBytePtr(), origSk.begin(), origSk.size()) != 0) {
			std::cout << "FAILED:  " << name << " private key Save/Load roundtrip" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " Save/Load DER roundtrip" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " Save/Load - " << e.what() << std::endl;
		return false;
	}
}

// Verify with an explicit context.
template <class PARAMS>
static bool SLHDSAVerifyWithContext(const SLHDSAVerifier<PARAMS>& verifier,
	const std::string& message, const byte* ctx, size_t ctxLen, const SecByteBlock& sig)
{
	SLHDSA_MessageAccumulator<PARAMS> accum;
	accum.SetContext(ctx, ctxLen);
	verifier.InputSignature(accum, sig.begin(), sig.size());
	if (!message.empty())
		accum.Update(reinterpret_cast<const byte*>(message.data()), message.size());
	return verifier.VerifyAndRestart(accum);
}

// Context bounds and context-bound signatures.
template <class PARAMS>
static bool TestSLHDSAContext(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		SLHDSA_MessageAccumulator<PARAMS> acc;
		acc.SetContext(NULLPTR, 0);  // empty context is allowed

		bool threw = false;
		try { acc.SetContext(NULLPTR, 1); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " SetContext(NULL, 1) did not throw" << std::endl;
			return false;
		}

		SecByteBlock big(256);
		threw = false;
		try { acc.SetContext(big.begin(), big.size()); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " SetContext(ctx, 256) did not throw" << std::endl;
			return false;
		}

		SLHDSASigner<PARAMS> signer(rng);
		SLHDSAVerifier<PARAMS> verifier(signer);

		const byte ctxA[] = { 'c', 't', 'x', '-', 'A' };
		const byte ctxB[] = { 'c', 't', 'x', '-', 'B' };
		std::string message = "context binding test message";

		SecByteBlock sig(signer.SignatureLength());
		SLHDSA_MessageAccumulator<PARAMS> signAccum(rng);
		signAccum.SetContext(ctxA, sizeof(ctxA));
		signAccum.Update(reinterpret_cast<const byte*>(message.data()), message.size());
		signer.SignAndRestart(rng, signAccum, sig.begin(), true);

		if (!SLHDSAVerifyWithContext<PARAMS>(verifier, message, ctxA, sizeof(ctxA), sig)) {
			std::cout << "FAILED:  " << name << " context A signature rejected under context A" << std::endl;
			return false;
		}
		if (SLHDSAVerifyWithContext<PARAMS>(verifier, message, ctxB, sizeof(ctxB), sig)) {
			std::cout << "FAILED:  " << name << " context A signature accepted under context B" << std::endl;
			return false;
		}
		if (SLHDSAVerifyWithContext<PARAMS>(verifier, message, NULLPTR, 0, sig)) {
			std::cout << "FAILED:  " << name << " context A signature accepted under empty context" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " context binding and bounds" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " context test - " << e.what() << std::endl;
		return false;
	}
}

// Verify a single ACVP vector through the FIPS 205 external (pure) interface.
template <class PARAMS>
static bool SLHDSAVerifyVector(const SecByteBlock& pk, const SecByteBlock& msg,
                               const SecByteBlock& ctx, const SecByteBlock& sig)
{
	SLHDSAVerifier<PARAMS> verifier(pk.begin(), pk.size());
	SLHDSA_MessageAccumulator<PARAMS> accum;
	accum.SetContext(ctx.begin(), ctx.size());
	verifier.InputSignature(accum, sig.begin(), sig.size());
	if (msg.size())
		accum.Update(msg.begin(), msg.size());
	return verifier.VerifyAndRestart(accum);
}

static SecByteBlock SLHDSAFromHex(const std::string& hex)
{
	std::string bin;
	StringSource(hex, true, new HexDecoder(new StringSink(bin)));
	return SecByteBlock(reinterpret_cast<const byte*>(bin.data()), bin.size());
}

static bool SLHDSADispatchVerify(const std::string& name, const SecByteBlock& pk,
	const SecByteBlock& msg, const SecByteBlock& ctx, const SecByteBlock& sig)
{
	if (name == "SLH-DSA-SHA2-128s")  return SLHDSAVerifyVector<SLHDSA_SHA2_128s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHA2-128f")  return SLHDSAVerifyVector<SLHDSA_SHA2_128f>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHA2-192s")  return SLHDSAVerifyVector<SLHDSA_SHA2_192s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHA2-192f")  return SLHDSAVerifyVector<SLHDSA_SHA2_192f>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHA2-256s")  return SLHDSAVerifyVector<SLHDSA_SHA2_256s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHA2-256f")  return SLHDSAVerifyVector<SLHDSA_SHA2_256f>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-128s") return SLHDSAVerifyVector<SLHDSA_SHAKE_128s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-128f") return SLHDSAVerifyVector<SLHDSA_SHAKE_128f>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-192s") return SLHDSAVerifyVector<SLHDSA_SHAKE_192s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-192f") return SLHDSAVerifyVector<SLHDSA_SHAKE_192f>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-256s") return SLHDSAVerifyVector<SLHDSA_SHAKE_256s>(pk, msg, ctx, sig);
	if (name == "SLH-DSA-SHAKE-256f") return SLHDSAVerifyVector<SLHDSA_SHAKE_256f>(pk, msg, ctx, sig);
	throw Exception(Exception::OTHER_ERROR, "SLH-DSA KAT: unknown parameter set " + name);
}

// NIST ACVP SLH-DSA signature verification known-answer tests.
// External pure-interface vectors. These fail against the old internal
// message form because it omitted the FIPS 205 message prefix.
static bool TestSLHDSASigVerKAT()
{
	const char* name = "SLH-DSA ACVP sigVer KAT";

	std::ifstream file(DataDir("TestVectors/slhdsa.txt").c_str());
	if (!file) {
		std::cout << "FAILED:  " << name << " cannot open TestVectors/slhdsa.txt" << std::endl;
		return false;
	}

	std::string line, curName, pkHex, msgHex, ctxHex, sigHex, passedStr;
	unsigned int total = 0;
	// Track pass/fail coverage per parameter set.
	std::map<std::string, std::pair<unsigned int, unsigned int> > coverage;

	try {
		while (std::getline(file, line)) {
			if (!line.empty() && line[line.size() - 1] == '\r')
				line.erase(line.size() - 1);
			if (line.empty() || line[0] == '#')
				continue;

			std::string::size_type colon = line.find(':');
			if (colon == std::string::npos)
				continue;
			std::string key = line.substr(0, colon);
			std::string val = line.substr(colon + 1);
			while (!val.empty() && val[0] == ' ')
				val.erase(0, 1);

			if (key == "Name") curName = val;
			else if (key == "PublicKey") pkHex = val;
			else if (key == "Message") msgHex = val;
			else if (key == "Context") ctxHex = val;
			else if (key == "Signature") sigHex = val;
			else if (key == "TestPassed") passedStr = val;
			else if (key == "Test") {
				if (val == "SigVer") {
					bool expected = (passedStr == "true");
					bool result;
					try {
						result = SLHDSADispatchVerify(curName,
							SLHDSAFromHex(pkHex), SLHDSAFromHex(msgHex),
							SLHDSAFromHex(ctxHex), SLHDSAFromHex(sigHex));
					}
					catch (const InvalidArgument&) {
						// A rejected signature length or malformed input is a
						// failed verification, not a test error.
						result = false;
					}
					if (result != expected) {
						std::cout << "FAILED:  " << name << " " << curName
							<< " expected " << (expected ? "pass" : "fail")
							<< " got " << (result ? "pass" : "fail") << std::endl;
						return false;
					}
					if (expected) coverage[curName].first++;
					else coverage[curName].second++;
					total++;
				}
				pkHex.clear(); msgHex.clear(); ctxHex.clear();
				sigHex.clear(); passedStr.clear();
			}
		}
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}

	// Guard against truncated vector files.
	static const char* const expectedSets[] = {
		"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
		"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
		"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
	};
	for (size_t i = 0; i < COUNTOF(expectedSets); i++) {
		const std::pair<unsigned int, unsigned int>& c = coverage[expectedSets[i]];
		if (c.first == 0 || c.second == 0) {
			std::cout << "FAILED:  " << name << " " << expectedSets[i]
				<< " coverage (" << c.first << " pass, " << c.second
				<< " fail); expected at least one of each" << std::endl;
			return false;
		}
	}

	std::cout << "passed:  " << name << " (" << total << " vectors, "
		<< COUNTOF(expectedSets) << " parameter sets)" << std::endl;
	return true;
}

bool ValidateSLHDSA()
{
	std::cout << "\nSLH-DSA (FIPS 205) validation suite running...\n\n";
	bool pass = true;

	// NIST ACVP external-interface signature verification known-answer tests
	pass = TestSLHDSASigVerKAT() && pass;

	// Context bounds and binding through the external interface
	pass = TestSLHDSAContext<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;

	// Fast 128f variants
	// SHA2 variants
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASaveLoad<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;

	// SHAKE variants
	pass = TestSLHDSAKeyGen<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASaveLoad<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;

	// One small variant
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;

	// Higher security-level size checks
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
		XWingDecapsulator decapsulator(rng);

		SecByteBlock pubKey(XWING_Constants::PUBLIC_KEY_SIZE);
		decapsulator.GetKey().GetPublicKey(pubKey);

		XWingEncapsulator encapsulator(pubKey.begin(), pubKey.size());

		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sharedSecret1(encapsulator.SharedSecretLength());

		encapsulator.Encapsulate(rng, ciphertext, sharedSecret1);

		if (ciphertext.size() != XWING_Constants::CIPHERTEXT_SIZE) {
			std::cout << "FAILED:  X-Wing ciphertext size mismatch" << std::endl;
			return false;
		}

		SecByteBlock sharedSecret2(decapsulator.SharedSecretLength());
		bool success = decapsulator.Decapsulate(ciphertext, sharedSecret2);

		if (!success) {
			std::cout << "FAILED:  X-Wing decapsulation failed" << std::endl;
			return false;
		}

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
		XWingDecapsulator decapsulator(rng);

		SecByteBlock pubKey(XWING_Constants::PUBLIC_KEY_SIZE);
		decapsulator.GetKey().GetPublicKey(pubKey);

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
