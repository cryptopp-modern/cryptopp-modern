// validat12.cpp - written and placed in the public domain by Colin Brown
//                 Stateful hash-based signature validation tests (SP 800-208):
//                 LMS, HSS, and the FileStateStore state backend.

#include <cryptopp/pch.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/validate.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <cryptopp/lms.h>
#include <cryptopp/hss.h>

#include <iostream>
#include <fstream>
#include <cstdio>
#include <limits>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <windows.h>
#endif

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

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
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(LMS_PARAMS::TOTAL_LEAVES);
		LMSSigner<LMS_PARAMS, OTS_PARAMS> signer(privKey, store);

		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string message = "Test message for LMS signature validation";
		SecByteBlock signature(signer.SignatureLength());

		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

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

// Cross-key negative: a signature produced under key A must be rejected
// by a verifier holding key B's public key.
template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSCrossKeyNegative(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privA;
		privA.GenerateRandom(rng, g_nullNameValuePairs);
		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubA;
		privA.MakePublicKey(pubA);

		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privB;
		privB.GenerateRandom(rng, g_nullNameValuePairs);
		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubB;
		privB.MakePublicKey(pubB);

		InsecureMemoryStateStore storeA(LMS_PARAMS::TOTAL_LEAVES);
		LMSSigner<LMS_PARAMS, OTS_PARAMS> signerA(privA, storeA);

		const std::string message = "Cross-key negative test message";
		SecByteBlock signature(signerA.SignatureLength());
		signerA.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifierB(
			pubB.GetPublicKeyBytePtr(), pubB.GetPublicKeyByteLength());
		bool accepted = verifierB.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (accepted) {
			std::cout << "FAILED:  " << name
			          << " cross-key: signature from key A accepted by key B verifier"
			          << std::endl;
			return false;
		}

		// Correct key must still accept.
		LMSVerifier<LMS_PARAMS, OTS_PARAMS> verifierA(
			pubA.GetPublicKeyBytePtr(), pubA.GetPublicKeyByteLength());
		bool acceptedSelf = verifierA.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!acceptedSelf) {
			std::cout << "FAILED:  " << name
			          << " cross-key: self-verification rejected (test setup broken)"
			          << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " cross-key negative" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " cross-key - " << e.what() << std::endl;
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

class FaultyOutOfRangeStore : public SignerStateStore
{
public:
	explicit FaultyOutOfRangeStore(uint64_t outOfRangeIndex)
		: m_outOfRangeIndex(outOfRangeIndex) {}

	StateReservation ReserveNext() override
	{
		return MakeReservation(m_outOfRangeIndex);
	}
	void CommitReservation(const StateReservation &) override {}
	void AbortReservation(const StateReservation &) override {}
	bool IsExhausted() const override { return false; }
	bool IsHealthy() const override { return true; }
	uint64_t RemainingSignatures() const override { return 1; }

private:
	uint64_t m_outOfRangeIndex;
};

class FaultyInvalidReservationStore : public SignerStateStore
{
public:
	StateReservation ReserveNext() override
	{
		StateReservation r = MakeReservation(0);
		StateReservation throwaway(std::move(r));
		CRYPTOPP_UNUSED(throwaway);
		return r;  // moved-from, IsValid() == false
	}
	void CommitReservation(const StateReservation &) override {}
	void AbortReservation(const StateReservation &) override {}
	bool IsExhausted() const override { return false; }
	bool IsHealthy() const override { return true; }
	uint64_t RemainingSignatures() const override { return 1; }
};

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

static bool TestLMSOutOfRangeReservation()
{
	const char* name = "LMS out-of-range reservation";
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		FaultyOutOfRangeStore store(LMS_SHA256_M32_H5::TOTAL_LEAVES);
		LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> signer(privKey, store);

		SecByteBlock signature(signer.SignatureLength());
		const byte msg[] = "out-of-range reservation test";

		bool threw = false;
		try {
			signer.SignMessage(rng, msg, sizeof(msg), signature.begin());
		}
		catch (const SignerStateIntegrityFailure&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name
			          << " did not throw on out-of-range index" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

static bool TestLMSInvalidReservationFromStore()
{
	const char* name = "LMS invalid reservation from store";
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		FaultyInvalidReservationStore store;
		LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> signer(privKey, store);

		SecByteBlock signature(signer.SignatureLength());
		const byte msg[] = "invalid reservation test";

		bool threw = false;
		try {
			signer.SignMessage(rng, msg, sizeof(msg), signature.begin());
		}
		catch (const SignerStateIntegrityFailure&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name
			          << " did not throw on invalid reservation" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
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

static bool TestInsecureMemoryStoreInvalidReservation()
{
	const char* name = "InsecureMemoryStateStore invalid reservation";

	try {
		InsecureMemoryStateStore store(4);

		StateReservation r = store.ReserveNext();
		StateReservation moved(std::move(r));

		bool commitThrew = false;
		try {
			store.CommitReservation(r);
		}
		catch (const SignerStateIntegrityFailure&) {
			commitThrew = true;
		}

		bool abortThrew = false;
		try {
			store.AbortReservation(r);
		}
		catch (const SignerStateIntegrityFailure&) {
			abortThrew = true;
		}

		if (!commitThrew || !abortThrew) {
			std::cout << "FAILED:  " << name
			          << " did not reject moved-from reservation" << std::endl;
			return false;
		}

		// Moved-to reservation remains valid.
		store.CommitReservation(moved);

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSSerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		LMSPrivateKey<LMS_PARAMS, OTS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_PARAMS, OTS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		std::string privDer;
		StringSink privSink(privDer);
		privKey.DEREncode(privSink);

		if (privDer.empty()) {
			std::cout << "FAILED:  " << name << " private key DER encode produced empty output" << std::endl;
			return false;
		}

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

		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.DEREncode(pubSink);

		if (pubDer.empty()) {
			std::cout << "FAILED:  " << name << " public key DER encode produced empty output" << std::endl;
			return false;
		}

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

template <class LMS_PARAMS, class OTS_PARAMS>
static bool TestLMSMalformedSignatures(const char* name)
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

		std::string message = "Malformed signature test message";
		SecByteBlock validSig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin(), validSig.size());
		if (!valid) {
			std::cout << "FAILED:  " << name << " valid signature rejected (setup)" << std::endl;
			return false;
		}

		// Test 1: Truncated signature (too short)
		bool truncatedAccepted = false;
		try {
			truncatedAccepted = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(message.data()), message.size(),
				validSig.begin(), validSig.size() - 1);
		}
		catch (const Exception&) {
			// Throwing on malformed input is acceptable.
			truncatedAccepted = false;
		}
		if (truncatedAccepted) {
			std::cout << "FAILED:  " << name << " truncated signature accepted" << std::endl;
			return false;
		}

		// Test 2: Wrong LMS type ID in signature
		SecByteBlock wrongLmsType(validSig);
		// LMS type is at offset 4 + OTS_sig_len
		size_t lmsTypeOffset = 4 + OTS_PARAMS::SIG_LEN;
		wrongLmsType[lmsTypeOffset] ^= 0x01;
		bool wrongLmsAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			wrongLmsType.begin(), wrongLmsType.size());
		if (wrongLmsAccepted) {
			std::cout << "FAILED:  " << name << " wrong LMS type accepted" << std::endl;
			return false;
		}

		// Test 3: Wrong OTS type ID in signature
		SecByteBlock wrongOtsType(validSig);
		// OTS type is at offset 4 (first 4 bytes of OTS sig)
		wrongOtsType[4] ^= 0x01;
		bool wrongOtsAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			wrongOtsType.begin(), wrongOtsType.size());
		if (wrongOtsAccepted) {
			std::cout << "FAILED:  " << name << " wrong OTS type accepted" << std::endl;
			return false;
		}

		// Test 4: Out-of-range q (>= 2^h)
		SecByteBlock outOfRangeQ(validSig);
		// q is first 4 bytes, set to 0xFF for all bytes (way out of range)
		outOfRangeQ[0] = 0xFF;
		outOfRangeQ[1] = 0xFF;
		outOfRangeQ[2] = 0xFF;
		outOfRangeQ[3] = 0xFF;
		bool outOfRangeAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			outOfRangeQ.begin(), outOfRangeQ.size());
		if (outOfRangeAccepted) {
			std::cout << "FAILED:  " << name << " out-of-range q accepted" << std::endl;
			return false;
		}

		// Test 5: Corrupted auth path (last byte)
		SecByteBlock corruptedPath(validSig);
		corruptedPath[corruptedPath.size() - 1] ^= 0x01;
		bool corruptedAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			corruptedPath.begin(), corruptedPath.size());
		if (corruptedAccepted) {
			std::cout << "FAILED:  " << name << " corrupted auth path accepted" << std::endl;
			return false;
		}

		// Test 6: Corrupted OTS y value (middle of signature)
		SecByteBlock corruptedY(validSig);
		size_t yOffset = 4 + 4 + 32 + 16 * 32;  // middle of y array
		corruptedY[yOffset] ^= 0x01;
		bool corruptedYAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			corruptedY.begin(), corruptedY.size());
		if (corruptedYAccepted) {
			std::cout << "FAILED:  " << name << " corrupted OTS y value accepted" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " malformed signature rejection (6 cases)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " malformed signatures - " << e.what() << std::endl;
		return false;
	}
}

static bool TestLMSSigGenKAT()
{
	const char *name = "LMS ACVP sigGen KAT";

	// Deterministic signing test using ACVP C derivation convention.
	// C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
	// This is the Appendix A formula with reserved index i=65533.
	// Uses keyGen vector tcId=76 (known seed + I + expected public key).

	try {
		const char *seedHex = "A2800F6DEA71A09BAA024F2EB15B34C3E8F42D15BF9818B6D3F8D74C40F5A99D";
		const char *identHex = "DC4C502EF70640EBA7D9F611FC66E5A9";
		const char *expectedPubKeyHex =
			"0000000500000004DC4C502EF70640EBA7D9F611FC66E5A9"
			"335A168B6EA2683E86A8CC2C1173A7A5E120505DE4BAB2E2F0D1B889C486D47F";

		byte seed[32], ident[16];
		typedef LMSPublicKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> PubKeyType;
		const size_t pkSize = PubKeyType::PUBLIC_KEY_SIZE;
		SecByteBlock expectedPK(pkSize);

		if (!HexDecode(seedHex, seed, 32) ||
			!HexDecode(identHex, ident, 16) ||
			!HexDecode(expectedPubKeyHex, expectedPK, pkSize))
		{
			std::cout << "FAILED:  " << name << " hex decode error" << std::endl;
			return false;
		}

		LMSPrivateKey<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> privKey;
		privKey.SetPrivateKey(seed, 32, ident, 16);

		PubKeyType pubKey;
		privKey.MakePublicKey(pubKey);

		// Check the derived public key.
		if (!VerifyBufsEqual(pubKey.GetPublicKeyBytePtr(), expectedPK, pkSize))
		{
			std::cout << "FAILED:  " << name << " public key mismatch" << std::endl;
			return false;
		}

		// Derive C deterministically for q=0 using ACVP convention:
		// C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
		byte C[32];
		{
			SHA256 hash;
			byte buf4[4], buf2[2], buf1[1];
			hash.Update(ident, 16);
			buf4[0] = 0; buf4[1] = 0; buf4[2] = 0; buf4[3] = 0;  // q=0
			hash.Update(buf4, 4);
			buf2[0] = 0xFF; buf2[1] = 0xFD;  // i=65533 = 0xFFFD
			hash.Update(buf2, 2);
			buf1[0] = 0xFF;
			hash.Update(buf1, 1);
			hash.Update(seed, 32);
			hash.TruncatedFinal(C, 32);
		}

		// Sign using FixedRNG that returns the deterministic C
		std::string message = "ACVP sigGen deterministic test";

		InsecureMemoryStateStore store1(32);
		LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> signer1(privKey, store1);

		StringSource cSource1(C, 32, true);
		FixedRNG rng1(cSource1);

		SecByteBlock sig1(signer1.SignatureLength());
		signer1.SignMessage(rng1,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			sig1.begin());

		LMSVerifier<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			sig1.begin(), sig1.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " deterministic signature rejected" << std::endl;
			return false;
		}

		// Sign again with fresh signer and same C - must be bit-exact
		InsecureMemoryStateStore store2(32);
		LMSSigner<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8> signer2(privKey, store2);

		StringSource cSource2(C, 32, true);
		FixedRNG rng2(cSource2);

		SecByteBlock sig2(signer2.SignatureLength());
		signer2.SignMessage(rng2,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			sig2.begin());

		if (!VerifyBufsEqual(sig1, sig2, sig1.size()))
		{
			std::cout << "FAILED:  " << name << " deterministic signing not reproducible" << std::endl;
			return false;
		}

		// Verify C appears in the signature at the expected offset
		// Signature layout: q(4) + OTS_type(4) + C(32) + y[0..33](34*32) + ...
		if (!VerifyBufsEqual(sig1.begin() + 8, C, 32))
		{
			std::cout << "FAILED:  " << name << " C not at expected signature offset" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " (deterministic signing, reproducible, C verified)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

static bool TestLMSSigGenVerifyACVP()
{
	const char *name = "LMS ACVP sigGen verification";

	// Verify signatures from ACVP sigGen vectors (tgId=24, tcId 231-233).
	// Verifies signatures generated by the NIST reference implementation.
	const char *publicKeyHex =
		"0000000500000004A6BCD9E759E4E69708B0463046635752"
		"67DAF41F97B8A2F733ADEE5238DE5D7FD60529475A0A44A21D4C9BEFC9E5B13E";

	struct SigGenVector {
		unsigned int tcId;
		const char *message;
		const char *signature;
	};

	static const SigGenVector vectors[] = {
		{ 231,
			"B897E0D73EE67BEB33267501744470714AE8A2EB075EE19E0765E3BE12AC21EA"
			"7E05F28A5F0BFB688E630A99038377C3F2DA84918FF066AB2140E3394F094E3E"
			"C07984EB07634BCF7A31DC6E0903DEEB9F33C861EAE16403F0FAEDABDA76996B"
			"D2149DE26E17F6BA3C6E73F3F456A50FEBBEB0E87521525D5BF302FE1D873DED",
			"0000000600000004F0DF4DDE6ED3BBF46047D02849CCCEC742D31D5415267DE4"
			"F325DFEDABC35A1637113049BC0DA1FF71630841FADDBA4D7D49F32F4099B718"
			"E8BE229CC6858383C8F379691E2C5F11DCF525BFA4F80EA63F3D33941D5CD94A"
			"E620F40EE17A5B1CC3888441A8C2C7E359AD35D968D5BE9C9EDA32834F21E943"
			"7ED64D1615042F745AE15AC05CE8D459BAA2F7CA44AD0BAE7F43D98607D61AA3"
			"A06997F3D6639717522EA4ABFFE7CC5DF74100A58A2DE3413F2E9348C3B6D466"
			"43A95D588C7A94A42F2BAEB45F1F184CC0F36026A48E164B42B86BD624B4BDC1"
			"64F02D6D4D0465141C23270B38AD42BE94F7DDDA078D34D174FBD043CC1D7F64"
			"0700184DE9E52A8C398C006A55A8A0144D6B272383A3ED0841CF4DA2BE67BE66"
			"DD5CBB9E23AB738C718A8E2082DCE5568785F7F99B9785464452BB07F25E0F1B"
			"CB2938E0B7C2A9E8D3E1AF018089248CB96420CC62753C3FFA568232FF71FBB9"
			"0BCBA9BF0A260C8CA5039168995DD9225EABDC4FF4B1D7F7BDD649A9781BF9FD"
			"3F456AFCD9A7EA03A38DFD38DCCAD850AD3BC64F8378465A42707591827FF9D1"
			"A36F1143C4F930A725CA0505E48B4AF2F71B0F7ADA1931C28617163C586E3823"
			"3EA5BC1FE2783B0B27261298E7378542B473ABACE366784177BD0537D23B25CE"
			"01744F226F6AF8BF382A670B2B92B79691AFC6EEC4FA52F352A331BD1B0EB6D4"
			"33DAAB72FFC426B6BBA18680F344A181315A6E3175F97D9C366C59CC306D110D"
			"B08943D19AE0B9073310AAF3788F70B5BB50F0A4E58D248EC6D4C859E725960F"
			"4106A5D32759AD89B33B602E663CA31F6F5647C38F4666ED877794CF600ED7BD"
			"0E8062376F856BD18242125AED64312826E2CE787448F08CDD3BF6030795C28B"
			"27FF4130EF8EF673054093381298AED21BFDCD35F41553DAF9B977F29081C9EA"
			"10DBF7F345B26442E9BB7B718C1C1AFFCADBC5F2C8BA6249540EA4457E5EB7AA"
			"DFD757EECF692CBF7069F2096700A0071B8C59C456A944ECAB428AB2CFFD27FC"
			"6ED8166C96678F970046AF5044F5B2A30D997307C87208E272DB35909B612AF3"
			"CAF0C0D2495511008BF7AE91066395D9E3D39FD97DEA4792885E90F8F3F6F0C7"
			"D1FC3B1F020E37665CC4C0FFADE1F3F4876A0D2C698859F9DE432915AB45A87C"
			"A5C4045797BB2C8C594CA4F5B89B957817A67CB6A1B0CC353E954DE0A939CC2A"
			"A3159154C1427958F5266270A908969A4C52E92A125B6FCE2C8876B3EF098416"
			"225B7109D89041D4D2B72D3A43CAD90CD2E705ADC1C2D71ECF88478C9031624E"
			"DF134987F43450412AAB57A2A7F6C9DE642372DD676734BFA092476024647596"
			"F23A6ED805B6D6145B0682A367E73F648285B9A74332F3DB704D3F51E23B8780"
			"AE014C24BC11229410526212D390546F7DB0A8B1A7EFECFF55B060CCE1EF5455"
			"C0962F8E2D38C532B9E7CC8EB3FC498D6010B7F83F24B64F775FE4DBDFB72FB2"
			"013702474C77EE49B873C6D3FDAC4ECE4F543A18DD038B6F4010E5DCCC2BBA2F"
			"6F0799E2A4EF8C589C750FBD6C4A466B1C7EEBCAFDE8ACB01BFE15C657093F8"
			"831BEE7403C3D98FF00000005E74BA94580AC8C3D8C0A4CB9BFF0DFDF388D220"
			"61BBB3FA39A50B5C083D6E07C9D50A0B501D282A4702E341A1FE12A86CA48B66"
			"F7865C5203DC6A3DDC1F6DFA959A5AF7FCDFD259757A4443A983BDBC2B9CD9FB"
			"4E0A760A4574CD114CA973173679108730660329F2CDB48AA2945D9F26DB1E44"
			"42F5D4FFB7682523FE1E42758C73A9CE5F00334086D8716C7CF9DC3B54CD53CF"
			"006958D3C4558FA13B5AC1C72"
		},
		{ 233,
			"51CFF9A18DFE10905202F49C81F040546E159B89FF45DB92D49EAA0E1B041DC6"
			"80E08AF25D23CA6D4A3BD87ABF93FAE5EF6F09DD452890DBC156C4586B5ACB2B"
			"7DB4307BD530C477F3E1B28F219DE999F71669E62F9A7AB05C5F23219BBE4EFC"
			"CBF917A82CF2FB59563978BFD9ED3BE4786017B9579625945D5C6ED08A1AB16B",
			"00000000000000042F43F4B5C48BF8770CE5B7E66D203DED1567AC30769DB4EB"
			"F96C4831246BBD96F63C1F55F492D4D31C5FAD6E9705092F73553394500F453F"
			"87F0636A157363629793925B4A01C26D8430D866982B354509F6FA026A8D5BD2"
			"E2BD61FA38076DB60F6E018AE3F1FAC6D3126E49FF9109FED098298C5DCF3D08"
			"BA10DFFE7E9885BEB9B4777D5B83965078E7C15019CB4848C2032AB089396AB1"
			"33D98E3AABFE4E3476C31853E0988F2071D36B72B764788A614550C0D724264"
			"8D27D600DE404F2289632B5E4BEEF478FD861CB61597A4D8DF2D525BC4A1B3D0"
			"641C0F03B1969B3C8396F8AD3D08544BED6BB226251A58898110D780E1F3F6BA"
			"367AC57AF6B43CB9854E48FEED35A4525AD34C2FECC6F12A803BD847A971101C"
			"61E30E244DA1532532D1AED540A5FC314B5437D4599602D1AA441237F434B28E"
			"B92D9890A888736C2555C607ACB7E53CE14E1D42CAD9C73148E3E746B8D358FE"
			"356959832E4F083D64411D05EE143E128301249D2A980CC0689B330E48D5961F"
			"138F2A3DED8B3C135CE49E7E6A0FC94FC95F7D33A43BBEB2C70BF0A90C4B1F8"
			"5F227FC2345DD8F2F989993604E81ABDABC5CFE90BF45E08A57493BCB927F0B1"
			"CD572093F6A0B60ABFEAEF22FA0CA61644304C0DA487709A1DB5C254C3C773E6"
			"87E8CC84D156CEEB37904F2367BFD59199C4BD5641C2F82B5846F41DA615E686"
			"DB37BD1A7F789263AF0D405DF14C03372DEECD40BC3B3B2407340B008ACCE7D3"
			"CA6F806E9EEB6E50FB97BE94427E255B4BBEA359F9C02FD416DF019FA6475145"
			"4EE2CD09176EF1775883F4BC462DC67AD57AAB48749DB5E5DBD019ADE3212626"
			"C0F8AB1FF970E0E829C52B49C4EC41D2D2D4919882084AA9960C5C88EAD0BEF1"
			"8BC7D60AD9611D03264FA74AF27F6481D0BFA3BA14073A570D636A4BF21CDCA2"
			"B14409BC6427CCD9CE070AEE6CFAE561EA5AECC08AB6F19436CDC74E28C9F337"
			"5916780843C6D303E4D4FFAE4EC1E0861F5B7D4E9E4E574459A7726E62A68FA"
			"7FCADA999DB67E3260A6780FDE1D59C3F7DCDD0AFAA7A9A87C7A37A6975B7117"
			"1342C89ABC67626841491D030D9E3AA7A02B8FEF222A561325B9AAC4AA6A65CA"
			"7635DE2770A2BDE32F9A24D6C31C298921313D75512A9E31835201A9C7F45CAF"
			"6B89653C1686D25AA53FF81D7EC04DBC150D82B8ABF152354785C0E6FC00BA85"
			"4EEC09D9F052F2C5C7DEF8FB34DD3FEC94F6D1A63333577C2F8863852632E669"
			"50D19591EDC891F1C34892DB72835E821EE98E17B05E35AAD21FDD5A9A899974"
			"17DB347B91BCE3B478D95F481A3EDF640EEF1E48192C72731D3065F20B25850F"
			"4722F11E19F7E8F43470581DB4809EB937F3807B4478048EE89CAB500BBF56ED"
			"616CFC3E0238EF40F48D965D2396CF5571D3A1D64B3B9482F3FA5DCC01648E18"
			"7F720431221F30CEFE7F88F01A00FA72FC81F028749E1EAED32D93AFEAC6F2A9"
			"DF435960EA67C663FCC4240EB91BB0EF6952EEA20CDA49C5B0DF18AAC6161280"
			"C7711B7A7AE13BAD45A8D6BD506745EEAA48BF70803ED35CB92FED61D9B2829E"
			"F03FFBF4FFC1B1EF9A700000005C352B0C3A2333F0FD9903C97D5D0F049BB623"
			"488ADA9263E6795A1F06ED6C5F501B620C35C6BCB2BAA5B400839F73E3536D25"
			"D338AFD7BDC1D72D5DAB2A37EB44D3AD7C4A7C8C3A1B174CC1B53F5BA3F3092"
			"9C5B1A9F89AFFB708487F2BB1FFB679108730660329F2CDB48AA2945D9F26DB1"
			"E4442F5D4FFB7682523FE1E42758C73A9CE5F00334086D8716C7CF9DC3B54CD5"
			"3CF006958D3C4558FA13B5AC1C72"
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

		for (size_t t = 0; t < 2; t++)
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

			if (!result)
			{
				std::cout << "FAILED:  " << name << " tcId " << vectors[t].tcId
					<< " valid signature rejected" << std::endl;
				return false;
			}
			passed++;
		}

		std::cout << "passed:  " << name << " (" << passed << "/2 vectors)" << std::endl;
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

	// State-store contract tests
	pass = TestLMSStoreContract() && pass;
	pass = TestInsecureMemoryStoreInvalidReservation() && pass;

	// NIST ACVP known-answer tests
	pass = TestLMSKeyGenKAT() && pass;
	pass = TestLMSSigVerKAT() && pass;
	pass = TestLMSSigGenKAT() && pass;
	pass = TestLMSSigGenVerifyACVP() && pass;

	// Functional tests: LMS-SHA256-M32-H5 / LMOTS-SHA256-N32-W8
	pass = TestLMSKeyGen<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSignVerify<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSMultipleSignatures<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSerialization<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSMalformedSignatures<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSCrossKeyNegative<LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;

	// LMS-SHA256-M32-H10 / LMOTS-SHA256-N32-W8
	pass = TestLMSKeyGen<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H10/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSignVerify<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H10/LMOTS-SHA256-N32-W8") && pass;
	pass = TestLMSSerialization<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>(
		"LMS-SHA256-M32-H10/LMOTS-SHA256-N32-W8") && pass;

	// Exhaustion test (H5 = 32 signatures)
	pass = TestLMSExhaustion() && pass;
	pass = TestLMSOutOfRangeReservation() && pass;
	pass = TestLMSInvalidReservationFromStore() && pass;

	return pass;
}

// ******************** HSS Validation (SP 800-208, RFC 8554 Section 6) ************************* //

template <class HSS_PARAMS>
static bool TestHSSKeyGen(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		HSSPrivateKey<HSS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		if (!privKey.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " private key validation" << std::endl;
			return false;
		}

		HSSPublicKey<HSS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		if (!pubKey.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " public key validation" << std::endl;
			return false;
		}

		if (pubKey.GetL() != HSS_PARAMS::L) {
			std::cout << "FAILED:  " << name << " L mismatch" << std::endl;
			return false;
		}

		if (pubKey.GetPublicKeyByteLength() != HSS_PARAMS::PublicKeySize()) {
			std::cout << "FAILED:  " << name << " public key size" << std::endl;
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

template <class HSS_PARAMS>
static bool TestHSSSignVerify(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		HSSPrivateKey<HSS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<HSS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(HSS_PARAMS::TotalSignatures());
		HSSSigner<HSS_PARAMS> signer(privKey, store);

		HSSVerifier<HSS_PARAMS> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string message = "Test message for HSS signature validation";
		SecByteBlock signature(signer.SignatureLength());

		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " valid signature rejected" << std::endl;
			return false;
		}

		// Modified message should fail
		std::string modified = "Modified message for HSS signature";
		bool invalidAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(modified.data()), modified.size(),
			signature.begin(), signature.size());

		if (invalidAccepted) {
			std::cout << "FAILED:  " << name << " modified message incorrectly verified" << std::endl;
			return false;
		}

		// Mutated signature should fail
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

// HSS cross-key negative; see the LMS test above for rationale.
template <class HSS_PARAMS>
static bool TestHSSCrossKeyNegative(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		HSSPrivateKey<HSS_PARAMS> privA;
		privA.GenerateRandom(rng, g_nullNameValuePairs);
		HSSPublicKey<HSS_PARAMS> pubA;
		privA.MakePublicKey(pubA);

		HSSPrivateKey<HSS_PARAMS> privB;
		privB.GenerateRandom(rng, g_nullNameValuePairs);
		HSSPublicKey<HSS_PARAMS> pubB;
		privB.MakePublicKey(pubB);

		InsecureMemoryStateStore storeA(HSS_PARAMS::TotalSignatures());
		HSSSigner<HSS_PARAMS> signerA(privA, storeA);

		const std::string message = "Cross-key negative test message";
		SecByteBlock signature(signerA.SignatureLength());
		signerA.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		HSSVerifier<HSS_PARAMS> verifierB(
			pubB.GetPublicKeyBytePtr(), pubB.GetPublicKeyByteLength());
		bool accepted = verifierB.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (accepted) {
			std::cout << "FAILED:  " << name
			          << " cross-key: signature from key A accepted by key B verifier"
			          << std::endl;
			return false;
		}

		// Correct key must still accept.
		HSSVerifier<HSS_PARAMS> verifierA(
			pubA.GetPublicKeyBytePtr(), pubA.GetPublicKeyByteLength());
		bool acceptedSelf = verifierA.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!acceptedSelf) {
			std::cout << "FAILED:  " << name
			          << " cross-key: self-verification rejected (test setup broken)"
			          << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " cross-key negative" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " cross-key - " << e.what() << std::endl;
		return false;
	}
}

template <class HSS_PARAMS>
static bool TestHSSMultipleSignatures(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		HSSPrivateKey<HSS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<HSS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(HSS_PARAMS::TotalSignatures());
		HSSSigner<HSS_PARAMS> signer(privKey, store);
		HSSVerifier<HSS_PARAMS> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		const unsigned int count = 5;
		SecByteBlock signature(signer.SignatureLength());

		for (unsigned int i = 0; i < count; i++)
		{
			std::string msg = "HSS message number " + std::to_string(i);
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " signature " << i << " rejected" << std::endl;
				return false;
			}
		}

		uint64_t remaining = signer.RemainingSignatures();
		if (remaining != HSS_PARAMS::TotalSignatures() - count) {
			std::cout << "FAILED:  " << name << " remaining count " << remaining
				<< " != " << (HSS_PARAMS::TotalSignatures() - count) << std::endl;
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

static bool TestHSSSubtreeBoundary()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(signer.SignatureLength());

		// Sign 32 messages (exhausts bottom-level subtree 0)
		for (unsigned int i = 0; i < Params::LeavesAt<0>(); i++)
		{
			std::string msg = "Subtree boundary test msg " + std::to_string(i);
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " subtree boundary - signature " << i << " rejected" << std::endl;
				return false;
			}
		}

		// Signature 33 (index 32) crosses into subtree 1 - new child tree
		std::string crossMsg = "First message in new subtree";
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(crossMsg.data()), crossMsg.size(),
			signature.begin());

		bool crossValid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(crossMsg.data()), crossMsg.size(),
			signature.begin(), signature.size());

		if (!crossValid) {
			std::cout << "FAILED:  " << name
				<< " subtree boundary - first-in-new-subtree rejected" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " subtree boundary (33 sigs across 2 subtrees)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " subtree boundary - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSSignerReconstruction()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(Params::SignatureSize());

		// Sign 5 messages with first signer
		{
			HSSSigner<Params> signer1(privKey, store);
			for (unsigned int i = 0; i < 5; i++)
			{
				std::string msg = "Reconstruction test msg " + std::to_string(i);
				signer1.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin());
			}
		}
		// signer1 is now destroyed

		// Reconstruct a new signer from same key + store
		{
			HSSSigner<Params> signer2(privKey, store);
			std::string msg = "Message after reconstruction";
			signer2.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " reconstruction - post-restart signature rejected" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " signer reconstruction" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " reconstruction - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSReconstructionAtBoundary()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(Params::SignatureSize());

		// Sign up to the subtree boundary (32 sigs = exhaust subtree 0)
		{
			HSSSigner<Params> signer1(privKey, store);
			for (unsigned int i = 0; i < Params::LeavesAt<0>(); i++)
			{
				std::string msg = "Boundary recon msg " + std::to_string(i);
				signer1.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin());
			}
		}
		// signer1 destroyed at subtree boundary

		// Reconstruct - next signature crosses into subtree 1
		{
			HSSSigner<Params> signer2(privKey, store);
			std::string msg = "First message after boundary reconstruction";
			signer2.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " boundary reconstruction - cross-boundary signature rejected" << std::endl;
				return false;
			}

			// One more in the new subtree
			std::string msg2 = "Second message in new subtree after reconstruction";
			signer2.SignMessage(rng,
				reinterpret_cast<const byte*>(msg2.data()), msg2.size(),
				signature.begin());

			valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg2.data()), msg2.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " boundary reconstruction - second post-boundary signature rejected" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " reconstruction at subtree boundary" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " boundary reconstruction - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSExhaustion()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;
		const uint64_t total = Params::TotalSignatures();  // 1024

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(total);
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(signer.SignatureLength());

		for (uint64_t i = 0; i < total; i++)
		{
			std::string msg = "Exhaustion msg " + std::to_string(i);
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " exhaustion - signature " << i << " rejected" << std::endl;
				return false;
			}
		}

		if (!signer.IsExhausted()) {
			std::cout << "FAILED:  " << name << " not exhausted after " << total << " sigs" << std::endl;
			return false;
		}

		if (signer.RemainingSignatures() != 0) {
			std::cout << "FAILED:  " << name << " remaining != 0" << std::endl;
			return false;
		}

		// 1025th signature should throw
		bool threw = false;
		try {
			std::string msg = "One too many";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());
		}
		catch (const SignerExhausted&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name << " did not throw SignerExhausted" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " exhaustion (" << total
			<< " sigs, " << (total + 1) << "th throws)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " exhaustion - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSOutOfRangeReservation()
{
	const char* name = "HSS out-of-range reservation";
	AutoSeededRandomPool rng;

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		FaultyOutOfRangeStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);

		SecByteBlock signature(signer.SignatureLength());
		const byte msg[] = "out-of-range reservation test";

		bool threw = false;
		try {
			signer.SignMessage(rng, msg, sizeof(msg), signature.begin());
		}
		catch (const SignerStateIntegrityFailure&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name
			          << " did not throw on out-of-range index" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSInvalidReservationFromStore()
{
	const char* name = "HSS invalid reservation from store";
	AutoSeededRandomPool rng;

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		FaultyInvalidReservationStore store;
		HSSSigner<Params> signer(privKey, store);

		SecByteBlock signature(signer.SignatureLength());
		const byte msg[] = "invalid reservation test";

		bool threw = false;
		try {
			signer.SignMessage(rng, msg, sizeof(msg), signature.begin());
		}
		catch (const SignerStateIntegrityFailure&) {
			threw = true;
		}

		if (!threw) {
			std::cout << "FAILED:  " << name
			          << " did not throw on invalid reservation" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

template <class HSS_PARAMS>
static bool TestHSSSerialization(const char* name)
{
	AutoSeededRandomPool rng;

	try {
		HSSPrivateKey<HSS_PARAMS> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<HSS_PARAMS> pubKey;
		privKey.MakePublicKey(pubKey);

		std::string pubDer;
		StringSink pubSink(pubDer);
		pubKey.DEREncode(pubSink);

		HSSPublicKey<HSS_PARAMS> decodedPub;
		StringSource pubSource(pubDer, true);
		decodedPub.BERDecode(pubSource);

		if (!decodedPub.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " decoded public key validation" << std::endl;
			return false;
		}

		// Verify decoded public key matches original
		if (decodedPub.GetPublicKeyByteLength() != pubKey.GetPublicKeyByteLength() ||
			!VerifyBufsEqual(decodedPub.GetPublicKeyBytePtr(),
				pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength())) {
			std::cout << "FAILED:  " << name << " public key round-trip mismatch" << std::endl;
			return false;
		}

		std::string privDer;
		StringSink privSink(privDer);
		privKey.DEREncode(privSink);

		HSSPrivateKey<HSS_PARAMS> decodedPriv;
		StringSource privSource(privDer, true);
		decodedPriv.BERDecode(privSource);

		if (!decodedPriv.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " decoded private key validation" << std::endl;
			return false;
		}

		// Sign with decoded key, verify with decoded public key
		InsecureMemoryStateStore store(HSS_PARAMS::TotalSignatures());
		HSSSigner<HSS_PARAMS> signer(decodedPriv, store);
		HSSVerifier<HSS_PARAMS> verifier(
			decodedPub.GetPublicKeyBytePtr(), decodedPub.GetPublicKeyByteLength());

		std::string message = "Serialisation round-trip test";
		SecByteBlock signature(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			signature.begin(), signature.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " post-deserialisation sign/verify" << std::endl;
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

static bool TestHSSRFCAppendixFTC1()
{
	// RFC 8554 Appendix F, Test Case 1 (Cisco hash-sigs reference)
	// L=2, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8
	const char* name = "HSS RFC 8554 Appendix F TC1";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		// Public key (60 bytes)
		const char* pkHex =
			"00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b8"
			"50650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da043"
			"4cb2b878";

		// Message: "The powers not delegated to the United States..."
		const char* msgHex =
			"54686520706f77657273206e6f742064656c65676174656420746f20"
			"74686520556e69746564205374617465732062792074686520436f6e"
			"737469747574696f6e2c206e6f722070726f68696269746564206279"
			"20697420746f20746865205374617465732c20617265207265736572"
			"76656420746f20746865205374617465732072657370656374697665"
			"6c792c206f7220746f207468652070656f706c652e0a";

		// Signature (2644 bytes) - only first and last fragments shown in source,
		// full hex assembled from Cisco test_testvector.c
		const char* sigHex =
			"000000010000000500000004d32b56671d7eb98833c49b433c272586"
			"bc4a1c8a8970528ffa04b966f9426eb9965a25bfd37f196b9073f3d4"
			"a232feb69128ec45146f86292f9dff9610a7bf95a64c7f60f6261a62"
			"043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0e05fd5c6"
			"509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2"
			"582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83"
			"a4943d1681d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2"
			"518eb20de2f66e3b14784269d7d876f5d35d3fbfc7039a462c716bb9"
			"f6891a7f41ad133e9e1f6d9560b960e7777c52f060492f2d7c660e14"
			"71e07e72655562035abc9a701b473ecbc3943c6b9c4f2405a3cb8bf8"
			"a691ca51d3f6ad2f428bab6f3a30f55dd9625563f0a75ee390e385e3"
			"ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c35b167b2"
			"8ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1"
			"e783ed04516de012498682212b07810579b250365941bcc98142da13"
			"609e9768aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb"
			"8dec2fc0e7f932701099762b37f43c4a3c20010a3d72e2f606be108d"
			"310e639f09ce7286800d9ef8a1a40281cc5a7ea98d2adc7c7400c2fe"
			"5a101552df4e3cccfd0cbf2ddf5dc6779cbbc68fee0c3efe4ec22b83"
			"a2caa3e48e0809a0a750b73ccdcf3c79e6580c154f8a58f7f24335ee"
			"c5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27c5b9f64a"
			"2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8"
			"26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603"
			"f2df56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403"
			"466b1afe78b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf"
			"947f698ce9c6ceb696ed70e9e87b0144417e8d7baf25eb5f70f09f01"
			"6fc925b4db048ab8d8cb2a661ce3b57ada67571f5dd546fc22cb1f97"
			"e0ebd1a65926b1234fd04f171cf469c76b884cf3115cce6f792cc84e"
			"36da58960c5f1d760f32c12faef477e94c92eb75625b6a371efc72d6"
			"0ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072"
			"c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da"
			"252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0a"
			"f1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b73"
			"00e882360a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f4884"
			"31606cb13f9241f40f44e537d302c64a4f1f4ab949b9feefadcb71ab"
			"50ef27d6d6ca8510f150c85fb525bf25703df7209b6066f09c37280d"
			"59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77b7c878c9"
			"411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6"
			"d76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96ae"
			"fee67676401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f0862"
			"78dd8ad0686078dfb0f3f79cd893d314168648499898fbc0ced5f95b"
			"74e8ff14d735cdea968bee7400000005d8b8112f9200a5e50c4a2621"
			"65bd342cd800b8496810bc716277435ac376728d129ac6eda839a6f3"
			"57b5a04387c5ce97382a78f2a4372917eefcbf93f63bb59112f5dbe4"
			"00bd49e4501e859f885bf0736e90a509b30a26bfac8c17b5991c157e"
			"b5971115aa39efd8d564a6b90282c3168af2d30ef89d51bf14654510"
			"a12b8a144cca1848cf7da59cc2b3d9d0692dd2a20ba3863480e25b1b"
			"85ee860c62bf51360000000500000004d2f14ff6346af964569f7d6c"
			"b880a1b66c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15"
			"cda93cfec582d7ab0000000a000000040703c491e7558b35011ece35"
			"92eaa5da4d918786771233e8353bc4f62323185c95cae05b899e35df"
			"fd717054706209988ebfdf6e37960bb5c38d7657e8bffeef9bc042da"
			"4b4525650485c66d0ce19b317587c6ba4bffcc428e25d08931e72dfb"
			"6a120c5612344258b85efdb7db1db9e1865a73caf96557eb39ed3e3f"
			"426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23"
			"f846df26fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a3"
			"73b98288b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f"
			"5ebe48f584d7159b8ada03586e65ad9c969f6aecbfe44cf356888a7b"
			"15a3ff074f771760b26f9c04884ee1faa329fbf4e61af23aee7fa5d4"
			"d9a5dfcf43c4c26ce8aea2ce8a2990d7ba7b57108b47dabfbeadb2b2"
			"5b3cacc1ac0cef346cbb90fb044beee4fac2603a442bdf7e507243b7"
			"319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2315f3d36"
			"ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd"
			"61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e4"
			"8a0e729f9184fcb1407c31529db268f6fe50032a363c9801306837fa"
			"fabdf957fd97eafc80dbd165e435d0e2dfd836a28b354023924b6fb7"
			"e48bc0b3ed95eea64c2d402f4d734c8dc26f3ac591825daef01eae3c"
			"38e3328d00a77dc657034f287ccb0f0e1c9a7cbdc828f627205e4737"
			"b84b58376551d44c12c3c215c812a0970789c83de51d6ad787271963"
			"327f0a5fbb6b5907dec02c9a90934af5a1c63b72c82653605d1dcce5"
			"1596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc"
			"2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182d"
			"e994cff192ec0e82fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1"
			"c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2c"
			"c06fa8c82bed4d944e71339ece780fd025bd41ec34ebff9d4270a322"
			"4e019fcb444474d482fd2dbe75efb20389cc10cd600abb54c47ede93"
			"e08c114edb04117d714dc1d525e11bed8756192f929d15462b939ff3"
			"f52f2252da2ed64d8fae88818b1efa2c7b08c8794fb1b214aa233db3"
			"162833141ea4383f1a6f120be1db82ce3630b342911446315"
			"7a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6aa"
			"d2831db61274993715a0182c7dc8089e32c8531deed4f7431c07c021"
			"95eba2ef91efb5613c37af7ae0c066babc69369700e1dd26eddc0d21"
			"6c781d56e4ce47e3303fa73007ff7b949ef23be2aa4dbf25206fe45c"
			"20dd888395b2526391a724996a44156beac808212858792bf8e74cba"
			"49dee5e8812e019da87454bff9e847ed83db07af313743082f880a27"
			"8f682c2bd0ad6887cb59f652e155987d61bbf6a88d36ee93b6072e66"
			"56d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3b3539eb77"
			"b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826f"
			"0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5"
			"b5806163d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2"
			"c6cef305b3ed633941ebc8b3bec9738754cddd60e1920ada52f43d05"
			"5b5031cee6192520d6a5115514851ce7fd448d4a39fae2ab2335b525"
			"f484e9b40d6a4a969394843bdcf6d14c48e8015e08ab92662c05c6e9"
			"f90b65a7a6201689999f32bfd368e5e3ec9cb70ac7b8399003f175c4"
			"0885081a09ab3034911fe125631051df0408b3946b0bde790911e897"
			"8ba07dd56c73e7ee";

		std::string pkStr, msgStr, sigStr;
		StringSource(pkHex, true, new HexDecoder(new StringSink(pkStr)));
		StringSource(msgHex, true, new HexDecoder(new StringSink(msgStr)));
		StringSource(sigHex, true, new HexDecoder(new StringSink(sigStr)));

		if (pkStr.size() != Params::PublicKeySize()) {
			std::cout << "FAILED:  " << name << " public key size " << pkStr.size()
				<< " != " << Params::PublicKeySize() << std::endl;
			return false;
		}
		if (sigStr.size() != Params::SignatureSize()) {
			std::cout << "FAILED:  " << name << " signature size " << sigStr.size()
				<< " != " << Params::SignatureSize() << std::endl;
			return false;
		}

		HSSVerifier<Params> verifier(
			reinterpret_cast<const byte*>(pkStr.data()), pkStr.size());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(msgStr.data()), msgStr.size(),
			reinterpret_cast<const byte*>(sigStr.data()), sigStr.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " signature verification" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " verification" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSMalformedSignatures()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		// Produce a valid signature
		std::string message = "Message for malformed signature tests";
		SecByteBlock validSig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin());

		// Check the baseline signature first.
		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin(), validSig.size());
		if (!valid) {
			std::cout << "FAILED:  " << name << " valid sig rejected (sanity)" << std::endl;
			return false;
		}

		// HSS sig layout for L=2 H5 W8:
		// [0..3]       Nspk (4 bytes, value = 1)
		// [4..1295]    intermediate LMS sig (1292 bytes)
		// [1296..1351] intermediate LMS pub key (56 bytes)
		// [1352..2643] final LMS sig (1292 bytes)
		const size_t lmsSigSize = Params::LMSSignatureSizeAt<0>();   // 1292
		const size_t lmsPubSize = Params::LMSPublicKeySizeAt<0>();   // 56
		unsigned int rejected = 0;

		// 1. Wrong Nspk (set to 0 instead of 1)
		{
			SecByteBlock bad(validSig);
			bad[0] = 0; bad[1] = 0; bad[2] = 0; bad[3] = 0;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " wrong Nspk accepted" << std::endl;
				return false;
			}
		}

		// 2. Wrong Nspk (set to 2 instead of 1)
		{
			SecByteBlock bad(validSig);
			bad[0] = 0; bad[1] = 0; bad[2] = 0; bad[3] = 2;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " Nspk=2 accepted" << std::endl;
				return false;
			}
		}

		// 3. Corrupted intermediate LMS signature (flip byte in middle)
		{
			SecByteBlock bad(validSig);
			bad[4 + lmsSigSize / 2] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " corrupted intermediate sig accepted" << std::endl;
				return false;
			}
		}

		// 4. Wrong intermediate public key LMS type ID
		{
			SecByteBlock bad(validSig);
			size_t pubOffset = 4 + lmsSigSize;  // start of intermediate pub key
			bad[pubOffset] ^= 0x01;  // corrupt LMS type byte
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " wrong intermediate LMS type accepted" << std::endl;
				return false;
			}
		}

		// 5. Wrong intermediate public key OTS type ID
		{
			SecByteBlock bad(validSig);
			size_t pubOffset = 4 + lmsSigSize + 4;  // OTS type within intermediate pub key
			bad[pubOffset] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " wrong intermediate OTS type accepted" << std::endl;
				return false;
			}
		}

		// 6. Corrupted intermediate public key root (T[1])
		{
			SecByteBlock bad(validSig);
			size_t rootOffset = 4 + lmsSigSize + lmsPubSize - 1;  // last byte of intermediate pub key
			bad[rootOffset] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " corrupted intermediate key accepted" << std::endl;
				return false;
			}
		}

		// 7. Corrupted final LMS signature (flip byte in middle)
		{
			SecByteBlock bad(validSig);
			size_t finalOffset = 4 + lmsSigSize + lmsPubSize;  // start of final LMS sig
			bad[finalOffset + lmsSigSize / 2] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " corrupted final sig accepted" << std::endl;
				return false;
			}
		}

		// 8. Out-of-range q in final LMS signature
		{
			SecByteBlock bad(validSig);
			size_t finalOffset = 4 + lmsSigSize + lmsPubSize;  // q is first 4 bytes of final LMS sig
			bad[finalOffset] = 0xFF;  // q = 0xFF?????? >= 2^5
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " out-of-range final q accepted" << std::endl;
				return false;
			}
		}

		// 9. Tampered C nonce in final LMS signature
		{
			SecByteBlock bad(validSig);
			size_t finalOffset = 4 + lmsSigSize + lmsPubSize;
			size_t cOffset = finalOffset + 4 + 4;
			bad[cOffset + 16] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " tampered C nonce accepted" << std::endl;
				return false;
			}
		}

		// 10. Embedded pubkey_1 substituted with a structurally valid pubkey from a different HSS key
		{
			HSSPrivateKey<Params> otherPriv;
			otherPriv.GenerateRandom(rng, g_nullNameValuePairs);
			InsecureMemoryStateStore otherStore(Params::TotalSignatures());
			HSSSigner<Params> otherSigner(otherPriv, otherStore);
			SecByteBlock otherSig(otherSigner.SignatureLength());
			otherSigner.SignMessage(rng,
				reinterpret_cast<const byte*>(message.data()), message.size(),
				otherSig.begin());

			SecByteBlock bad(validSig);
			size_t pubOffset = 4 + lmsSigSize;
			for (size_t i = 0; i < lmsPubSize; i++)
				bad[pubOffset + i] = otherSig[pubOffset + i];

			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name << " substituted pubkey_1 accepted" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " malformed signature rejection (" << rejected << " cases)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " malformed signatures - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSSafeFailure()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(Params::SignatureSize());

		// Sign 3 messages normally
		{
			HSSSigner<Params> signer(privKey, store);
			for (unsigned int i = 0; i < 3; i++)
			{
				std::string msg = "Safe failure pre-msg " + std::to_string(i);
				signer.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin());
			}
		}
		// signer destroyed after 3 sigs. Remaining = 1024 - 3 = 1021

		uint64_t remainingBefore = store.RemainingSignatures();
		if (remainingBefore != Params::TotalSignatures() - 3) {
			std::cout << "FAILED:  " << name << " safe failure - wrong count before abort" << std::endl;
			return false;
		}

		// Simulate failure after ReserveNext() and before CommitReservation().
		{
			StateReservation reservation = store.ReserveNext();
			store.AbortReservation(reservation);
			// Index 3 is burned and not reissued.
		}

		uint64_t remainingAfter = store.RemainingSignatures();
		if (remainingAfter != remainingBefore - 1) {
			std::cout << "FAILED:  " << name
				<< " safe failure - abort did not burn capability ("
				<< remainingAfter << " vs expected " << (remainingBefore - 1) << ")" << std::endl;
			return false;
		}

		// Next normal signature (index 4) must still work
		{
			HSSSigner<Params> signer2(privKey, store);
			std::string msg = "Message after aborted reservation";
			signer2.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin(), signature.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " safe failure - post-abort signature rejected" << std::endl;
				return false;
			}

			// Remaining should be 1024 - 3 - 1(abort) - 1(sign) = 1019
			if (signer2.RemainingSignatures() != Params::TotalSignatures() - 5) {
				std::cout << "FAILED:  " << name
					<< " safe failure - wrong remaining after abort+sign" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " safe failure (abort burns capability)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " safe failure - " << e.what() << std::endl;
		return false;
	}
}

// ******************** HSS L=3 Tests ************************* //

static bool TestHSSL3SignVerify()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[3]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L3_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		if (!pubKey.Validate(NullRNG(), 0)) {
			std::cout << "FAILED:  " << name << " public key validation" << std::endl;
			return false;
		}

		if (pubKey.GetL() != 3) {
			std::cout << "FAILED:  " << name << " L != 3" << std::endl;
			return false;
		}

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string msg = "L=3 HSS test message";
		SecByteBlock sig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(msg.data()), msg.size(),
			sig.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(msg.data()), msg.size(),
			sig.begin(), sig.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " signature rejected" << std::endl;
			return false;
		}

		// Modified message rejected
		std::string bad = "L=3 HSS test messagX";
		bool badAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(bad.data()), bad.size(),
			sig.begin(), sig.size());

		if (badAccepted) {
			std::cout << "FAILED:  " << name << " modified message accepted" << std::endl;
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

static bool TestHSSL3SubtreeBoundary()
{
	// L=3 H5: bottom subtree boundary at 32 sigs.
	// Sign 33 messages - the 33rd crosses into a new bottom subtree
	// within the same mid-level subtree.
	AutoSeededRandomPool rng;
	const char* name = "HSS[3]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L3_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(signer.SignatureLength());

		// Sign 33 messages (crosses bottom subtree boundary)
		for (unsigned int i = 0; i < 33; i++)
		{
			std::string msg = "L3 boundary msg " + std::to_string(i);
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " subtree boundary - sig " << i << " rejected" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name
			<< " bottom subtree boundary (33 sigs)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " subtree boundary - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSL3Reconstruction()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[3]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L3_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(Params::SignatureSize());

		// Sign 5 with first signer, then destroy it
		{
			HSSSigner<Params> signer1(privKey, store);
			for (unsigned int i = 0; i < 5; i++)
			{
				std::string msg = "L3 recon pre " + std::to_string(i);
				signer1.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin());
			}
		}

		// Reconstruct and sign across bottom subtree boundary
		// (sign 28 more to reach index 33, crossing the boundary at 32)
		{
			HSSSigner<Params> signer2(privKey, store);
			for (unsigned int i = 5; i < 34; i++)
			{
				std::string msg = "L3 recon post " + std::to_string(i);
				signer2.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin());

				bool valid = verifier.VerifyMessage(
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin(), sig.size());

				if (!valid) {
					std::cout << "FAILED:  " << name
						<< " reconstruction - sig " << i << " rejected" << std::endl;
					return false;
				}
			}
		}

		std::cout << "passed:  " << name
			<< " reconstruction across bottom subtree boundary" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " reconstruction - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSL3SafeFailure()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS[3]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L3_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(Params::SignatureSize());

		// Sign 3 normally
		{
			HSSSigner<Params> signer(privKey, store);
			for (unsigned int i = 0; i < 3; i++)
			{
				std::string msg = "L3 safe failure msg " + std::to_string(i);
				signer.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin());
			}
		}

		// Simulate failure: reserve + abort
		uint64_t before = store.RemainingSignatures();
		{
			StateReservation r = store.ReserveNext();
			store.AbortReservation(r);
		}
		uint64_t after = store.RemainingSignatures();

		if (after != before - 1) {
			std::cout << "FAILED:  " << name << " safe failure - abort did not burn" << std::endl;
			return false;
		}

		// Next signature still works
		{
			HSSSigner<Params> signer(privKey, store);
			std::string msg = "L3 after abort";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " safe failure - post-abort sig rejected" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " safe failure (abort burns capability)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " safe failure - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSL3MalformedSignatures()
{
	// L=3-specific: tamper sig_1 and pubkey_2 (positions only present at L>=3).
	AutoSeededRandomPool rng;
	const char* name = "HSS[3]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L3_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string message = "L=3 malformed signature test";
		SecByteBlock validSig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin(), validSig.size());
		if (!valid) {
			std::cout << "FAILED:  " << name << " valid sig rejected (sanity)" << std::endl;
			return false;
		}

		// L=3 sig layout: Nspk (4) + 2 * (intermediate_sig + intermediate_pubkey) + final_sig.
		// sig_0 (root -> L1)  at offset 4
		// pubkey_1            at offset 4 + lmsSigSize
		// sig_1 (L1 -> L2)    at offset 4 + lmsSigSize + lmsPubSize     <-- middle intermediate sig
		// pubkey_2            at offset 4 + 2*lmsSigSize + lmsPubSize   <-- layer-2 pubkey
		// final sig (L2 -> M) at offset 4 + 2*lmsSigSize + 2*lmsPubSize
		const size_t lmsSigSize = Params::LMSSignatureSizeAt<0>();
		const size_t lmsPubSize = Params::LMSPublicKeySizeAt<0>();
		unsigned int rejected = 0;

		// Tamper middle intermediate sig (sig_1)
		{
			SecByteBlock bad(validSig);
			size_t sig1Offset = 4 + lmsSigSize + lmsPubSize;
			bad[sig1Offset + lmsSigSize / 2] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name
					<< " middle intermediate sig tamper accepted" << std::endl;
				return false;
			}
		}

		// Tamper layer-2 pubkey (pubkey_2) LMS type byte
		{
			SecByteBlock bad(validSig);
			size_t pub2Offset = 4 + 2 * lmsSigSize + lmsPubSize;
			bad[pub2Offset] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name
					<< " layer-2 pubkey tamper accepted" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name
			<< " L=3 malformed signature rejection (" << rejected << " cases)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " L=3 malformed - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSL4SignVerify()
{
	// Smoke test that L=4 compiles, signs, and verifies. Exercises the
	// LEVELS <= 4 ceiling enforced by static_assert in HSS_Params.
	AutoSeededRandomPool rng;
	const char* name = "HSS[4]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L4_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		if (!pubKey.Validate(NullRNG(), 0)) {
			std::cout << "FAILED:  " << name << " public key validation" << std::endl;
			return false;
		}

		if (pubKey.GetL() != 4) {
			std::cout << "FAILED:  " << name << " L != 4" << std::endl;
			return false;
		}

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string msg = "L=4 HSS test message";
		SecByteBlock sig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(msg.data()), msg.size(),
			sig.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(msg.data()), msg.size(),
			sig.begin(), sig.size());

		if (!valid) {
			std::cout << "FAILED:  " << name << " signature rejected" << std::endl;
			return false;
		}

		std::string bad = "L=4 HSS test messagX";
		bool badAccepted = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(bad.data()), bad.size(),
			sig.begin(), sig.size());

		if (badAccepted) {
			std::cout << "FAILED:  " << name << " modified message accepted" << std::endl;
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

static bool TestHSSL4MiddleBoundary()
{
	// L=4 H5: layer-2 -> layer-1 cursor advance at sig 1025.
	// Signs 1025 messages so the 1025th forces a layer-1 advance
	// (layer-2 subtree 0 is exhausted after 1024 sigs).
	AutoSeededRandomPool rng;
	const char* name = "HSS[4]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L4_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(signer.SignatureLength());

		for (unsigned int i = 0; i < 1025; i++)
		{
			std::string msg = "L4 middle boundary msg " + std::to_string(i);
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name
					<< " middle boundary - sig " << i << " rejected" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name
			<< " layer-2 boundary (1025 sigs)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " middle boundary - " << e.what() << std::endl;
		return false;
	}
}

static bool TestHSSL4MalformedSignatures()
{
	// L=4-specific: tamper sig_2 and pubkey_2 (positions only present at L>=4).
	AutoSeededRandomPool rng;
	const char* name = "HSS[4]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8";

	try {
		typedef HSS_SHA256_H5_W8_L4_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSSigner<Params> signer(privKey, store);
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		std::string message = "L=4 malformed signature test";
		SecByteBlock validSig(signer.SignatureLength());
		signer.SignMessage(rng,
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin());

		bool valid = verifier.VerifyMessage(
			reinterpret_cast<const byte*>(message.data()), message.size(),
			validSig.begin(), validSig.size());
		if (!valid) {
			std::cout << "FAILED:  " << name << " valid sig rejected (sanity)" << std::endl;
			return false;
		}

		// L=4 sig layout: Nspk (4) + 3 * (intermediate_sig + intermediate_pubkey) + final_sig.
		// sig_0 (root -> L1)  at offset 4
		// pubkey_1            at offset 4 + lmsSigSize
		// sig_1 (L1  -> L2)   at offset 4 + lmsSigSize + lmsPubSize
		// pubkey_2            at offset 4 + 2*lmsSigSize + lmsPubSize   <-- layer-2 pubkey
		// sig_2 (L2  -> L3)   at offset 4 + 2*lmsSigSize + 2*lmsPubSize <-- depth-3 intermediate sig
		// pubkey_3            at offset 4 + 3*lmsSigSize + 2*lmsPubSize
		// final sig (L3 -> M) at offset 4 + 3*lmsSigSize + 3*lmsPubSize
		const size_t lmsSigSize = Params::LMSSignatureSizeAt<0>();
		const size_t lmsPubSize = Params::LMSPublicKeySizeAt<0>();
		unsigned int rejected = 0;

		// Tamper depth-3 intermediate sig (sig_2)
		{
			SecByteBlock bad(validSig);
			size_t sig2Offset = 4 + 2 * lmsSigSize + 2 * lmsPubSize;
			bad[sig2Offset + lmsSigSize / 2] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name
					<< " depth-3 intermediate sig tamper accepted" << std::endl;
				return false;
			}
		}

		// Tamper layer-2 pubkey (pubkey_2) LMS type byte
		{
			SecByteBlock bad(validSig);
			size_t pub2Offset = 4 + 2 * lmsSigSize + lmsPubSize;
			bad[pub2Offset] ^= 0x01;
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(message.data()), message.size(),
					bad.begin(), bad.size()))
				rejected++;
			else {
				std::cout << "FAILED:  " << name
					<< " layer-2 pubkey tamper accepted" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name
			<< " L=4 malformed signature rejection (" << rejected << " cases)" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " L=4 malformed - " << e.what() << std::endl;
		return false;
	}
}

// Check that the variadic HSS typedefs keep the existing uniform sizes.
static_assert(HSS_SHA256_H5_W8_L2_Params::LMSSignatureSizeAt<0>() ==
              HSS_SHA256_H5_W8_L2_Params::LMSSignatureSizeAt<1>() &&
              HSS_SHA256_H5_W8_L2_Params::LMSPublicKeySizeAt<0>() ==
              HSS_SHA256_H5_W8_L2_Params::LMSPublicKeySizeAt<1>(),
              "uniform HSS levels must resolve to identical per-level sizes (H5/W8 L2)");
static_assert(HSS_SHA256_H5_W8_L2_Params::SignatureSize() == 2644 &&
              HSS_SHA256_H5_W8_L2_Params::PublicKeySize() == 60,
              "HSS H5/W8 L2 signature and public key sizes are fixed");
static_assert(HSS_SHA256_H10_W8_L2_Params::SignatureSize() == 2964,
              "HSS H10/W8 L2 signature size is fixed");
static_assert(HSS_SHA256_H5_W8_L3_Params::LMSSignatureSizeAt<0>() ==
              HSS_SHA256_H5_W8_L3_Params::LMSSignatureSizeAt<2>(),
              "uniform HSS levels must resolve to identical per-level sizes (H5/W8 L3)");
static_assert(HSS_SHA256_H5_W8_L4_Params::LMSSignatureSizeAt<0>() ==
              HSS_SHA256_H5_W8_L4_Params::LMSSignatureSizeAt<3>(),
              "uniform HSS levels must resolve to identical per-level sizes (H5/W8 L4)");

// Mixed-height L=2: an H10 root over an H5 bottom tree, uniform W8.
// Signature sizes differ, so this catches level-0 sizing assumptions.
typedef HSS_Params<
	HSSLevel<LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8>,
	HSSLevel<LMS_SHA256_M32_H5,  LMOTS_SHA256_N32_W8> > HSS_Mixed_H10H5_W8_L2_Params;

static bool TestHSSMixedHeights()
{
	AutoSeededRandomPool rng;
	const char* name = "HSS mixed H10/H5 L2";

	try {
		typedef HSS_Mixed_H10H5_W8_L2_Params Params;

		const std::string expectedName =
			"HSS[2]/(LMS-SHA256-M32-H10/LMOTS-SHA256-N32-W8,"
			"LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8)";
		if (Params::StaticAlgorithmName() != expectedName)
		{
			std::cout << "FAILED:  " << name << " algorithm name "
				<< Params::StaticAlgorithmName() << std::endl;
			return false;
		}

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		InsecureMemoryStateStore store(Params::TotalSignatures());
		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock signature(Params::SignatureSize());

		// Sign across the H5 bottom boundary: index 32 enters root leaf 1, which
		// forces a bottom-subtree rebuild.
		const unsigned int count = 34;
		{
			HSSSigner<Params> signer(privKey, store);
			for (unsigned int i = 0; i < count; i++)
			{
				std::string msg = "mixed msg " + std::to_string(i);
				signer.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin());

				if (!verifier.VerifyMessage(
						reinterpret_cast<const byte*>(msg.data()), msg.size(),
						signature.begin(), signature.size()))
				{
					std::cout << "FAILED:  " << name << " signature " << i
						<< " rejected" << std::endl;
					return false;
				}

				// Rollover check: index 31 is root 0 / bottom 31, index 32 is
				// root 1 / bottom 0. A reversed level order would fail here.
				if (i == 31 || i == 32)
				{
					auto be32 = [](const byte* p) -> uint32_t {
						return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
						       (uint32_t(p[2]) << 8) | uint32_t(p[3]);
					};
					const byte* s = signature.begin();
					const size_t finalSigOff = 4 +
						Params::LMSSignatureSizeAt<0>() + Params::LMSPublicKeySizeAt<1>();
					uint32_t rootLeaf = be32(s + 4);
					uint32_t bottomLeaf = be32(s + finalSigOff);
					if (rootLeaf != i / 32 || bottomLeaf != i % 32)
					{
						std::cout << "FAILED:  " << name << " index " << i
							<< " decomposed to root " << rootLeaf
							<< " bottom " << bottomLeaf << std::endl;
						return false;
					}
				}
			}
		}

		// Tamper rejection.
		{
			HSSSigner<Params> signer(privKey, store);
			std::string msg = "mixed tamper";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());
			signature[signature.size() / 2] ^= 0x01;
			if (verifier.VerifyMessage(
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin(), signature.size()))
			{
				std::cout << "FAILED:  " << name << " accepted tampered signature"
					<< std::endl;
				return false;
			}
		}

		// Reconstruct from the persisted store.
		{
			HSSSigner<Params> signer(privKey, store);
			std::string msg = "mixed after restart";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				signature.begin());
			if (!verifier.VerifyMessage(
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					signature.begin(), signature.size()))
			{
				std::cout << "FAILED:  " << name << " signature after restart rejected"
					<< std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name
			<< " sign/verify across boundary, tamper, restart" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}
}

bool ValidateHSS()
{
	std::cout << "\nHSS (SP 800-208, RFC 8554) validation suite running...\n\n";
	bool pass = true;

	// Functional tests: HSS L=2 H5/W8
	pass = TestHSSKeyGen<HSS_SHA256_H5_W8_L2_Params>(
		"HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestHSSSignVerify<HSS_SHA256_H5_W8_L2_Params>(
		"HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestHSSMultipleSignatures<HSS_SHA256_H5_W8_L2_Params>(
		"HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestHSSSerialization<HSS_SHA256_H5_W8_L2_Params>(
		"HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;
	pass = TestHSSRFCAppendixFTC1() && pass;
	pass = TestHSSMalformedSignatures() && pass;
	pass = TestHSSCrossKeyNegative<HSS_SHA256_H5_W8_L2_Params>(
		"HSS[2]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;

	// HSS-specific: subtree boundary, reconstruction, exhaustion
	pass = TestHSSSubtreeBoundary() && pass;
	pass = TestHSSSignerReconstruction() && pass;
	pass = TestHSSReconstructionAtBoundary() && pass;
	pass = TestHSSExhaustion() && pass;
	pass = TestHSSOutOfRangeReservation() && pass;
	pass = TestHSSInvalidReservationFromStore() && pass;
	pass = TestHSSSafeFailure() && pass;

	// HSS L=3 selective tests (non-exhaustive)
	pass = TestHSSL3SignVerify() && pass;
	pass = TestHSSL3SubtreeBoundary() && pass;
	pass = TestHSSL3Reconstruction() && pass;
	pass = TestHSSL3SafeFailure() && pass;
	pass = TestHSSL3MalformedSignatures() && pass;

	// HSS L=4 coverage
	pass = TestHSSL4SignVerify() && pass;
	pass = TestHSSL4MiddleBoundary() && pass;
	pass = TestHSSL4MalformedSignatures() && pass;
	pass = TestHSSCrossKeyNegative<HSS_SHA256_H5_W8_L4_Params>(
		"HSS[4]/LMS-SHA256-M32-H5/LMOTS-SHA256-N32-W8") && pass;

	// Mixed-height coverage: per-level dispatch with different tree heights
	pass = TestHSSSignVerify<HSS_Mixed_H10H5_W8_L2_Params>(
		"HSS mixed H10/H5 L2") && pass;
	pass = TestHSSSerialization<HSS_Mixed_H10H5_W8_L2_Params>(
		"HSS mixed H10/H5 L2") && pass;
	pass = TestHSSCrossKeyNegative<HSS_Mixed_H10H5_W8_L2_Params>(
		"HSS mixed H10/H5 L2") && pass;
	pass = TestHSSMixedHeights() && pass;

	return pass;
}

// ******************** FileStateStore Validation ************************* //

// Mirror FileStateStore path handling for non-ASCII test paths.

#ifdef _WIN32
static std::wstring TestUtf8PathToWide(const std::string &path)
{
	if (path.empty()) return std::wstring();
	if (path.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
		throw Exception(Exception::IO_ERROR,
			"test helper: path too long");
	const int wlen = MultiByteToWideChar(
		CP_UTF8, MB_ERR_INVALID_CHARS,
		path.c_str(), static_cast<int>(path.size()),
		nullptr, 0);
	if (wlen <= 0)
		throw Exception(Exception::IO_ERROR,
			"test helper: invalid UTF-8 in path: " + path);
	std::wstring wide(static_cast<size_t>(wlen), L'\0');
	MultiByteToWideChar(
		CP_UTF8, MB_ERR_INVALID_CHARS,
		path.c_str(), static_cast<int>(path.size()),
		&wide[0], wlen);
	return wide;
}
#endif

// Remove a test file if it exists. Best-effort, mirroring POSIX
// std::remove semantics (failure to delete a non-existent file is fine).
static void RemoveTestFile(const std::string &path)
{
#ifdef _WIN32
	try {
		const std::wstring wpath = TestUtf8PathToWide(path);
		if (!wpath.empty()) DeleteFileW(wpath.c_str());
	}
	catch (const Exception&) {
		// Cleanup is best-effort; swallow conversion errors.
	}
#else
	std::remove(path.c_str());
#endif
}

// Write raw bytes to a file (for corruption tests). Throws on any failure
// so a broken setup does not silently mask the test it is preparing.
static void WriteRawFile(const std::string &path, const byte *data, size_t len)
{
#ifdef _WIN32
	const std::wstring wpath = TestUtf8PathToWide(path);
	HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr,
	                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		throw Exception(Exception::IO_ERROR,
			"test helper: CreateFileW failed for write: " + path);
	DWORD written = 0;
	BOOL ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr);
	CloseHandle(h);
	if (!ok || written != static_cast<DWORD>(len))
		throw Exception(Exception::IO_ERROR,
			"test helper: WriteFile failed: " + path);
#else
	std::ofstream f(path, std::ios::binary | std::ios::trunc);
	if (!f)
		throw Exception(Exception::IO_ERROR,
			"test helper: ofstream open failed: " + path);
	f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
	if (!f)
		throw Exception(Exception::IO_ERROR,
			"test helper: ofstream write failed: " + path);
#endif
}

// Read raw bytes from a file. Throws on any failure so a broken read
// does not leave the caller's buffer holding stale data.
static void ReadRawFile(const std::string &path, byte *data, size_t len)
{
#ifdef _WIN32
	const std::wstring wpath = TestUtf8PathToWide(path);
	HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ, 0, nullptr,
	                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		throw Exception(Exception::IO_ERROR,
			"test helper: CreateFileW failed for read: " + path);
	DWORD bytesRead = 0;
	BOOL ok = ReadFile(h, data, static_cast<DWORD>(len), &bytesRead, nullptr);
	CloseHandle(h);
	if (!ok || bytesRead != static_cast<DWORD>(len))
		throw Exception(Exception::IO_ERROR,
			"test helper: ReadFile failed: " + path);
#else
	std::ifstream f(path, std::ios::binary);
	if (!f)
		throw Exception(Exception::IO_ERROR,
			"test helper: ifstream open failed: " + path);
	f.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(len));
	if (f.gcount() != static_cast<std::streamsize>(len))
		throw Exception(Exception::IO_ERROR,
			"test helper: ifstream short read: " + path);
#endif
}

static bool TestFileStoreCreateAndOpen()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_create.state";
	RemoveTestFile(path);

	try {
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			if (store.IsExhausted()) {
				std::cout << "FAILED:  " << name << " new store reports exhausted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
			if (store.RemainingSignatures() != 100) {
				std::cout << "FAILED:  " << name << " remaining != 100" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}
		// store closed (destructor)

		{
			FileStateStore store = FileStateStore::Open(path, 100);
			if (store.RemainingSignatures() != 100) {
				std::cout << "FAILED:  " << name << " reopen remaining != 100" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << " create and open" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " create/open - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreReserveAndReopen()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_reserve.state";
	RemoveTestFile(path);

	try {
		// Create and reserve 5 indices
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 5; i++)
			{
				StateReservation r = store.ReserveNext();
				if (r.LeafIndex() != static_cast<uint64_t>(i)) {
					std::cout << "FAILED:  " << name << " reserve index " << i << std::endl;
					RemoveTestFile(path);
					return false;
				}
				store.CommitReservation(r);
			}
			if (store.RemainingSignatures() != 95) {
				std::cout << "FAILED:  " << name << " remaining after 5 reserves" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// Reopen and verify state persisted
		{
			FileStateStore store = FileStateStore::Open(path, 100);
			if (store.RemainingSignatures() != 95) {
				std::cout << "FAILED:  " << name << " reopen remaining != 95" << std::endl;
				RemoveTestFile(path);
				return false;
			}
			// Next index should be 5
			StateReservation r = store.ReserveNext();
			if (r.LeafIndex() != 5) {
				std::cout << "FAILED:  " << name << " reopen next index != 5" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << " reserve and reopen continuity" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " reserve/reopen - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreExhaustion()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_exhaust.state";
	RemoveTestFile(path);

	try {
		FileStateStore store = FileStateStore::Create(path, 10);
		for (int i = 0; i < 10; i++)
			store.ReserveNext();

		if (!store.IsExhausted()) {
			std::cout << "FAILED:  " << name << " not exhausted" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		bool threw = false;
		try { store.ReserveNext(); }
		catch (const SignerExhausted&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " did not throw SignerExhausted" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		std::cout << "passed:  " << name << " exhaustion" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " exhaustion - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreCorruption()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_corrupt.state";
	RemoveTestFile(path);

	try {
		unsigned int detected = 0;

		// Create a valid file and reserve a few
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++)
				store.ReserveNext();
		}

		byte fileBuf[64];
		ReadRawFile(path, fileBuf, 64);

		// 1. Corrupted HMAC
		{
			byte bad[64];
			std::memcpy(bad, fileBuf, 64);
			bad[32] ^= 0x01;  // flip HMAC byte
			WriteRawFile(path, bad, 64);

			bool threw = false;
			try { FileStateStore::Open(path, 100); }
			catch (const SignerStateIntegrityFailure&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " corrupted HMAC accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// Restore valid file for next test
		WriteRawFile(path, fileBuf, 64);

		// 2. Corrupted magic
		{
			byte bad[64];
			std::memcpy(bad, fileBuf, 64);
			bad[0] = 'X';
			WriteRawFile(path, bad, 64);

			bool threw = false;
			try { FileStateStore::Open(path, 100); }
			catch (const SignerStateIntegrityFailure&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " corrupted magic accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		WriteRawFile(path, fileBuf, 64);

		// 3. Truncated file
		{
			WriteRawFile(path, fileBuf, 32);  // only 32 of 64 bytes

			bool threw = false;
			try { FileStateStore::Open(path, 100); }
			catch (const Exception&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " truncated file accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		WriteRawFile(path, fileBuf, 64);

		// 4. Wrong totalLeaves
		{
			bool threw = false;
			try { FileStateStore::Open(path, 200); }  // file has 100
			catch (const SignerStateIntegrityFailure&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " wrong totalLeaves accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// 5. Create over existing file
		{
			bool threw = false;
			try { FileStateStore::Create(path, 100); }
			catch (const Exception&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " create over existing accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// 6. Open nonexistent file
		{
			RemoveTestFile(path);
			bool threw = false;
			try { FileStateStore::Open("nonexistent_state_file.state", 100); }
			catch (const Exception&) { threw = true; }
			if (threw) detected++;
			else {
				std::cout << "FAILED:  " << name << " open nonexistent accepted" << std::endl;
				return false;
			}
		}

		std::cout << "passed:  " << name << " corruption and negative tests (" << detected << " cases)" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " corruption - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreIntegrityKey()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_key.state";
	RemoveTestFile(path);

	try {
		const byte keyA[] = "integrity-key-alpha";
		const byte keyB[] = "integrity-key-bravo";

		// Create with key A, reserve a few
		{
			FileStateStore store = FileStateStore::Create(path, 100, keyA, sizeof(keyA) - 1);
			for (int i = 0; i < 5; i++)
				store.ReserveNext();
		}

		// Reopen with key A - should work
		{
			FileStateStore store = FileStateStore::Open(path, 100, keyA, sizeof(keyA) - 1);
			if (store.RemainingSignatures() != 95) {
				std::cout << "FAILED:  " << name << " key A reopen wrong count" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// Reopen with key B - should fail
		{
			bool threw = false;
			try { FileStateStore::Open(path, 100, keyB, sizeof(keyB) - 1); }
			catch (const SignerStateIntegrityFailure&) { threw = true; }
			if (!threw) {
				std::cout << "FAILED:  " << name << " wrong key accepted" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		// Reopen with no key - should fail (file was created with key)
		{
			bool threw = false;
			try { FileStateStore::Open(path, 100); }
			catch (const SignerStateIntegrityFailure&) { threw = true; }
			if (!threw) {
				std::cout << "FAILED:  " << name << " no key accepted on keyed file" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << " integrity key verification" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " integrity key - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStorePoisonedState()
{
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_poison.state";
	RemoveTestFile(path);

	try {
		// Create valid, reserve a few, then close
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++)
				store.ReserveNext();
		}

		// Corrupt the file while no store holds it open
		byte fileBuf[64];
		ReadRawFile(path, fileBuf, 64);
		fileBuf[32] ^= 0xFF;  // corrupt HMAC
		WriteRawFile(path, fileBuf, 64);

		// Open should throw (integrity failure on read)
		bool openThrew = false;
		try { FileStateStore::Open(path, 100); }
		catch (const SignerStateIntegrityFailure&) { openThrew = true; }

		if (!openThrew) {
			std::cout << "FAILED:  " << name << " Open did not throw on corrupted file" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		// Restore valid file, open, then test poison via IsHealthy
		// by corrupting while store is open (POSIX only - on Windows
		// the exclusive handle blocks external writes, so we test
		// the Open-time detection path above instead)
		WriteRawFile(path, fileBuf, 64);  // still corrupted from above

		// Restore actually-valid content for next test
		byte validBuf[64];
		{
			// Re-create a clean file to get valid bytes
			RemoveTestFile(path);
			FileStateStore tmp = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++)
				tmp.ReserveNext();
		}
		ReadRawFile(path, validBuf, 64);

		// Open valid file, then verify IsHealthy works on valid state
		{
			FileStateStore store = FileStateStore::Open(path, 100);

			// IsHealthy on uncorrupted file should return true
			bool healthy = store.IsHealthy();
			if (!healthy) {
				std::cout << "FAILED:  " << name << " IsHealthy false on valid file" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << " poisoned state / corruption detection" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " poisoned state - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreLMSIntegration()
{
	const char* name = "FileStateStore + LMS";
	const std::string path = "test_filestore_lms.state";
	RemoveTestFile(path);

	AutoSeededRandomPool rng;

	try {
		typedef LMS_SHA256_M32_H5 LMS_P;
		typedef LMOTS_SHA256_N32_W8 OTS_P;

		LMSPrivateKey<LMS_P, OTS_P> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		LMSPublicKey<LMS_P, OTS_P> pubKey;
		privKey.MakePublicKey(pubKey);

		LMSVerifier<LMS_P, OTS_P> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		// Sign with file-backed store
		{
			FileStateStore store = FileStateStore::Create(path, LMS_P::TOTAL_LEAVES);
			LMSSigner<LMS_P, OTS_P> signer(privKey, store);

			std::string msg = "LMS + FileStateStore test";
			SecByteBlock sig(signer.SignatureLength());
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " signature rejected" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreHSSIntegration()
{
	const char* name = "FileStateStore + HSS";
	const std::string path = "test_filestore_hss.state";
	RemoveTestFile(path);

	AutoSeededRandomPool rng;

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(Params::SignatureSize());

		// Sign 5 messages, close, reopen, sign 6th
		{
			FileStateStore store = FileStateStore::Create(path, Params::TotalSignatures());
			HSSSigner<Params> signer(privKey, store);

			for (int i = 0; i < 5; i++) {
				std::string msg = "HSS file store msg " + std::to_string(i);
				signer.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin());
			}
		}

		// Reopen and sign 6th
		{
			FileStateStore store = FileStateStore::Open(path, Params::TotalSignatures());
			HSSSigner<Params> signer(privKey, store);

			std::string msg = "HSS file store msg after restart";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " post-restart sig rejected" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << " sign/restart/sign" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreHSSSubtreeBoundaryRestart()
{
	const char* name = "FileStateStore + HSS subtree boundary restart";
	const std::string path = "test_filestore_hss_boundary.state";
	RemoveTestFile(path);

	AutoSeededRandomPool rng;

	try {
		typedef HSS_SHA256_H5_W8_L2_Params Params;

		HSSPrivateKey<Params> privKey;
		privKey.GenerateRandom(rng, g_nullNameValuePairs);

		HSSPublicKey<Params> pubKey;
		privKey.MakePublicKey(pubKey);

		HSSVerifier<Params> verifier(
			pubKey.GetPublicKeyBytePtr(), pubKey.GetPublicKeyByteLength());

		SecByteBlock sig(Params::SignatureSize());

		// Sign 32 (exhaust first subtree), close
		{
			FileStateStore store = FileStateStore::Create(path, Params::TotalSignatures());
			HSSSigner<Params> signer(privKey, store);

			for (unsigned int i = 0; i < Params::LeavesAt<0>(); i++) {
				std::string msg = "Boundary restart msg " + std::to_string(i);
				signer.SignMessage(rng,
					reinterpret_cast<const byte*>(msg.data()), msg.size(),
					sig.begin());
			}
		}

		// Reopen - next sig crosses into subtree 1
		{
			FileStateStore store = FileStateStore::Open(path, Params::TotalSignatures());
			HSSSigner<Params> signer(privKey, store);

			std::string msg = "First msg in new subtree after file restart";
			signer.SignMessage(rng,
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin());

			bool valid = verifier.VerifyMessage(
				reinterpret_cast<const byte*>(msg.data()), msg.size(),
				sig.begin(), sig.size());

			if (!valid) {
				std::cout << "FAILED:  " << name << " cross-boundary sig rejected" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreCrossRestartRollbackLimit()
{
	// Documented limitation: an older valid file image can reopen after restart.
	// FileStateStore has no external monotonic anchor for rollback detection.
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_rollback_limit.state";
	RemoveTestFile(path);

	try {
		byte oldFile[64];

		// Create, advance to index 3, save a copy of the file
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++)
				store.ReserveNext();
		}
		ReadRawFile(path, oldFile, 64);

		// Advance further to index 7, close
		{
			FileStateStore store = FileStateStore::Open(path, 100);
			for (int i = 0; i < 4; i++)
				store.ReserveNext();
			// store now at nextIndex=7
		}

		// Restore the old file (nextIndex=3) - simulates full-system rollback
		WriteRawFile(path, oldFile, 64);

		// Reopen in a "fresh process" - should succeed because the old file
		// is internally valid and the HMAC checks out. This is the documented
		// limitation: no external monotonic anchor means no cross-restart
		// rollback detection.
		bool openedCleanly = false;
		try {
			FileStateStore store = FileStateStore::Open(path, 100);
			// Verify it resumed from the old index (3), not the newer one (7)
			StateReservation r = store.ReserveNext();
			if (r.LeafIndex() == 3)
				openedCleanly = true;
		}
		catch (const Exception&) {
			openedCleanly = false;
		}

		if (!openedCleanly) {
			std::cout << "FAILED:  " << name
				<< " cross-restart rollback limit - old valid file should reopen" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		std::cout << "passed:  " << name
			<< " cross-restart rollback limitation (honest: old valid file reopens)" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " rollback limit - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStorePoisonedStateContract()
{
	// Check the post-integrity-failure contract:
	// 1. ReserveNext() throws SignerStateIntegrityFailure
	// 2. IsHealthy() throws SignerStateIntegrityFailure
	// 3. IsExhausted() returns true
	// 4. RemainingSignatures() returns 0
	const char* name = "FileStateStore";
	const std::string path = "test_filestore_poison_contract.state";
	RemoveTestFile(path);

	try {
		// Create valid file, advance, close
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 5; i++)
				store.ReserveNext();
		}

		// Corrupt the HMAC
		byte fileBuf[64];
		ReadRawFile(path, fileBuf, 64);
		fileBuf[32] ^= 0xFF;
		WriteRawFile(path, fileBuf, 64);

		// Open-time corruption is checked first. The store does not escape when
		// Open throws, so live-object poisoning is covered separately below.
		bool openThrew = false;
		try { FileStateStore::Open(path, 100); }
		catch (const SignerStateIntegrityFailure&) { openThrew = true; }

		if (!openThrew) {
			std::cout << "FAILED:  " << name
				<< " poisoned contract - Open did not throw on corrupt file" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		// Live-object poisoning needs a store that opens successfully and fails
		// on a later operation.
		fileBuf[32] ^= 0xFF;  // restore valid HMAC
		WriteRawFile(path, fileBuf, 64);

		// Verify valid file opens fine
		{
			FileStateStore store = FileStateStore::Open(path, 100);
			// This should work - file is valid
		}

		// Wrong expectedTotalLeaves is another Open-time failure path.
		// The static Open throws, so no poisoned object is returned.

		// POSIX can also cover live-object poisoning by changing the file
		// behind an open store.
#ifndef _WIN32
		{
			// Restore valid file and open
			WriteRawFile(path, fileBuf, 64);
			FileStateStore store = FileStateStore::Open(path, 100);

			// Corrupt the file while store is open (POSIX allows this)
			byte corruptBuf[64];
			std::memcpy(corruptBuf, fileBuf, 64);
			corruptBuf[32] ^= 0xFF;
			WriteRawFile(path, corruptBuf, 64);

			// IsHealthy should throw and poison
			bool healthThrew = false;
			try { store.IsHealthy(); }
			catch (const SignerStateIntegrityFailure&) { healthThrew = true; }

			if (!healthThrew) {
				std::cout << "FAILED:  " << name
					<< " poisoned contract - IsHealthy did not throw" << std::endl;
				RemoveTestFile(path);
				return false;
			}

			// Contract point 1: ReserveNext throws
			bool reserveThrew = false;
			try { store.ReserveNext(); }
			catch (const SignerStateIntegrityFailure&) { reserveThrew = true; }

			// Contract point 2: IsHealthy throws again
			bool healthThrew2 = false;
			try { store.IsHealthy(); }
			catch (const SignerStateIntegrityFailure&) { healthThrew2 = true; }

			// Contract point 3: IsExhausted returns true
			bool exhausted = store.IsExhausted();

			// Contract point 4: RemainingSignatures returns 0
			uint64_t remaining = store.RemainingSignatures();

			if (!reserveThrew || !healthThrew2 || !exhausted || remaining != 0) {
				std::cout << "FAILED:  " << name
					<< " poisoned contract - post-poison state incorrect"
					<< " (reserve=" << reserveThrew << " health=" << healthThrew2
					<< " exhausted=" << exhausted << " remaining=" << remaining << ")" << std::endl;
				RemoveTestFile(path);
				return false;
			}

			std::cout << "passed:  " << name
				<< " poisoned state full contract (POSIX, 4 points)" << std::endl;
		}
#else
		// On Windows, the exclusive handle blocks live corruption.
		// We can only test Open-time detection, which we did above.
		std::cout << "passed:  " << name
			<< " poisoned state contract (Windows: Open-time detection)" << std::endl;
#endif

		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " poisoned contract - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreInvalidReservation()
{
	const char* name = "FileStateStore invalid reservation";
	const std::string path = "test_filestore_invalid_reservation.state";
	RemoveTestFile(path);

	try {
		FileStateStore store = FileStateStore::Create(path, 4);

		StateReservation r = store.ReserveNext();
		StateReservation moved(std::move(r));

		bool commitThrew = false;
		try {
			store.CommitReservation(r);
		}
		catch (const SignerStateIntegrityFailure&) {
			commitThrew = true;
		}

		bool abortThrew = false;
		try {
			store.AbortReservation(r);
		}
		catch (const SignerStateIntegrityFailure&) {
			abortThrew = true;
		}

		if (!commitThrew || !abortThrew) {
			std::cout << "FAILED:  " << name
			          << " did not reject moved-from reservation" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		// Moved-to reservation remains valid.
		store.CommitReservation(moved);

		std::cout << "passed:  " << name << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

// Helper for cross-store tests below: returns true if op() throws
// SignerStateIntegrityFailure, false otherwise.
#define CROSS_STORE_EXPECT_THROW(which, op) \
	do { \
		bool threw = false; \
		try { op; } \
		catch (const SignerStateIntegrityFailure&) { threw = true; } \
		if (!threw) { \
			std::cout << "FAILED:  " << name << " " << (which) \
			          << " accepted foreign reservation" << std::endl; \
			RemoveTestFile(pathA); RemoveTestFile(pathB); \
			return false; \
		} \
	} while (0)

static bool TestCrossStoreReservationRejection()
{
	const char* name = "Cross-store reservation rejection";
	const std::string pathA = "test_filestore_cross_a.state";
	const std::string pathB = "test_filestore_cross_b.state";
	RemoveTestFile(pathA);
	RemoveTestFile(pathB);

	try {
		// In-memory A reservation rejected by in-memory B (commit + abort)
		{
			InsecureMemoryStateStore a(4);
			InsecureMemoryStateStore b(4);
			StateReservation rA = a.ReserveNext();
			CROSS_STORE_EXPECT_THROW("memory B commit", b.CommitReservation(rA));
			CROSS_STORE_EXPECT_THROW("memory B abort", b.AbortReservation(rA));
			// Original store still accepts the reservation.
			a.CommitReservation(rA);
		}

		// File A reservation rejected by File B (commit + abort)
		{
			FileStateStore a = FileStateStore::Create(pathA, 4);
			FileStateStore b = FileStateStore::Create(pathB, 4);
			StateReservation rA = a.ReserveNext();
			CROSS_STORE_EXPECT_THROW("file B commit", b.CommitReservation(rA));
			CROSS_STORE_EXPECT_THROW("file B abort", b.AbortReservation(rA));
			a.CommitReservation(rA);
		}
		RemoveTestFile(pathA);
		RemoveTestFile(pathB);

		// In-memory reservation rejected by FileStateStore (cross-type)
		{
			InsecureMemoryStateStore mem(4);
			FileStateStore file = FileStateStore::Create(pathA, 4);
			StateReservation rMem = mem.ReserveNext();
			CROSS_STORE_EXPECT_THROW("cross-type file commit",
				file.CommitReservation(rMem));
			CROSS_STORE_EXPECT_THROW("cross-type file abort",
				file.AbortReservation(rMem));
			mem.CommitReservation(rMem);
		}
		RemoveTestFile(pathA);

		// Moved-from reservation from store A passed to store B is rejected.
		// The validity helper handles both invalidity and issuer mismatch
		// without depending on check order.
		{
			InsecureMemoryStateStore a(4);
			InsecureMemoryStateStore b(4);
			StateReservation rA = a.ReserveNext();
			StateReservation moved(std::move(rA));
			CROSS_STORE_EXPECT_THROW("memory B moved-from commit",
				b.CommitReservation(rA));
			CROSS_STORE_EXPECT_THROW("memory B moved-from abort",
				b.AbortReservation(rA));
			// Moved-to reservation still valid against its original issuer.
			a.CommitReservation(moved);
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(pathA);
		RemoveTestFile(pathB);
		return false;
	}
}

#undef CROSS_STORE_EXPECT_THROW

#ifndef _WIN32
static bool TestFileStoreConcurrentOpenRejected()
{
	// POSIX only: a second Open against the same path while the first
	// store still holds the advisory flock should fail with IO_ERROR.
	const char* name = "FileStateStore (POSIX) concurrent open rejected";
	const std::string path = "test_filestore_concurrent.state";
	RemoveTestFile(path);

	try {
		FileStateStore first = FileStateStore::Create(path, 4);

		bool secondThrew = false;
		try {
			FileStateStore second = FileStateStore::Open(path, 4);
		}
		catch (const Exception &e) {
			if (e.GetErrorType() == Exception::IO_ERROR)
				secondThrew = true;
		}

		if (!secondThrew) {
			std::cout << "FAILED:  " << name << " second open accepted" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		std::cout << "passed:  " << name << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception &e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreInProcessRollback()
{
	// POSIX only: rewrite the backing file with an older nextIndex
	// while the store is open, verify IsHealthy detects rollback.
	const char* name = "FileStateStore (POSIX)";
	const std::string path = "test_filestore_inprocess_rollback.state";
	RemoveTestFile(path);

	try {
		// Create and advance to index 5
		byte oldFile[64];
		{
			FileStateStore tmp = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++)
				tmp.ReserveNext();
		}
		ReadRawFile(path, oldFile, 64);  // save state at index 3

		// Reopen and advance to index 5
		FileStateStore store = FileStateStore::Open(path, 100);
		store.ReserveNext();  // index 3
		store.ReserveNext();  // index 4
		// store now at nextIndex=5

		// Rewrite the file with the old state (nextIndex=3)
		// The store's in-memory m_nextIndex is 5, so IsHealthy
		// should detect the on-disk regression.
		WriteRawFile(path, oldFile, 64);

		bool threw = false;
		try { store.IsHealthy(); }
		catch (const SignerStateIntegrityFailure&) { threw = true; }

		if (!threw) {
			std::cout << "FAILED:  " << name
				<< " in-process rollback not detected" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		// Verify store is now poisoned
		bool reserveThrew = false;
		try { store.ReserveNext(); }
		catch (const SignerStateIntegrityFailure&) { reserveThrew = true; }

		if (!reserveThrew) {
			std::cout << "FAILED:  " << name
				<< " store not poisoned after rollback" << std::endl;
			RemoveTestFile(path);
			return false;
		}

		std::cout << "passed:  " << name
			<< " in-process rollback detection" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " in-process rollback - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}
#endif  // !_WIN32

static bool TestZeroCapacityRejection()
{
	const char* name = "Zero-capacity rejection";
	const std::string path = "test_filestore_zero_cap.state";
	RemoveTestFile(path);

	bool memoryThrew = false;
	try {
		InsecureMemoryStateStore store(0);
	}
	catch (const InvalidArgument&) {
		memoryThrew = true;
	}
	if (!memoryThrew) {
		std::cout << "FAILED:  " << name << " InsecureMemoryStateStore(0) accepted" << std::endl;
		return false;
	}

	bool createThrew = false;
	try {
		FileStateStore store = FileStateStore::Create(path, 0);
	}
	catch (const InvalidArgument&) {
		createThrew = true;
	}
	if (!createThrew) {
		std::cout << "FAILED:  " << name << " FileStateStore::Create(path, 0) accepted" << std::endl;
		RemoveTestFile(path);
		return false;
	}
	RemoveTestFile(path);

	// For Open we need a valid file to attempt opening with zero expected leaves.
	FileStateStore::Create(path, 4);
	bool openThrew = false;
	try {
		FileStateStore store = FileStateStore::Open(path, 0);
	}
	catch (const InvalidArgument&) {
		openThrew = true;
	}
	if (!openThrew) {
		std::cout << "FAILED:  " << name << " FileStateStore::Open(path, 0) accepted" << std::endl;
		RemoveTestFile(path);
		return false;
	}
	RemoveTestFile(path);

	std::cout << "passed:  " << name << std::endl;
	return true;
}

static bool TestFileStoreSizeValidation()
{
	const char* name = "FileStateStore size validation";
	const std::string path = "test_filestore_size.state";
	RemoveTestFile(path);

	try {
		// Short file: 32 bytes
		{
			byte shortBuf[32];
			std::memset(shortBuf, 0, sizeof(shortBuf));
			WriteRawFile(path, shortBuf, sizeof(shortBuf));

			bool threw = false;
			try {
				FileStateStore store = FileStateStore::Open(path, 100);
			}
			catch (const SignerStateIntegrityFailure&) {
				threw = true;
			}

			if (!threw) {
				std::cout << "FAILED:  " << name << " accepted short file" << std::endl;
				RemoveTestFile(path);
				return false;
			}
			RemoveTestFile(path);
		}

		// Long file: 128 bytes
		{
			byte longBuf[128];
			std::memset(longBuf, 0, sizeof(longBuf));
			WriteRawFile(path, longBuf, sizeof(longBuf));

			bool threw = false;
			try {
				FileStateStore store = FileStateStore::Open(path, 100);
			}
			catch (const SignerStateIntegrityFailure&) {
				threw = true;
			}

			if (!threw) {
				std::cout << "FAILED:  " << name << " accepted oversized file" << std::endl;
				RemoveTestFile(path);
				return false;
			}
			RemoveTestFile(path);
		}

		std::cout << "passed:  " << name << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

static bool TestFileStoreNonAsciiPath()
{
	const char* name = "FileStateStore";
	// UTF-8 encoded path: "test_filestore_café_状態.state"
	//   café  -> caf + 0xC3 0xA9   (U+00E9, Latin small letter e with acute)
	//   状    -> 0xE7 0x8A 0xB6    (U+72B6)
	//   態    -> 0xE6 0x85 0x8B    (U+614B)
	const std::string path =
		"test_filestore_caf\xC3\xA9_\xE7\x8A\xB6\xE6\x85\x8B.state";
	RemoveTestFile(path);

	try {
		{
			FileStateStore store = FileStateStore::Create(path, 100);
			for (int i = 0; i < 3; i++) {
				StateReservation r = store.ReserveNext();
				if (r.LeafIndex() != static_cast<uint64_t>(i)) {
					std::cout << "FAILED:  " << name
					          << " non-ASCII path reserve index " << i << std::endl;
					RemoveTestFile(path);
					return false;
				}
				store.CommitReservation(r);
			}
		}

		{
			FileStateStore store = FileStateStore::Open(path, 100);
			if (store.RemainingSignatures() != 97) {
				std::cout << "FAILED:  " << name
				          << " non-ASCII path reopen remaining != 97" << std::endl;
				RemoveTestFile(path);
				return false;
			}
			StateReservation r = store.ReserveNext();
			if (r.LeafIndex() != 3) {
				std::cout << "FAILED:  " << name
				          << " non-ASCII path reopen next index != 3" << std::endl;
				RemoveTestFile(path);
				return false;
			}
		}

		std::cout << "passed:  " << name
		          << " non-ASCII (UTF-8) path round-trip" << std::endl;
		RemoveTestFile(path);
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name
		          << " non-ASCII path - " << e.what() << std::endl;
		RemoveTestFile(path);
		return false;
	}
}

bool ValidateFileStateStore()
{
	std::cout << "\nFileStateStore validation suite running...\n\n";
	bool pass = true;

	pass = TestFileStoreCreateAndOpen() && pass;
	pass = TestFileStoreReserveAndReopen() && pass;
	pass = TestFileStoreExhaustion() && pass;
	pass = TestFileStoreCorruption() && pass;
	pass = TestFileStoreIntegrityKey() && pass;
	pass = TestFileStorePoisonedState() && pass;
	pass = TestFileStoreCrossRestartRollbackLimit() && pass;
	pass = TestFileStorePoisonedStateContract() && pass;
	pass = TestFileStoreInvalidReservation() && pass;
	pass = TestCrossStoreReservationRejection() && pass;
	pass = TestZeroCapacityRejection() && pass;
	pass = TestFileStoreSizeValidation() && pass;
	pass = TestFileStoreNonAsciiPath() && pass;
#ifndef _WIN32
	pass = TestFileStoreConcurrentOpenRejected() && pass;
	pass = TestFileStoreInProcessRollback() && pass;
#endif
	pass = TestFileStoreLMSIntegration() && pass;
	pass = TestFileStoreHSSIntegration() && pass;
	pass = TestFileStoreHSSSubtreeBoundaryRestart() && pass;

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
