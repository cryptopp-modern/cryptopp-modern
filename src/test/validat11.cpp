// validat11.cpp - written and placed in the public domain by Colin Brown
//                 Stateless post-quantum validation tests (FIPS 203, 204, 205).

#include <cryptopp/pch.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/validate.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cstring>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

#include <cryptopp/mlkem.h>
#include <cryptopp/mldsa.h>
#include <cryptopp/slhdsa.h>
#include <cryptopp/xwing.h>

#include "../pqc/wipe_guard.h"

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

// ******************** PQC key decode-state helpers ************************* //

// Grow the outer SEQUENCE by one trailing NULL, so decoding parses the key
// payload and then fails at the outer MessageEnd. Handles short and long-form
// length, including a short form that no longer fits after the increment.
static std::string DerWithTrailingElementInSequence(const std::string& der)
{
	CRYPTOPP_ASSERT(!der.empty() && static_cast<byte>(der[0]) == 0x30);
	const size_t extra = 2;  // one NULL: 0x05 0x00
	std::string out = der;
	byte first = static_cast<byte>(out[1]);
	if (first < 0x80) {
		size_t newLen = static_cast<size_t>(first) + extra;
		if (newLen < 0x80) {
			out[1] = static_cast<char>(newLen);
		}
		else {
			out[1] = static_cast<char>(0x81);  // promote to one-byte long form
			out.insert(out.begin() + 2, static_cast<char>(newLen));
		}
	}
	else {
		size_t n = first & 0x7F;
		size_t carry = extra;
		for (size_t i = 1 + n; i > 1 && carry; --i) {
			size_t v = static_cast<byte>(out[i]) + carry;
			out[i] = static_cast<char>(v & 0xFF);
			carry = v >> 8;
		}
		CRYPTOPP_ASSERT(carry == 0);  // +2 never widens a real key's length field
	}
	out.push_back(static_cast<char>(0x05));
	out.push_back(static_cast<char>(0x00));
	return out;
}

// Rejected decodes must leave an existing key unchanged. Valid decodes must
// stop at the end of the object and leave trailing input unread.
// aBytes is encoded; bBytes is the key state that must survive failure.
template <class PubKey>
static bool TestPqcPublicDecodeState(const char* name,
	const byte* aBytes, const byte* bBytes, size_t len)
{
	try {
		if (VerifyBufsEqual(aBytes, bBytes, len)) {
			std::cout << "FAILED:  " << name << " public test keys A and B identical" << std::endl;
			return false;
		}

		PubKey keyA;
		keyA.SetPublicKey(aBytes, len);
		std::string der;
		StringSink sink(der);
		keyA.Save(sink);

		PubKey target;
		target.SetPublicKey(bBytes, len);

		bool pass = true;
		bool rejected = false;
		try {
			std::string malformed = DerWithTrailingElementInSequence(der);
			StringSource src(malformed, true);
			target.Load(src);
		}
		catch (const BERDecodeErr&) { rejected = true; }
		if (!rejected) {
			std::cout << "FAILED:  " << name << " public malformed stream accepted" << std::endl;
			pass = false;
		}
		if (!VerifyBufsEqual(target.GetPublicKeyBytePtr(), bBytes, len)) {
			std::cout << "FAILED:  " << name << " public key changed after rejected decode" << std::endl;
			pass = false;
		}

		std::string withTail = der + "TAIL";
		PubKey key;
		StringSource src2(withTail, true);
		key.Load(src2);
		if (!VerifyBufsEqual(key.GetPublicKeyBytePtr(), aBytes, len)) {
			std::cout << "FAILED:  " << name << " public boundary decode mismatch" << std::endl;
			pass = false;
		}
		byte tail[4];
		if (src2.MaxRetrievable() != 4 || src2.Get(tail, 4) != 4 ||
			!VerifyBufsEqual(tail, reinterpret_cast<const byte*>("TAIL"), 4)) {
			std::cout << "FAILED:  " << name << " public trailing bytes consumed" << std::endl;
			pass = false;
		}

		if (pass)
			std::cout << "passed:  " << name << " public decode state (2 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " public decode state - " << e.what() << std::endl;
		return false;
	}
}

template <class PrivKey>
static bool TestPqcPrivateDecodeState(const char* name,
	const byte* aBytes, const byte* bBytes, size_t len)
{
	try {
		if (VerifyBufsEqual(aBytes, bBytes, len)) {
			std::cout << "FAILED:  " << name << " private test keys A and B identical" << std::endl;
			return false;
		}

		PrivKey keyA;
		keyA.SetPrivateKey(aBytes, len);
		std::string der;
		StringSink sink(der);
		keyA.Save(sink);

		PrivKey target;
		target.SetPrivateKey(bBytes, len);
		SecByteBlock targetPub(target.GetPublicKeyBytePtr(), target.GetPublicKeySize());

		bool pass = true;
		bool rejected = false;
		try {
			std::string malformed = DerWithTrailingElementInSequence(der);
			StringSource src(malformed, true);
			target.Load(src);
		}
		catch (const BERDecodeErr&) { rejected = true; }
		if (!rejected) {
			std::cout << "FAILED:  " << name << " private malformed stream accepted" << std::endl;
			pass = false;
		}
		if (!VerifyBufsEqual(target.GetPrivateKeyBytePtr(), bBytes, len) ||
			!VerifyBufsEqual(target.GetPublicKeyBytePtr(), targetPub, targetPub.size())) {
			std::cout << "FAILED:  " << name << " private key changed after rejected decode" << std::endl;
			pass = false;
		}

		std::string withTail = der + "TAIL";
		PrivKey key;
		StringSource src2(withTail, true);
		key.Load(src2);
		if (!VerifyBufsEqual(key.GetPrivateKeyBytePtr(), aBytes, len)) {
			std::cout << "FAILED:  " << name << " private boundary decode mismatch" << std::endl;
			pass = false;
		}
		byte tail[4];
		if (src2.MaxRetrievable() != 4 || src2.Get(tail, 4) != 4 ||
			!VerifyBufsEqual(tail, reinterpret_cast<const byte*>("TAIL"), 4)) {
			std::cout << "FAILED:  " << name << " private trailing bytes consumed" << std::endl;
			pass = false;
		}

		if (pass)
			std::cout << "passed:  " << name << " private decode state (2 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " private decode state - " << e.what() << std::endl;
		return false;
	}
}

// Encoding a key that was never set must throw InvalidArgument and write
// nothing. Once a key is set, the same object must encode.
template <class Key>
static bool ExpectPqcEncodeReject(const char* name, const char* label, const Key& key)
{
	ByteQueue queue;
	bool rejected = false;
	try {
		key.DEREncode(queue);
	}
	catch (const InvalidArgument&) {
		rejected = true;
	}
	if (!rejected) {
		std::cout << "FAILED:  " << name << " " << label << " encoded" << std::endl;
		return false;
	}
	if (queue.MaxRetrievable() != 0) {
		std::cout << "FAILED:  " << name << " " << label << " wrote output" << std::endl;
		return false;
	}
	return true;
}

// zeroIsUnset: the family stores keys in fixed-size blocks and treats
// all-zero material as unset, so the setters must not defeat the guard.
template <class PARAMS, class PubKey, class PrivKey>
static bool TestPqcEncodeGuard(const char* name, bool zeroIsUnset)
{
	AutoSeededRandomPool rng;
	try {
		PubKey pub;
		PrivKey priv;
		bool pass = ExpectPqcEncodeReject(name, "default public", pub);
		pass = ExpectPqcEncodeReject(name, "default private", priv) && pass;
		unsigned int cases = 2;

		if (zeroIsUnset) {
			SecByteBlock zeros;
			zeros.CleanNew(PARAMS::PUBLIC_KEY_SIZE);
			pub.SetPublicKey(zeros, zeros.size());
			pass = ExpectPqcEncodeReject(name, "all-zero public", pub) && pass;
			zeros.CleanNew(PARAMS::SECRET_KEY_SIZE);
			// A setter that checks the key refuses it here; the object stays unset.
			try { priv.SetPrivateKey(zeros, zeros.size()); }
			catch (const InvalidArgument&) {}
			pass = ExpectPqcEncodeReject(name, "all-zero private", priv) && pass;
			cases += 2;
		}

		priv.GenerateRandom(rng, g_nullNameValuePairs);
		pub.SetPublicKey(priv.GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);
		ByteQueue pubQueue, privQueue;
		pub.DEREncode(pubQueue);
		priv.DEREncode(privQueue);
		if (pubQueue.MaxRetrievable() == 0 || privQueue.MaxRetrievable() == 0) {
			std::cout << "FAILED:  " << name << " set key encode" << std::endl;
			pass = false;
		}

		if (pass)
			std::cout << "passed:  " << name << " unset-key encode rejection (" << cases << " cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " unset-key encode rejection - " << e.what() << std::endl;
		return false;
	}
}

// Use deterministic key material to keep the DER digests reproducible.
static void FillPattern(SecByteBlock& b, byte seed)
{
	for (size_t i = 0; i < b.size(); ++i)
		b[i] = static_cast<byte>(seed + 3 * i);
}

template <class Key>
static bool ExpectDerDigest(const char* name, const char* label, const Key& key,
	const char* expected)
{
	std::string der, digest;
	StringSink sink(der);
	key.DEREncode(sink);
	SHA256 hash;
	StringSource(der, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
	if (digest != expected) {
		std::cout << "FAILED:  " << name << " " << label << " DER digest " << digest << std::endl;
		return false;
	}
	return true;
}

template <class PARAMS, class PubKey, class PrivKey>
static bool TestPqcDerFixtures(const char* name, const SecByteBlock& privMaterial,
	const char* privDigest, const SecByteBlock& pubMaterial, const char* pubDigest)
{
	try {
		PrivKey priv;
		priv.SetPrivateKey(privMaterial, privMaterial.size());
		bool pass = ExpectDerDigest(name, "private", priv, privDigest);

		PubKey pub;
		pub.SetPublicKey(pubMaterial, pubMaterial.size());
		pass = ExpectDerDigest(name, "public", pub, pubDigest) && pass;

		if (pass)
			std::cout << "passed:  " << name << " DER fixtures (2 keys)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " DER fixtures - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS, class PubKey, class PrivKey>
static bool TestPqcDerFixtures(const char* name, byte privSeed, const char* privDigest,
	byte pubSeed, const char* pubDigest)
{
	SecByteBlock priv(PARAMS::SECRET_KEY_SIZE), pub(PARAMS::PUBLIC_KEY_SIZE);
	FillPattern(priv, privSeed);
	FillPattern(pub, pubSeed);
	return TestPqcDerFixtures<PARAMS, PubKey, PrivKey>(name, priv, privDigest,
		pub, pubDigest);
}

// ******************** PQC stack wipe guard ************************* //

// The guarded storage belongs to the caller, so it can be read after the
// guard has run. Canaries either side catch a wipe of the wrong size.
struct GuardedBytes { byte before[8]; byte secret[61]; byte after[8]; };
struct GuardedWords { word64 before; word64 secret[5]; word64 after; };

static void FillThenLeave(void* buf, size_t byteCount, bool leaveByThrow)
{
	PQC_Internal::WipeGuard wipe(buf, byteCount);
	std::memset(buf, 0xA5, byteCount);
	if (leaveByThrow)
		throw Exception(Exception::OTHER_ERROR, "leaving by exception");
}

static bool IsFilledWith(const void* buf, size_t byteCount, byte value)
{
	const byte* p = static_cast<const byte*>(buf);
	for (size_t i = 0; i < byteCount; ++i)
		if (p[i] != value)
			return false;
	return true;
}

template <class T>
static bool GuardWipesExactly(T& t, bool leaveByThrow)
{
	std::memset(&t, 0xC3, sizeof(t));
	bool threw = false;
	try { FillThenLeave(t.secret, sizeof(t.secret), leaveByThrow); }
	catch (const Exception&) { threw = true; }
	return threw == leaveByThrow &&
		IsFilledWith(t.secret, sizeof(t.secret), 0) &&
		IsFilledWith(&t.before, sizeof(t.before), 0xC3) &&
		IsFilledWith(&t.after, sizeof(t.after), 0xC3);
}

static bool TestWipeGuard()
{
	GuardedBytes b;
	GuardedWords w;
	bool pass = GuardWipesExactly(b, false);
	pass = GuardWipesExactly(b, true) && pass;
	pass = GuardWipesExactly(w, false) && pass;
	pass = GuardWipesExactly(w, true) && pass;

	std::memset(&b, 0xC3, sizeof(b));
	{
		PQC_Internal::WipeGuard wipe(b.secret, sizeof(b.secret));
		std::memset(b.secret, 0xA5, sizeof(b.secret));
	}
	pass = IsFilledWith(b.secret, sizeof(b.secret), 0) &&
		IsFilledWith(b.before, sizeof(b.before), 0xC3) &&
		IsFilledWith(b.after, sizeof(b.after), 0xC3) && pass;

	std::cout << (pass ? "passed:  " : "FAILED:  ") << "stack wipe guard (5 cases)" << std::endl;
	return pass;
}

// ******************** ML-KEM Validation (FIPS 203) ************************* //

// Fails on the first GenerateBlock call after the allowed count, so a test
// can break key generation between its random draws.
class CountedFailRNG : public RandomNumberGenerator
{
public:
	explicit CountedFailRNG(unsigned int allowed) : m_allowed(allowed) {}
	void GenerateBlock(byte *output, size_t size)
	{
		if (m_allowed == 0)
			throw Exception(Exception::OTHER_ERROR, "CountedFailRNG: no more draws");
		--m_allowed;
		std::memset(output, 0x5a, size);
	}
private:
	unsigned int m_allowed;
};

// Writes half of the requested bytes and then fails.
class PartialWriteFailRNG : public RandomNumberGenerator
{
public:
	void GenerateBlock(byte *output, size_t size)
	{
		std::memset(output, 0x5a, size / 2);
		throw Exception(Exception::OTHER_ERROR, "PartialWriteFailRNG: failed part way");
	}
};

// Key generation draws d and then z. A failure on the second draw must leave
// an existing key exactly as it was.
template <class PARAMS>
static bool TestMLKEMKeyGenFailure(const char* name)
{
	try {
		AutoSeededRandomPool goodRng;
		MLKEMPrivateKey<PARAMS> key;
		key.GenerateRandom(goodRng, g_nullNameValuePairs);
		SecByteBlock before(key.GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);

		CountedFailRNG rng(1);
		bool threw = false;
		try {
			key.GenerateRandom(rng, g_nullNameValuePairs);
		}
		catch (const Exception&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " key generation completed with a failing generator" << std::endl;
			return false;
		}
		if (!VerifyBufsEqual(key.GetPrivateKeyBytePtr(), before, before.size())) {
			std::cout << "FAILED:  " << name << " key changed by failed key generation" << std::endl;
			return false;
		}

		std::cout << "passed:  " << name << " failed key generation leaves key unchanged" << std::endl;
		return true;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " failed key generation - " << e.what() << std::endl;
		return false;
	}
}

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

		// Test with modified ciphertext. This is a smoke test over freshly
		// generated keys; TestMLKEMKAT checks the FIPS 203 rejection
		// value itself against the ACVP vectors.
		SecByteBlock modifiedCt(ciphertext);
		modifiedCt[0] ^= 0xFF;

		SecByteBlock sharedSecret3(decapsulator.SharedSecretLength());
		decapsulator.Decapsulate(modifiedCt, sharedSecret3);

		// A modified ciphertext should not reproduce the valid shared secret
		if (std::memcmp(sharedSecret1.begin(), sharedSecret3.begin(), sharedSecret1.size()) == 0) {
			std::cout << "FAILED:  " << name << " modified ciphertext returned valid shared secret" << std::endl;
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

static SecByteBlock MLKEMFromHex(const std::string& hex)
{
	std::string bin;
	StringSource(hex, true, new HexDecoder(new StringSink(bin)));
	return SecByteBlock(reinterpret_cast<const byte*>(bin.data()), bin.size());
}

struct MLKEMKatRecord
{
	std::string name, comment, d, z, m, ek, dk, ct, ss, keyCheck;
};

// Unlike FixedRNG, throws when asked for more bytes than the seed holds.
class MLKEMKatRNG : public RandomNumberGenerator
{
public:
	explicit MLKEMKatRNG(BufferedTransformation& source) : m_source(source) {}
	void GenerateBlock(byte *output, size_t size)
	{
		if (m_source.MaxRetrievable() < size)
			throw Exception(Exception::OTHER_ERROR, "MLKEMKatRNG: seed exhausted");
		m_source.Get(output, size);
	}
private:
	BufferedTransformation& m_source;
};

// Key generation draws d then z, so a generator holding d || z reproduces
// the NIST key pair through the public constructor.
template <class PARAMS>
static bool MLKEMKeyGenVector(const SecByteBlock& d, const SecByteBlock& z,
	const SecByteBlock& ek, const SecByteBlock& dk)
{
	if (d.size() != 32 || z.size() != 32 ||
		ek.size() != PARAMS::PUBLIC_KEY_SIZE || dk.size() != PARAMS::SECRET_KEY_SIZE)
		return false;

	ByteQueue seed;
	seed.Put(d.begin(), d.size());
	seed.Put(z.begin(), z.size());
	MLKEMKatRNG rng(seed);

	MLKEMDecapsulator<PARAMS> decapsulator(rng);

	if (seed.AnyRetrievable())
		return false;

	return std::memcmp(decapsulator.GetKey().GetPublicKeyBytePtr(), ek.begin(), ek.size()) == 0 &&
		std::memcmp(decapsulator.GetKey().GetPrivateKeyBytePtr(), dk.begin(), dk.size()) == 0;
}

// Encapsulation draws only m.
template <class PARAMS>
static bool MLKEMEncapsVector(const SecByteBlock& ek, const SecByteBlock& m,
	const SecByteBlock& ct, const SecByteBlock& expected)
{
	if (ek.size() != PARAMS::PUBLIC_KEY_SIZE || m.size() != 32 ||
		ct.size() != PARAMS::CIPHERTEXT_SIZE || expected.size() != PARAMS::SHARED_SECRET_SIZE)
		return false;

	ByteQueue seed;
	seed.Put(m.begin(), m.size());
	MLKEMKatRNG rng(seed);

	MLKEMEncapsulator<PARAMS> encapsulator(ek.begin(), ek.size());

	SecByteBlock ciphertext(encapsulator.CiphertextLength());
	SecByteBlock sharedSecret(encapsulator.SharedSecretLength());
	encapsulator.Encapsulate(rng, ciphertext.begin(), sharedSecret.begin());

	if (seed.AnyRetrievable())
		return false;

	return ciphertext == ct && sharedSecret == expected;
}

template <class PARAMS>
static bool MLKEMDecapsVector(const SecByteBlock& dk, const SecByteBlock& ct,
	const SecByteBlock& expected)
{
	if (dk.size() != PARAMS::SECRET_KEY_SIZE || ct.size() != PARAMS::CIPHERTEXT_SIZE ||
		expected.size() != PARAMS::SHARED_SECRET_SIZE)
		return false;

	MLKEMDecapsulator<PARAMS> decapsulator(dk.begin(), dk.size());

	SecByteBlock sharedSecret(decapsulator.SharedSecretLength());
	decapsulator.Decapsulate(ct.begin(), sharedSecret.begin());

	return sharedSecret == expected;
}

// FIPS 203 Section 7.3 hash check.
template <class PARAMS>
static bool MLKEMKeyCheckVector(const SecByteBlock& dk, const std::string& expected)
{
	if (dk.size() != PARAMS::SECRET_KEY_SIZE || (expected != "pass" && expected != "fail"))
		return false;

	bool accepted = true;
	try {
		MLKEMPrivateKey<PARAMS> key;
		key.SetPrivateKey(dk.begin(), dk.size());
	}
	catch (const InvalidArgument&) {
		accepted = false;
	}
	return accepted == (expected == "pass");
}

// FIPS 203 Section 7.2 modulus check.
template <class PARAMS>
static bool MLKEMEncapsKeyCheckVector(const SecByteBlock& ek, const std::string& expected)
{
	if (ek.size() != PARAMS::PUBLIC_KEY_SIZE || (expected != "pass" && expected != "fail"))
		return false;

	bool accepted = true;
	try {
		MLKEMPublicKey<PARAMS> key;
		key.SetPublicKey(ek.begin(), ek.size());
	}
	catch (const InvalidArgument&) {
		accepted = false;
	}
	return accepted == (expected == "pass");
}

template <class PARAMS>
static bool MLKEMKatVector(const std::string& test, const MLKEMKatRecord& r)
{
	if (test == "KeyGen")
		return MLKEMKeyGenVector<PARAMS>(MLKEMFromHex(r.d), MLKEMFromHex(r.z),
			MLKEMFromHex(r.ek), MLKEMFromHex(r.dk));
	if (test == "Encapsulate")
		return MLKEMEncapsVector<PARAMS>(MLKEMFromHex(r.ek), MLKEMFromHex(r.m),
			MLKEMFromHex(r.ct), MLKEMFromHex(r.ss));
	if (test == "Decapsulate")
		return MLKEMDecapsVector<PARAMS>(MLKEMFromHex(r.dk), MLKEMFromHex(r.ct),
			MLKEMFromHex(r.ss));
	if (test == "DecapsulationKeyCheck")
		return MLKEMKeyCheckVector<PARAMS>(MLKEMFromHex(r.dk), r.keyCheck);
	if (test == "EncapsulationKeyCheck")
		return MLKEMEncapsKeyCheckVector<PARAMS>(MLKEMFromHex(r.ek), r.keyCheck);
	throw Exception(Exception::OTHER_ERROR, "ML-KEM KAT: unknown test " + test);
}

static bool MLKEMDispatchKat(const std::string& test, const MLKEMKatRecord& r)
{
	if (r.name == "ML-KEM-512")  return MLKEMKatVector<MLKEM_512>(test, r);
	if (r.name == "ML-KEM-768")  return MLKEMKatVector<MLKEM_768>(test, r);
	if (r.name == "ML-KEM-1024") return MLKEMKatVector<MLKEM_1024>(test, r);
	throw Exception(Exception::OTHER_ERROR, "ML-KEM KAT: unknown parameter set " + r.name);
}

// ACVP vectors. Most decapsulation records carry a ciphertext the key
// rejects, so the expected shared secret is the FIPS 203 implicit-rejection
// value. NIST supplies it, so this checks the rejection path against an
// external reference rather than against our own recomputation of it.
static bool TestMLKEMKAT()
{
	const char* name = "ML-KEM ACVP";

	std::ifstream file(DataDir("TestVectors/mlkem.txt").c_str());
	if (!file) {
		std::cout << "FAILED:  " << name << " cannot open TestVectors/mlkem.txt" << std::endl;
		return false;
	}

	std::string line;
	MLKEMKatRecord r;
	std::map<std::string, unsigned int> coverage;

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

			if (key == "Name") r.name = val;
			else if (key == "Comment") r.comment = val;
			else if (key == "d") r.d = val;
			else if (key == "z") r.z = val;
			else if (key == "m") r.m = val;
			else if (key == "EncapsulationKey") r.ek = val;
			else if (key == "DecapsulationKey") r.dk = val;
			else if (key == "Ciphertext") r.ct = val;
			else if (key == "SharedSecret") r.ss = val;
			else if (key == "KeyCheck") r.keyCheck = val;
			else if (key == "Test") {
				if (!MLKEMDispatchKat(val, r)) {
					std::cout << "FAILED:  " << name << " " << val << " " << r.name
						<< " " << r.comment << " mismatch" << std::endl;
					return false;
				}
				coverage[val + " " + r.name]++;
				r = MLKEMKatRecord();
			}
		}
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}

	// Guard against a truncated or partially converted vector file. The count is
	// pinned deliberately: adding vectors should mean updating it here too.
	static const struct { const char* test; unsigned int perSet; } expected[] = {
		{ "KeyGen", 3 }, { "Encapsulate", 3 }, { "Decapsulate", 3 },
		{ "DecapsulationKeyCheck", 10 }, { "EncapsulationKeyCheck", 10 }
	};
	static const char* const expectedSets[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

	for (size_t t = 0; t < COUNTOF(expected); t++) {
		for (size_t i = 0; i < COUNTOF(expectedSets); i++) {
			const std::string id = std::string(expected[t].test) + " " + expectedSets[i];
			if (coverage[id] != expected[t].perSet) {
				std::cout << "FAILED:  " << name << " " << id
					<< " coverage (" << coverage[id]
					<< " vectors; expected " << expected[t].perSet << ")" << std::endl;
				return false;
			}
		}
		std::cout << "passed:  " << name << " " << expected[t].test << " KAT ("
			<< expected[t].perSet * COUNTOF(expectedSets) << " vectors, "
			<< COUNTOF(expectedSets) << " parameter sets)" << std::endl;
	}
	return true;
}

template <class PARAMS>
static bool TestMLKEMDecodeState(const char* name)
{
	AutoSeededRandomPool rng;
	try {
		MLKEMDecapsulator<PARAMS> a(rng), b(rng);
		bool pass = true;
		pass = TestPqcPublicDecodeState<MLKEMPublicKey<PARAMS> >(name,
			a.GetKey().GetPublicKeyBytePtr(), b.GetKey().GetPublicKeyBytePtr(),
			PARAMS::PUBLIC_KEY_SIZE) && pass;
		pass = TestPqcPrivateDecodeState<MLKEMPrivateKey<PARAMS> >(name,
			a.GetKey().GetPrivateKeyBytePtr(), b.GetKey().GetPrivateKeyBytePtr(),
			PARAMS::SECRET_KEY_SIZE) && pass;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " decode state - " << e.what() << std::endl;
		return false;
	}
}

// A decapsulation key is dkPKE || ek || H(ek) || z. Import must refuse one whose
// hash field does not match its ek (FIPS 203 Section 7.3) and leave the object
// as it was; a key that was never set must not decapsulate.
template <class PARAMS>
static bool TestMLKEMKeyCheck(const char* name)
{
	AutoSeededRandomPool rng;
	try {
		const size_t skLen = PARAMS::SECRET_KEY_SIZE, pkLen = PARAMS::PUBLIC_KEY_SIZE;
		const size_t hashOffset = skLen - 64, ekOffset = hashOffset - pkLen;

		MLKEMDecapsulator<PARAMS> original(rng);
		const SecByteBlock sk(original.GetKey().GetPrivateKeyBytePtr(), skLen);

		MLKEMEncapsulator<PARAMS> encapsulator(original.GetKey().GetPublicKeyBytePtr(), pkLen);
		SecByteBlock ct(encapsulator.CiphertextLength());
		SecByteBlock expected(encapsulator.SharedSecretLength()), got(expected.size());
		encapsulator.Encapsulate(rng, ct.begin(), expected.begin());

		std::string der;
		StringSink sink(der);
		original.GetKey().DEREncode(sink);
		if (der.size() < skLen ||
			!VerifyBufsEqual(reinterpret_cast<const byte*>(der.data()) + der.size() - skLen, sk, skLen)) {
			std::cout << "FAILED:  " << name << " key check: DER does not end with the key (setup)" << std::endl;
			return false;
		}

		bool pass = true;
		static const struct { bool hash; const char* label; } cases[] = {
			{ true, "altered H(ek)" }, { false, "altered ek" }
		};
		for (size_t i = 0; i < COUNTOF(cases); i++)
		{
			const size_t offset = cases[i].hash ? hashOffset : ekOffset;
			SecByteBlock raw(sk);
			raw[offset] ^= 0x01;
			std::string badDer(der);
			badDer[der.size() - skLen + offset] ^= 0x01;

			MLKEMDecapsulator<PARAMS> target(sk.begin(), skLen);

			bool rejected = false;
			try { target.AccessPrivateKey().SetPrivateKey(raw, skLen); }
			catch (const InvalidArgument&) { rejected = true; }
			if (!rejected) {
				std::cout << "FAILED:  " << name << " key check: " << cases[i].label
					<< ", raw import accepted" << std::endl;
				pass = false;
			}
			if (!VerifyBufsEqual(target.GetKey().GetPrivateKeyBytePtr(), sk, skLen)) {
				std::cout << "FAILED:  " << name << " key check: " << cases[i].label
					<< ", key changed after rejected raw import" << std::endl;
				pass = false;
			}

			rejected = false;
			try {
				StringSource source(badDer, true);
				target.AccessPrivateKey().BERDecode(source);
			}
			catch (const InvalidArgument&) { rejected = true; }
			if (!rejected) {
				std::cout << "FAILED:  " << name << " key check: " << cases[i].label
					<< ", DER import accepted" << std::endl;
				pass = false;
			}
			if (!VerifyBufsEqual(target.GetKey().GetPrivateKeyBytePtr(), sk, skLen)) {
				std::cout << "FAILED:  " << name << " key check: " << cases[i].label
					<< ", key changed after rejected DER import" << std::endl;
				pass = false;
			}
		}

		{
			MLKEMDecapsulator<PARAMS> target;
			StringSource source(der, true);
			target.AccessPrivateKey().BERDecode(source);
			target.Decapsulate(ct.begin(), got.begin());
			if (got != expected) {
				std::cout << "FAILED:  " << name << " key check: unaltered DER import" << std::endl;
				pass = false;
			}
		}

		MLKEMPrivateKey<PARAMS> unset;
		if (!original.GetKey().Validate(rng, 0) || !original.GetKey().Validate(rng, 1) ||
			!unset.Validate(rng, 0) || unset.Validate(rng, 1)) {
			std::cout << "FAILED:  " << name << " key check: Validate" << std::endl;
			pass = false;
		}

		MLKEMDecapsulator<PARAMS> empty;
		bool threw = false;
		try { empty.Decapsulate(ct.begin(), got.begin()); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " key check: unset key decapsulated" << std::endl;
			pass = false;
		}

		if (pass)
			std::cout << "passed:  " << name << " decapsulation key check" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " decapsulation key check - " << e.what() << std::endl;
		return false;
	}
}

// An encapsulation key is 12-bit coefficients followed by rho. Import must
// refuse one with a coefficient of q or more (FIPS 203 Section 7.2) and leave
// the object as it was.
template <class PARAMS>
static bool TestMLKEMEncapsKeyCheck(const char* name)
{
	AutoSeededRandomPool rng;
	try {
		const size_t pkLen = PARAMS::PUBLIC_KEY_SIZE;
		const size_t last = pkLen - 32 - 1;

		MLKEMDecapsulator<PARAMS> original(rng);
		const SecByteBlock pk(original.GetKey().GetPublicKeyBytePtr(), pkLen);

		MLKEMPublicKey<PARAMS> pubKey;
		pubKey.SetPublicKey(pk, pkLen);
		std::string der;
		StringSink sink(der);
		pubKey.DEREncode(sink);
		if (der.size() < pkLen ||
			!VerifyBufsEqual(reinterpret_cast<const byte*>(der.data()) + der.size() - pkLen, pk, pkLen)) {
			std::cout << "FAILED:  " << name << " encapsulation key check: DER does not end with the key (setup)" << std::endl;
			return false;
		}

		// Each case sets one coefficient to q (3329, 0xD01), the smallest rejected value.
		bool pass = true;
		static const struct { bool first; const char* label; } cases[] = {
			{ true, "first coefficient" }, { false, "last coefficient" }
		};
		for (size_t i = 0; i < COUNTOF(cases); i++)
		{
			SecByteBlock raw(pk);
			if (cases[i].first) {
				raw[0] = 0x01;
				raw[1] = static_cast<byte>((raw[1] & 0xF0) | 0x0D);
			}
			else {
				raw[last] = 0xD0;
				raw[last - 1] = static_cast<byte>((raw[last - 1] & 0x0F) | 0x10);
			}
			std::string badDer(der);
			badDer.replace(der.size() - pkLen, pkLen, reinterpret_cast<const char*>(raw.begin()), pkLen);

			MLKEMPublicKey<PARAMS> target;
			target.SetPublicKey(pk, pkLen);

			bool rejected = false;
			try { target.SetPublicKey(raw, pkLen); }
			catch (const InvalidArgument&) { rejected = true; }
			if (!rejected) {
				std::cout << "FAILED:  " << name << " encapsulation key check: " << cases[i].label
					<< ", raw import accepted" << std::endl;
				pass = false;
			}
			if (!VerifyBufsEqual(target.GetPublicKeyBytePtr(), pk, pkLen)) {
				std::cout << "FAILED:  " << name << " encapsulation key check: " << cases[i].label
					<< ", key changed after rejected raw import" << std::endl;
				pass = false;
			}

			rejected = false;
			try {
				StringSource source(badDer, true);
				target.BERDecode(source);
			}
			catch (const InvalidArgument&) { rejected = true; }
			if (!rejected) {
				std::cout << "FAILED:  " << name << " encapsulation key check: " << cases[i].label
					<< ", DER import accepted" << std::endl;
				pass = false;
			}
			if (!VerifyBufsEqual(target.GetPublicKeyBytePtr(), pk, pkLen)) {
				std::cout << "FAILED:  " << name << " encapsulation key check: " << cases[i].label
					<< ", key changed after rejected DER import" << std::endl;
				pass = false;
			}
		}

		if (pass)
			std::cout << "passed:  " << name << " encapsulation key check" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " encapsulation key check - " << e.what() << std::endl;
		return false;
	}
}

// The DER fixtures must be keys that pass the import checks. This is the key
// pair of NIST ACVP keyGen tcId=1 (TestVectors/mlkem.txt), from its d and z.
static SecByteBlock MLKEM512FixtureKey(bool privateKey)
{
	const SecByteBlock d = MLKEMFromHex("bba3c0f5df044cdf4d9caa53ca15fde26f34eb3541555cfc54ca9c31b964d0c8");
	const SecByteBlock z = MLKEMFromHex("0a64fdd51a8d91b3166c4958a94efc3166a4f5df680980b878db8371b7624c96");
	ByteQueue seed;
	seed.Put(d.begin(), d.size());
	seed.Put(z.begin(), z.size());
	MLKEMKatRNG rng(seed);
	MLKEMDecapsulator<MLKEM_512> decapsulator(rng);
	if (privateKey)
		return SecByteBlock(decapsulator.GetKey().GetPrivateKeyBytePtr(), MLKEM_512::SECRET_KEY_SIZE);
	return SecByteBlock(decapsulator.GetKey().GetPublicKeyBytePtr(), MLKEM_512::PUBLIC_KEY_SIZE);
}

bool ValidateMLKEM()
{
	std::cout << "\nML-KEM (FIPS 203) validation suite running...\n\n";
	bool pass = true;

	pass = TestWipeGuard() && pass;

	// ML-KEM-512
	pass = TestMLKEMKeyGen<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMKeyGenFailure<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMSerialization<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMSaveLoad<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMKeyCheck<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMEncapsKeyCheck<MLKEM_512>("ML-KEM-512") && pass;

	// ML-KEM-768
	pass = TestMLKEMKeyGen<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMSerialization<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMSaveLoad<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMKeyCheck<MLKEM_768>("ML-KEM-768") && pass;
	pass = TestMLKEMEncapsKeyCheck<MLKEM_768>("ML-KEM-768") && pass;

	// ML-KEM-1024
	pass = TestMLKEMKeyGen<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMEncapsDecaps<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMSerialization<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMSaveLoad<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMKeyCheck<MLKEM_1024>("ML-KEM-1024") && pass;
	pass = TestMLKEMEncapsKeyCheck<MLKEM_1024>("ML-KEM-1024") && pass;

	// ACVP known-answer vectors, covering the implicit-rejection path
	pass = TestMLKEMKAT() && pass;

	pass = TestMLKEMDecodeState<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestPqcEncodeGuard<MLKEM_512, MLKEMPublicKey<MLKEM_512>, MLKEMPrivateKey<MLKEM_512> >(
		"ML-KEM-512", true) && pass;
	pass = TestPqcDerFixtures<MLKEM_512, MLKEMPublicKey<MLKEM_512>, MLKEMPrivateKey<MLKEM_512> >("ML-KEM-512",
		MLKEM512FixtureKey(true), "A2753D4328E90F030DCF3965622CCDD693EE4E16B5F5C6D0CC793FF84B349C56",
		MLKEM512FixtureKey(false), "8DE855B1A6BC0111541F9753BD80BFDA93AC8D5956BDC0CC369AA86088170776") && pass;

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

template <class PARAMS>
static bool TestMLDSADecodeState(const char* name)
{
	AutoSeededRandomPool rng;
	try {
		MLDSASigner<PARAMS> a(rng), b(rng);
		bool pass = true;
		pass = TestPqcPublicDecodeState<MLDSAPublicKey<PARAMS> >(name,
			a.GetKey().GetPublicKeyBytePtr(), b.GetKey().GetPublicKeyBytePtr(),
			PARAMS::PUBLIC_KEY_SIZE) && pass;
		pass = TestPqcPrivateDecodeState<MLDSAPrivateKey<PARAMS> >(name,
			a.GetKey().GetPrivateKeyBytePtr(), b.GetKey().GetPrivateKeyBytePtr(),
			PARAMS::SECRET_KEY_SIZE) && pass;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " decode state - " << e.what() << std::endl;
		return false;
	}
}

template <class PARAMS>
static bool MLDSAKeyMatches(const MLDSAPrivateKey<PARAMS>& key, const byte* sk, const byte* pk)
{
	return key.GetPrivateKeyBytePtr() && key.GetPublicKeyBytePtr() &&
		VerifyBufsEqual(key.GetPrivateKeyBytePtr(), sk, PARAMS::SECRET_KEY_SIZE) &&
		VerifyBufsEqual(key.GetPublicKeyBytePtr(), pk, PARAMS::PUBLIC_KEY_SIZE);
}

template <class PARAMS>
static bool MLDSASignsAndVerifies(RandomNumberGenerator& rng, const MLDSAPrivateKey<PARAMS>& key)
{
	MLDSASigner<PARAMS> signer(key.GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);
	MLDSAVerifier<PARAMS> verifier(key.GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);
	const byte message[] = "after a failed key operation";
	SecByteBlock signature(signer.SignatureLength());
	size_t sigLen = signer.SignMessage(rng, message, sizeof(message), signature);
	return verifier.VerifyMessage(message, sizeof(message), signature, sigLen);
}

// Failed generation or import must leave the key unchanged.
template <class PARAMS>
static bool TestMLDSAKeyStateOnFailure(const char* name)
{
	typedef MLDSAPrivateKey<PARAMS> PrivKey;
	const size_t skLen = PARAMS::SECRET_KEY_SIZE;
	const size_t pkLen = PARAMS::PUBLIC_KEY_SIZE;
	try {
		AutoSeededRandomPool rng;
		CountedFailRNG failRng(0);
		bool pass = true;

		PrivKey key;
		bool threw = false;
		try { key.GenerateRandom(failRng, g_nullNameValuePairs); }
		catch (const Exception&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " key generation completed with a failing generator" << std::endl;
			pass = false;
		}
		if (key.Validate(rng, 3) || key.GetPrivateKeyBytePtr() || key.GetPublicKeyBytePtr()) {
			std::cout << "FAILED:  " << name << " failed key generation left key data behind" << std::endl;
			pass = false;
		}
		threw = false;
		try {
			std::string der;
			StringSink sink(der);
			key.Save(sink);
		}
		catch (const InvalidArgument&) { threw = true; }
		if (!threw) {
			std::cout << "FAILED:  " << name << " failed key generation left a key that encodes" << std::endl;
			pass = false;
		}

		key.GenerateRandom(rng, g_nullNameValuePairs);
		if (!key.Validate(rng, 3) || !MLDSASignsAndVerifies<PARAMS>(rng, key)) {
			std::cout << "FAILED:  " << name << " key generation retry after failure" << std::endl;
			pass = false;
		}

		SecByteBlock sk(key.GetPrivateKeyBytePtr(), skLen);
		SecByteBlock pk(key.GetPublicKeyBytePtr(), pkLen);
		PrivKey other;
		other.GenerateRandom(rng, g_nullNameValuePairs);

		threw = false;
		try { key.GenerateRandom(failRng, g_nullNameValuePairs); }
		catch (const Exception&) { threw = true; }
		if (!threw || !MLDSAKeyMatches<PARAMS>(key, sk, pk)) {
			std::cout << "FAILED:  " << name << " key changed by failed key generation" << std::endl;
			pass = false;
		}

		threw = false;
		try { key.SetPrivateKey(other.GetPrivateKeyBytePtr(), skLen - 1); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw || !MLDSAKeyMatches<PARAMS>(key, sk, pk)) {
			std::cout << "FAILED:  " << name << " key changed by a rejected private key length" << std::endl;
			pass = false;
		}

		threw = false;
		try { key.SetPrivateKey(NULLPTR, skLen); }
		catch (const InvalidArgument&) { threw = true; }
		if (!threw || !MLDSAKeyMatches<PARAMS>(key, sk, pk)) {
			std::cout << "FAILED:  " << name << " key changed by a rejected null private key" << std::endl;
			pass = false;
		}

		key.SetPrivateKey(key.GetPrivateKeyBytePtr(), skLen);
		if (!MLDSAKeyMatches<PARAMS>(key, sk, pk)) {
			std::cout << "FAILED:  " << name << " key changed by importing its own private key" << std::endl;
			pass = false;
		}

		key.SetPrivateKey(other.GetPrivateKeyBytePtr(), skLen);
		if (!MLDSAKeyMatches<PARAMS>(key, other.GetPrivateKeyBytePtr(), other.GetPublicKeyBytePtr()) ||
			!MLDSASignsAndVerifies<PARAMS>(rng, key)) {
			std::cout << "FAILED:  " << name << " private key replacement mismatch" << std::endl;
			pass = false;
		}

		if (pass)
			std::cout << "passed:  " << name << " key state after failure (7 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " key state after failure - " << e.what() << std::endl;
		return false;
	}
}

// A generator that fails during signing, before or part way through its
// write, must not stop the signer from signing afterwards.
template <class PARAMS>
static bool TestMLDSASignFailure(const char* name)
{
	try {
		AutoSeededRandomPool rng;
		MLDSASigner<PARAMS> signer(rng);
		MLDSAVerifier<PARAMS> verifier(signer);
		const byte message[] = "signing with a failing generator";
		SecByteBlock signature(signer.SignatureLength());
		bool pass = true;

		CountedFailRNG failBefore(0);
		PartialWriteFailRNG failPartWay;
		RandomNumberGenerator* failing[] = { &failBefore, &failPartWay };
		for (unsigned int i = 0; i < 2; i++) {
			bool threw = false;
			try { signer.SignMessage(*failing[i], message, sizeof(message), signature); }
			catch (const Exception&) { threw = true; }
			if (!threw) {
				std::cout << "FAILED:  " << name << " signing completed with a failing generator" << std::endl;
				pass = false;
			}
			size_t sigLen = signer.SignMessage(rng, message, sizeof(message), signature);
			if (!verifier.VerifyMessage(message, sizeof(message), signature, sigLen)) {
				std::cout << "FAILED:  " << name << " signing after a generator failure" << std::endl;
				pass = false;
			}
		}

		if (pass)
			std::cout << "passed:  " << name << " signing after a generator failure (2 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " signing after a generator failure - " << e.what() << std::endl;
		return false;
	}
}

// One record of TestVectors/mldsa.txt, keyed by field name. Reading a field
// the record lacks throws, so a deleted line is a parse error, while a present
// but empty Message or Context is a legitimate value.
typedef std::map<std::string, std::string> MLDSAKatRecord;

static const std::string& MLDSAField(const MLDSAKatRecord& r, const char* field)
{
	MLDSAKatRecord::const_iterator it = r.find(field);
	if (it == r.end()) {
		MLDSAKatRecord::const_iterator n = r.find("Name");
		throw Exception(Exception::OTHER_ERROR, "ML-DSA KAT: " +
			(n == r.end() ? std::string("record") : n->second + " record") + " without " + field);
	}
	return it->second;
}

static SecByteBlock MLDSAFromHex(const std::string& hex)
{
	std::string bin;
	StringSource(hex, true, new HexDecoder(new StringSink(bin)));
	return SecByteBlock(reinterpret_cast<const byte*>(bin.data()), bin.size());
}

// Key generation draws the 32-byte seed, so a generator holding it
// reproduces the NIST key pair through the public constructor.
template <class PARAMS>
static bool MLDSAKeyGenVector(const SecByteBlock& seed, const SecByteBlock& pk,
	const SecByteBlock& sk)
{
	if (seed.size() != 32 ||
		pk.size() != PARAMS::PUBLIC_KEY_SIZE || sk.size() != PARAMS::SECRET_KEY_SIZE)
		return false;

	ByteQueue queue;
	queue.Put(seed.begin(), seed.size());
	MLKEMKatRNG rng(queue);

	MLDSASigner<PARAMS> signer(rng);

	if (queue.AnyRetrievable())
		return false;

	return std::memcmp(signer.GetKey().GetPublicKeyBytePtr(), pk.begin(), pk.size()) == 0 &&
		std::memcmp(signer.GetKey().GetPrivateKeyBytePtr(), sk.begin(), sk.size()) == 0;
}

// Hedged signing draws only the 32-byte rnd.
template <class PARAMS>
static bool MLDSASigGenVector(const SecByteBlock& sk, const SecByteBlock& msg,
	const SecByteBlock& ctx, const SecByteBlock& rnd, const SecByteBlock& sig)
{
	if (sk.size() != PARAMS::SECRET_KEY_SIZE || rnd.size() != 32 ||
		sig.size() != PARAMS::SIGNATURE_SIZE)
		return false;

	MLDSASigner<PARAMS> signer(sk.begin(), sk.size());
	MLDSA_MessageAccumulator<PARAMS> accum;
	accum.SetContext(ctx.begin(), ctx.size());
	accum.Update(msg.begin(), msg.size());

	ByteQueue queue;
	queue.Put(rnd.begin(), rnd.size());
	MLKEMKatRNG rng(queue);

	SecByteBlock signature(signer.SignatureLength());
	const size_t length = signer.SignAndRestart(rng, accum, signature.begin());

	if (queue.AnyRetrievable())
		return false;

	return length == sig.size() && std::memcmp(signature.begin(), sig.begin(), length) == 0;
}

// Every record carries a full-length key and signature; the rejected ones
// fail inside the verifier, not at the length checks.
template <class PARAMS>
static bool MLDSASigVerVector(const SecByteBlock& pk, const SecByteBlock& msg,
	const SecByteBlock& ctx, const SecByteBlock& sig, bool expected)
{
	if (pk.size() != PARAMS::PUBLIC_KEY_SIZE || sig.size() != PARAMS::SIGNATURE_SIZE)
		return false;

	MLDSAVerifier<PARAMS> verifier(pk.begin(), pk.size());
	MLDSA_MessageAccumulator<PARAMS> accum;
	accum.SetContext(ctx.begin(), ctx.size());
	verifier.InputSignature(accum, sig.begin(), sig.size());
	accum.Update(msg.begin(), msg.size());
	return verifier.VerifyAndRestart(accum) == expected;
}

template <class PARAMS>
static bool MLDSAKatVector(const std::string& test, const MLDSAKatRecord& r)
{
	if (test == "KeyGen")
		return MLDSAKeyGenVector<PARAMS>(MLDSAFromHex(MLDSAField(r, "Seed")),
			MLDSAFromHex(MLDSAField(r, "PublicKey")), MLDSAFromHex(MLDSAField(r, "SecretKey")));
	if (test == "SigGen")
		return MLDSASigGenVector<PARAMS>(MLDSAFromHex(MLDSAField(r, "SecretKey")),
			MLDSAFromHex(MLDSAField(r, "Message")), MLDSAFromHex(MLDSAField(r, "Context")),
			MLDSAFromHex(MLDSAField(r, "Rnd")), MLDSAFromHex(MLDSAField(r, "Signature")));
	if (test == "SigVer") {
		const std::string& passed = MLDSAField(r, "TestPassed");
		if (passed != "true" && passed != "false")
			throw Exception(Exception::OTHER_ERROR, "ML-DSA KAT: " + MLDSAField(r, "Name") + " TestPassed is " + passed);
		return MLDSASigVerVector<PARAMS>(MLDSAFromHex(MLDSAField(r, "PublicKey")),
			MLDSAFromHex(MLDSAField(r, "Message")), MLDSAFromHex(MLDSAField(r, "Context")),
			MLDSAFromHex(MLDSAField(r, "Signature")), passed == "true");
	}
	throw Exception(Exception::OTHER_ERROR, "ML-DSA KAT: unknown test " + test);
}

static bool MLDSADispatchKat(const std::string& test, const MLDSAKatRecord& r)
{
	const std::string& name = MLDSAField(r, "Name");
	if (name == "ML-DSA-44") return MLDSAKatVector<MLDSA_44>(test, r);
	if (name == "ML-DSA-65") return MLDSAKatVector<MLDSA_65>(test, r);
	if (name == "ML-DSA-87") return MLDSAKatVector<MLDSA_87>(test, r);
	throw Exception(Exception::OTHER_ERROR, "ML-DSA KAT: unknown parameter set " + name);
}

// ACVP vectors through the external (pure) interface. The verification
// records include signatures NIST expects to be rejected.
static bool TestMLDSAKAT()
{
	const char* name = "ML-DSA ACVP";

	std::ifstream file(DataDir("TestVectors/mldsa.txt").c_str());
	if (!file) {
		std::cout << "FAILED:  " << name << " cannot open TestVectors/mldsa.txt" << std::endl;
		return false;
	}

	std::string line;
	MLDSAKatRecord r;
	std::map<std::string, unsigned int> coverage;

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

			if (key == "Test") {
				if (!MLDSADispatchKat(val, r)) {
					std::cout << "FAILED:  " << name << " " << val << " " << r["Name"]
						<< (r.count("Comment") ? " " + r["Comment"] : "") << " mismatch" << std::endl;
					return false;
				}
				coverage[val + " " + r["Name"]]++;
				r.clear();
			}
			else
				r[key] = val;
		}
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}

	// Guard against a truncated vector file. The counts are pinned
	// deliberately: adding vectors should mean updating them here too.
	struct Expected { const char* test; unsigned int perSet; };
	static const Expected expectedTests[] = { { "KeyGen", 1 }, { "SigGen", 1 }, { "SigVer", 3 } };
	static const char* const expectedSets[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

	for (size_t t = 0; t < COUNTOF(expectedTests); t++) {
		for (size_t i = 0; i < COUNTOF(expectedSets); i++) {
			const std::string id = std::string(expectedTests[t].test) + " " + expectedSets[i];
			if (coverage[id] != expectedTests[t].perSet) {
				std::cout << "FAILED:  " << name << " " << id
					<< " coverage (" << coverage[id]
					<< " vectors; expected " << expectedTests[t].perSet << ")" << std::endl;
				return false;
			}
		}
		std::cout << "passed:  " << name << " " << expectedTests[t].test << " KAT ("
			<< expectedTests[t].perSet * COUNTOF(expectedSets) << " vectors, "
			<< COUNTOF(expectedSets) << " parameter sets)" << std::endl;
	}
	return true;
}

bool ValidateMLDSA()
{
	std::cout << "\nML-DSA (FIPS 204) validation suite running...\n\n";
	bool pass = true;

	// NIST ACVP known-answer tests
	pass = TestMLDSAKAT() && pass;

	// Context argument bounds
	pass = TestMLDSAContext<MLDSA_44>("ML-DSA-44") && pass;

	// ML-DSA-44
	pass = TestMLDSAKeyGen<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSAKeyStateOnFailure<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASignVerify<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASignFailure<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASerialization<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestMLDSASaveLoad<MLDSA_44>("ML-DSA-44") && pass;

	// ML-DSA-65
	pass = TestMLDSAKeyGen<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSAKeyStateOnFailure<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASignVerify<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASignFailure<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASerialization<MLDSA_65>("ML-DSA-65") && pass;
	pass = TestMLDSASaveLoad<MLDSA_65>("ML-DSA-65") && pass;

	// ML-DSA-87
	pass = TestMLDSAKeyGen<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSAKeyStateOnFailure<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASignVerify<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASignFailure<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASerialization<MLDSA_87>("ML-DSA-87") && pass;
	pass = TestMLDSASaveLoad<MLDSA_87>("ML-DSA-87") && pass;

	pass = TestMLDSADecodeState<MLDSA_44>("ML-DSA-44") && pass;
	pass = TestPqcEncodeGuard<MLDSA_44, MLDSAPublicKey<MLDSA_44>, MLDSAPrivateKey<MLDSA_44> >(
		"ML-DSA-44", false) && pass;
	pass = TestPqcDerFixtures<MLDSA_44, MLDSAPublicKey<MLDSA_44>, MLDSAPrivateKey<MLDSA_44> >("ML-DSA-44",
		0x77, "7D22109CEF3717A65787BD69460EEC6F978413EF92A604BEF0CA8AFEFCE099FA",
		0x88, "693E1FA426C9FE75B316AD56F2CBC3308219739A6AFBC2DB805D76D3575F8FDF") && pass;

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

// Key generation draws SK.seed, SK.prf and PK.seed in turn. A failure before
// the first draw, between any two draws, or part way through a draw must
// leave an existing key pair exactly as it was.
template <class PARAMS>
static bool TestSLHDSAKeyGenFailure(const char* name)
{
	try {
		AutoSeededRandomPool goodRng;
		SLHDSAPrivateKey<PARAMS> key;
		key.GenerateRandom(goodRng, g_nullNameValuePairs);
		SecByteBlock before(key.GetPrivateKeyBytePtr(), PARAMS::SECRET_KEY_SIZE);
		SecByteBlock beforePub(key.GetPublicKeyBytePtr(), PARAMS::PUBLIC_KEY_SIZE);
		bool pass = true;

		CountedFailRNG failFirst(0), failSecond(1), failThird(2);
		PartialWriteFailRNG failPartWay;
		RandomNumberGenerator* failing[] = { &failFirst, &failSecond, &failThird, &failPartWay };
		for (unsigned int i = 0; i < 4; i++) {
			bool threw = false;
			try { key.GenerateRandom(*failing[i], g_nullNameValuePairs); }
			catch (const Exception&) { threw = true; }
			if (!threw) {
				std::cout << "FAILED:  " << name << " key generation completed with a failing generator" << std::endl;
				pass = false;
			}
			if (!VerifyBufsEqual(key.GetPrivateKeyBytePtr(), before, before.size()) ||
				!VerifyBufsEqual(key.GetPublicKeyBytePtr(), beforePub, beforePub.size())) {
				std::cout << "FAILED:  " << name << " key pair changed by failed key generation" << std::endl;
				pass = false;
			}
		}

		if (pass)
			std::cout << "passed:  " << name << " failed key generation leaves key unchanged (4 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " failed key generation - " << e.what() << std::endl;
		return false;
	}
}

// A generator that fails during signing, before or part way through its
// write, must not stop the signer from signing afterwards.
template <class PARAMS>
static bool TestSLHDSASignFailure(const char* name)
{
	try {
		AutoSeededRandomPool rng;
		SLHDSASigner<PARAMS> signer(rng);
		SLHDSAVerifier<PARAMS> verifier(signer);
		const byte message[] = "signing with a failing generator";
		SecByteBlock signature(signer.SignatureLength());
		bool pass = true;

		CountedFailRNG failBefore(0);
		PartialWriteFailRNG failPartWay;
		RandomNumberGenerator* failing[] = { &failBefore, &failPartWay };
		for (unsigned int i = 0; i < 2; i++) {
			bool threw = false;
			try { signer.SignMessage(*failing[i], message, sizeof(message), signature); }
			catch (const Exception&) { threw = true; }
			if (!threw) {
				std::cout << "FAILED:  " << name << " signing completed with a failing generator" << std::endl;
				pass = false;
			}
			size_t sigLen = signer.SignMessage(rng, message, sizeof(message), signature);
			if (!verifier.VerifyMessage(message, sizeof(message), signature, sigLen)) {
				std::cout << "FAILED:  " << name << " signing after a generator failure" << std::endl;
				pass = false;
			}
		}

		if (pass)
			std::cout << "passed:  " << name << " signing after a generator failure (2 cases)" << std::endl;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " signing after a generator failure - " << e.what() << std::endl;
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

template <class PARAMS>
static bool TestSLHDSADecodeState(const char* name)
{
	AutoSeededRandomPool rng;
	try {
		SLHDSASigner<PARAMS> a(rng), b(rng);
		bool pass = true;
		pass = TestPqcPublicDecodeState<SLHDSAPublicKey<PARAMS> >(name,
			a.GetKey().GetPublicKeyBytePtr(), b.GetKey().GetPublicKeyBytePtr(),
			PARAMS::PUBLIC_KEY_SIZE) && pass;
		pass = TestPqcPrivateDecodeState<SLHDSAPrivateKey<PARAMS> >(name,
			a.GetKey().GetPrivateKeyBytePtr(), b.GetKey().GetPrivateKeyBytePtr(),
			PARAMS::SECRET_KEY_SIZE) && pass;
		return pass;
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " decode state - " << e.what() << std::endl;
		return false;
	}
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
	pass = TestSLHDSAKeyGenFailure<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASignFailure<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestSLHDSASaveLoad<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;

	// SHAKE variants
	pass = TestSLHDSAKeyGen<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSAKeyGenFailure<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASignFailure<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASerialization<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;
	pass = TestSLHDSASaveLoad<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f") && pass;

	// One small variant
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;
	pass = TestSLHDSASignVerify<SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s") && pass;

	// Higher security-level size checks
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_192f>("SLH-DSA-SHA2-192f") && pass;
	pass = TestSLHDSAKeyGen<SLHDSA_SHA2_256f>("SLH-DSA-SHA2-256f") && pass;

	pass = TestSLHDSADecodeState<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f") && pass;
	pass = TestPqcEncodeGuard<SLHDSA_SHA2_128f, SLHDSAPublicKey<SLHDSA_SHA2_128f>, SLHDSAPrivateKey<SLHDSA_SHA2_128f> >(
		"SLH-DSA-SHA2-128f", true) && pass;
	pass = TestPqcDerFixtures<SLHDSA_SHA2_128f, SLHDSAPublicKey<SLHDSA_SHA2_128f>, SLHDSAPrivateKey<SLHDSA_SHA2_128f> >("SLH-DSA-SHA2-128f",
		0xbb, "77D041C07123CCEC0712990D7483BE51F68BA73CFDE9687316AE74577550B8D1",
		0xcc, "CF8BE8CB315BB7D9C50AC16D6905D6AC6D6A7D12BF6E63BEF983D320972F2E47") && pass;

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

struct XWingKatRecord
{
	std::string name, seed, pk, eseed, ct, ss;
};

// Encapsulation draws the ML-KEM message and then the X25519 ephemeral key,
// which is the layout of the draft's 64-byte eseed.
static bool XWingKatVector(const XWingKatRecord& r)
{
	const SecByteBlock seed = MLKEMFromHex(r.seed), pk = MLKEMFromHex(r.pk),
		eseed = MLKEMFromHex(r.eseed), ct = MLKEMFromHex(r.ct), ss = MLKEMFromHex(r.ss);

	if (seed.size() != XWING_Constants::SEED_SIZE || pk.size() != XWING_Constants::PUBLIC_KEY_SIZE ||
		eseed.size() != 64 || ct.size() != XWING_Constants::CIPHERTEXT_SIZE ||
		ss.size() != XWING_Constants::SHARED_SECRET_SIZE)
		return false;

	XWingDecapsulator decapsulator;
	decapsulator.AccessPrivateKey().GenerateFromSeed(seed.begin());

	SecByteBlock publicKey(XWING_Constants::PUBLIC_KEY_SIZE);
	decapsulator.GetKey().GetPublicKey(publicKey);
	if (publicKey != pk)
		return false;

	ByteQueue source;
	source.Put(eseed.begin(), eseed.size());
	MLKEMKatRNG rng(source);

	XWingEncapsulator encapsulator(pk.begin(), pk.size());
	SecByteBlock ciphertext(encapsulator.CiphertextLength());
	SecByteBlock sent(encapsulator.SharedSecretLength());
	encapsulator.Encapsulate(rng, ciphertext, sent);

	if (source.AnyRetrievable() || ciphertext != ct || sent != ss)
		return false;

	SecByteBlock received(decapsulator.SharedSecretLength());
	return decapsulator.Decapsulate(ct, received) && received == ss;
}

// draft-connolly-cfrg-xwing-kem-09, Appendix C.
static bool TestXWingKAT()
{
	const char* name = "X-Wing draft";

	std::ifstream file(DataDir("TestVectors/xwing.txt").c_str());
	if (!file) {
		std::cout << "FAILED:  " << name << " cannot open TestVectors/xwing.txt" << std::endl;
		return false;
	}

	std::string line;
	XWingKatRecord r;
	unsigned int count = 0;

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

			if (key == "Name") r.name = val;
			else if (key == "Seed") r.seed = val;
			else if (key == "PublicKey") r.pk = val;
			else if (key == "Eseed") r.eseed = val;
			else if (key == "Ciphertext") r.ct = val;
			else if (key == "SharedSecret") r.ss = val;
			else if (key == "Test") {
				if (!XWingKatVector(r)) {
					std::cout << "FAILED:  " << name << " " << r.name << " mismatch" << std::endl;
					return false;
				}
				count++;
				r = XWingKatRecord();
			}
		}
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}

	// Pinned so that a truncated vector file fails.
	const unsigned int expected = 3;
	if (count != expected) {
		std::cout << "FAILED:  " << name << " coverage (" << count
			<< " vectors; expected " << expected << ")" << std::endl;
		return false;
	}

	std::cout << "passed:  " << name << " KAT (" << count << " vectors)" << std::endl;
	return true;
}

// X25519 maps a small-order point to 32 zero bytes, so a ciphertext carrying
// one must decapsulate to the combiner value over that all-zero secret.
static bool TestXWingSmallOrderShare()
{
	const char* name = "X-Wing small-order X25519 share";

	// u = 0, u = 1, a point of order 8, and u = p - 1.
	static const byte shares[][32] = {
		{0x00},
		{0x01},
		{0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
		 0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00},
		{0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f}
	};
	static const byte label[] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};
	static const byte zero[32] = {0};

	try {
		byte seed[XWING_Constants::SEED_SIZE], eseed[64];
		for (size_t i = 0; i < sizeof(seed); i++)
			seed[i] = static_cast<byte>(i);
		for (size_t i = 0; i < sizeof(eseed); i++)
			eseed[i] = static_cast<byte>(0x80 + i);

		XWingDecapsulator decapsulator;
		decapsulator.AccessPrivateKey().GenerateFromSeed(seed);

		SecByteBlock pubKey(XWING_Constants::PUBLIC_KEY_SIZE);
		decapsulator.GetKey().GetPublicKey(pubKey);

		ByteQueue source;
		source.Put(eseed, sizeof(eseed));
		MLKEMKatRNG rng(source);

		XWingEncapsulator encapsulator(pubKey.begin(), pubKey.size());
		SecByteBlock ciphertext(encapsulator.CiphertextLength());
		SecByteBlock sent(encapsulator.SharedSecretLength());
		encapsulator.Encapsulate(rng, ciphertext, sent);

		// The ML-KEM half of the ciphertext is left alone, so its secret is
		// the same for every case.
		MLKEMDecapsulator<MLKEM_768> mlkem(
			decapsulator.GetPrivateKey().GetMLKEMPrivateKeyPtr(), MLKEM_768::SECRET_KEY_SIZE);
		SecByteBlock mlkemSecret(mlkem.SharedSecretLength());
		mlkem.Decapsulate(ciphertext, mlkemSecret);

		byte* share = ciphertext.begin() + MLKEM_768::CIPHERTEXT_SIZE;
		const byte* x25519Public = pubKey.begin() + MLKEM_768::PUBLIC_KEY_SIZE;

		// The first pass keeps the sender's share, which must not give the
		// all-zero value.
		for (size_t i = 0; i <= COUNTOF(shares); i++) {
			const bool honest = (i == 0);
			if (!honest)
				std::memcpy(share, shares[i - 1], 32);

			byte expected[32];
			SHA3_256 hash;
			hash.Update(mlkemSecret, mlkemSecret.size());
			hash.Update(zero, sizeof(zero));
			hash.Update(share, 32);
			hash.Update(x25519Public, 32);
			hash.Update(label, sizeof(label));
			hash.Final(expected);

			SecByteBlock received(decapsulator.SharedSecretLength());
			if (!decapsulator.Decapsulate(ciphertext, received)) {
				std::cout << "FAILED:  " << name << " - decapsulation returned false" << std::endl;
				return false;
			}

			const bool match = std::memcmp(received, expected, sizeof(expected)) == 0;
			if (honest ? (match || received != sent) : !match) {
				std::cout << "FAILED:  " << name << " - case " << i << std::endl;
				return false;
			}
		}
	}
	catch (const Exception& e) {
		std::cout << "FAILED:  " << name << " - " << e.what() << std::endl;
		return false;
	}

	std::cout << "passed:  " << name << std::endl;
	return true;
}

static bool TestXWingUnsetKeys()
{
	// Heap objects, so a run with malloc fill shows any storage left unwritten.
	member_ptr<XWingPrivateKey> priv(new XWingPrivateKey);
	member_ptr<XWingPublicKey> pub(new XWingPublicKey);

	byte acc = 0;
	for (size_t i = 0; i < MLKEM_768::SECRET_KEY_SIZE; ++i)
		acc |= priv->GetMLKEMPrivateKeyPtr()[i];
	for (size_t i = 0; i < 32; ++i)
		acc |= priv->GetX25519PrivateKeyPtr()[i] | priv->GetX25519PublicKeyPtr()[i];
	for (size_t i = 0; i < XWING_Constants::PUBLIC_KEY_SIZE; ++i)
		acc |= pub->GetPublicKeyBytePtr()[i];

	if (acc != 0)
	{
		std::cout << "FAILED:  X-Wing unset keys are all zero" << std::endl;
		return false;
	}

	std::cout << "passed:  X-Wing unset keys are all zero" << std::endl;
	return true;
}

// The ML-KEM half of an unset X-Wing key is all zero, which fails the ML-KEM
// decapsulation key check.
static bool TestXWingUnsetDecapsulate()
{
	XWingDecapsulator decapsulator;
	SecByteBlock ct(decapsulator.CiphertextLength()), ss(decapsulator.SharedSecretLength());
	std::memset(ct, 0, ct.size());

	bool threw = false;
	try { decapsulator.Decapsulate(ct.begin(), ss.begin()); }
	catch (const InvalidArgument&) { threw = true; }

	if (!threw)
	{
		std::cout << "FAILED:  X-Wing unset key decapsulated" << std::endl;
		return false;
	}

	std::cout << "passed:  X-Wing unset key does not decapsulate" << std::endl;
	return true;
}

bool ValidateXWing()
{
	std::cout << "\nX-Wing (Hybrid KEM) validation suite running...\n\n";
	bool pass = true;

	pass = TestXWingKeyGen() && pass;
	pass = TestXWingEncapsDecaps() && pass;
	pass = TestXWingMultipleRounds() && pass;
	pass = TestXWingKAT() && pass;
	pass = TestXWingSmallOrderShare() && pass;
	pass = TestXWingUnsetKeys() && pass;
	pass = TestXWingUnsetDecapsulate() && pass;

	return pass;
}

NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP
