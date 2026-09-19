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
			priv.SetPrivateKey(zeros, zeros.size());
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
static bool TestPqcDerFixtures(const char* name, byte privSeed, const char* privDigest,
	byte pubSeed, const char* pubDigest)
{
	try {
		PrivKey priv;
		SecByteBlock material(PARAMS::SECRET_KEY_SIZE);
		FillPattern(material, privSeed);
		priv.SetPrivateKey(material, material.size());
		bool pass = ExpectDerDigest(name, "private", priv, privDigest);

		PubKey pub;
		material.New(PARAMS::PUBLIC_KEY_SIZE);
		FillPattern(material, pubSeed);
		pub.SetPublicKey(material, material.size());
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
	std::string name, comment, d, z, m, ek, dk, ct, ss;
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
	static const char* const expectedTests[] = { "KeyGen", "Encapsulate", "Decapsulate" };
	static const char* const expectedSets[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
	const unsigned int expectedPerSet = 3;

	for (size_t t = 0; t < COUNTOF(expectedTests); t++) {
		for (size_t i = 0; i < COUNTOF(expectedSets); i++) {
			const std::string id = std::string(expectedTests[t]) + " " + expectedSets[i];
			if (coverage[id] != expectedPerSet) {
				std::cout << "FAILED:  " << name << " " << id
					<< " coverage (" << coverage[id]
					<< " vectors; expected " << expectedPerSet << ")" << std::endl;
				return false;
			}
		}
		std::cout << "passed:  " << name << " " << expectedTests[t] << " KAT ("
			<< expectedPerSet * COUNTOF(expectedSets) << " vectors, "
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

bool ValidateMLKEM()
{
	std::cout << "\nML-KEM (FIPS 203) validation suite running...\n\n";
	bool pass = true;

	// ML-KEM-512
	pass = TestMLKEMKeyGen<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestMLKEMKeyGenFailure<MLKEM_512>("ML-KEM-512") && pass;
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

	// ACVP known-answer vectors, covering the implicit-rejection path
	pass = TestMLKEMKAT() && pass;

	pass = TestMLKEMDecodeState<MLKEM_512>("ML-KEM-512") && pass;
	pass = TestPqcEncodeGuard<MLKEM_512, MLKEMPublicKey<MLKEM_512>, MLKEMPrivateKey<MLKEM_512> >(
		"ML-KEM-512", true) && pass;
	pass = TestPqcDerFixtures<MLKEM_512, MLKEMPublicKey<MLKEM_512>, MLKEMPrivateKey<MLKEM_512> >("ML-KEM-512",
		0x99, "444E0F29B287FF094184F0D3D35F72EE1E9B49844FB2228791A1AD0AD3663BD8",
		0xaa, "6543C03D1B41D8D953760972D8230E53C81BFFACE194D07C560137D20AF10D48") && pass;

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
