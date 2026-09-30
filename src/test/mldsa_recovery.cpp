// ML-DSA key state after allocation failures. Linux/GNU ld, static library.

#include <cryptopp/mldsa.h>
#include <cryptopp/misc.h>
#include <cryptopp/secblock.h>
#include <cstdio>
#include <cstring>
#include <new>

namespace {

bool countAllocations = false;
size_t allocationCount = 0;
size_t failurePosition = 0;

// CTest treats SKIP_EXIT as a skipped test. CI runs the program directly,
// where any non-zero exit fails the step.
enum Result { PASSED, FAILED, SKIPPED };
const int SKIP_EXIT = 77;

class FixedRNG : public CryptoPP::RandomNumberGenerator
{
public:
    explicit FixedRNG(CryptoPP::byte fill) : m_fill(fill) {}
    void GenerateBlock(CryptoPP::byte* output, size_t size) override
    {
        std::memset(output, m_fill, size);
    }
private:
    CryptoPP::byte m_fill;
};

typedef CryptoPP::MLDSAPrivateKey<CryptoPP::MLDSA_44> Key;
const size_t SK = CryptoPP::MLDSA_44::SECRET_KEY_SIZE;
const size_t PK = CryptoPP::MLDSA_44::PUBLIC_KEY_SIZE;

CryptoPP::SecByteBlock aSk, aPk, bSk, bPk;

bool Matches(const Key& key, const CryptoPP::SecByteBlock& sk, const CryptoPP::SecByteBlock& pk)
{
    return key.GetPrivateKeyBytePtr() && key.GetPublicKeyBytePtr() &&
           CryptoPP::VerifyBufsEqual(key.GetPrivateKeyBytePtr(), sk, SK) &&
           CryptoPP::VerifyBufsEqual(key.GetPublicKeyBytePtr(), pk, PK);
}

bool Validates(const Key& key)
{
    FixedRNG rng(0);
    return key.Validate(rng, 3);
}

bool SignsAndVerifies(const Key& key)
{
    using namespace CryptoPP;
    MLDSASigner<MLDSA_44> signer(key.GetPrivateKeyBytePtr(), SK);
    MLDSAVerifier<MLDSA_44> verifier(key.GetPublicKeyBytePtr(), PK);
    FixedRNG rng(0x44);
    const byte message[] = "after a failed allocation";
    SecByteBlock signature(signer.SignatureLength());
    size_t sigLen = signer.SignMessage(rng, message, sizeof(message), signature);
    return verifier.VerifyMessage(message, sizeof(message), signature, sigLen);
}

void Fresh(Key&) {}
void HoldA(Key& key) { key.SetPrivateKey(aSk, SK); }
void SetB(Key& key) { key.SetPrivateKey(bSk, SK); }
void Generate(Key& key)
{
    FixedRNG rng(0x33);
    key.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
}
bool IsA(const Key& key) { return Matches(key, aSk, aPk); }
bool IsB(const Key& key) { return Matches(key, bSk, bPk); }
bool IsUnset(const Key& key)
{
    return key.GetPrivateKeyBytePtr() == NULLPTR && key.GetPublicKeyBytePtr() == NULLPTR;
}
bool IsNewKey(const Key& key) { return Validates(key) && !IsA(key); }

} // namespace

extern "C" void* __real__ZN8CryptoPP17UnalignedAllocateEm(size_t);

extern "C" void* __wrap__ZN8CryptoPP17UnalignedAllocateEm(size_t size)
{
    if (countAllocations && ++allocationCount == failurePosition)
    {
        countAllocations = false;
        throw std::bad_alloc();
    }
    return __real__ZN8CryptoPP17UnalignedAllocateEm(size);
}

// The control run measures the allocations that operation makes on a key
// that prepare set up. Each following run fails one of them and checks that
// the key is unchanged and that the same operation then completes.
static Result TestRecovery(const char* name, void (*prepare)(Key&), void (*operation)(Key&),
                    bool (*unchanged)(const Key&), bool (*completed)(const Key&))
{
    size_t positions = 0;
    for (size_t position = 0; position <= positions; ++position)
    {
        Key key;
        prepare(key);

        allocationCount = 0;
        failurePosition = position;
        countAllocations = true;
        bool threw = false;
        try
        {
            operation(key);
        }
        catch (const std::bad_alloc&)
        {
            threw = true;
        }
        catch (...)
        {
            countAllocations = false;
            throw;
        }
        countAllocations = false;

        if (position == 0)
        {
            positions = allocationCount;
            if (threw || !completed(key))
            {
                std::printf("FAILED: %s control run\n", name);
                return FAILED;
            }
            // The linker did not redirect the library's calls to the wrapper.
            if (positions == 0)
                return SKIPPED;
            continue;
        }

        if (!threw || allocationCount != position)
        {
            std::printf("FAILED: %s allocation %zu was not thrown\n", name, position);
            return FAILED;
        }
        if (!unchanged(key))
        {
            std::printf("FAILED: %s key changed by allocation %zu failure\n", name, position);
            return FAILED;
        }

        operation(key);
        if (!completed(key) || !SignsAndVerifies(key))
        {
            std::printf("FAILED: %s retry after allocation %zu\n", name, position);
            return FAILED;
        }
    }

    std::printf("passed: %s at all %zu allocation positions\n", name, positions);
    return PASSED;
}

int main()
{
    try
    {
        {
            Key a, b;
            FixedRNG rngA(0x11), rngB(0x22);
            a.GenerateRandom(rngA, CryptoPP::g_nullNameValuePairs);
            b.GenerateRandom(rngB, CryptoPP::g_nullNameValuePairs);
            aSk.Assign(a.GetPrivateKeyBytePtr(), SK);
            aPk.Assign(a.GetPublicKeyBytePtr(), PK);
            bSk.Assign(b.GetPrivateKeyBytePtr(), SK);
            bPk.Assign(b.GetPublicKeyBytePtr(), PK);
        }

        const Result import = TestRecovery("ML-DSA-44 SetPrivateKey on an unset key",
                                           Fresh, SetB, IsUnset, IsB);
        const Result set = TestRecovery("ML-DSA-44 SetPrivateKey over an existing key",
                                        HoldA, SetB, IsA, IsB);
        const Result fresh = TestRecovery("ML-DSA-44 GenerateRandom on an unset key",
                                          Fresh, Generate, IsUnset, Validates);
        const Result regen = TestRecovery("ML-DSA-44 GenerateRandom over an existing key",
                                          HoldA, Generate, IsA, IsNewKey);
        if (import == FAILED || set == FAILED || fresh == FAILED || regen == FAILED)
            return 1;
        if (import == SKIPPED || set == SKIPPED || fresh == SKIPPED || regen == SKIPPED)
        {
            std::printf("SKIPPED: allocation wrapper intercepted no calls\n");
            return SKIP_EXIT;
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        std::printf("FAILED: ML-DSA allocation recovery: %s\n", error.what());
        return 1;
    }
}
