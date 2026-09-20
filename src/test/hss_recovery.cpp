// HSS recovery after allocation failures. Linux/GNU ld, static library.

#include <cryptopp/hss.h>
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
    void GenerateBlock(CryptoPP::byte* output, size_t size) override
    {
        std::memset(output, 0xa5, size);
    }
};

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

template <class Params>
Result TestRecovery(const char* name, uint64_t boundary)
{
    using namespace CryptoPP;

    byte seed[32], identifier[16];
    std::memset(seed, 0x11, sizeof(seed));
    std::memset(identifier, 0x22, sizeof(identifier));
    HSSPrivateKey<Params> key;
    key.SetPrivateKey(seed, sizeof(seed), identifier, sizeof(identifier));
    HSSPublicKey<Params> publicKey;
    key.MakePublicKey(publicKey);
    HSSVerifier<Params> verifier(publicKey.GetPublicKeyBytePtr(),
                                publicKey.GetPublicKeyByteLength());
    FixedRNG rng;
    const byte warmMessage[] = "before rebuild";
    const byte failedMessage[] = "during failed rebuild";
    const byte retryMessage[] = "after failed rebuild";
    SecByteBlock signature(Params::SignatureSize());

    // The control run measures the allocations. Each following run fails
    // one of them, so changes to the rebuild do not invalidate a countdown.
    size_t positions = 0;
    for (size_t position = 0; position <= positions; ++position)
    {
        InsecureMemoryStateStore store(Params::TotalSignatures());
        HSSSigner<Params> signer(key, store);
        signer.SignMessage(rng, warmMessage, sizeof(warmMessage), signature);
        signer.SignMessage(rng, warmMessage, sizeof(warmMessage), signature);

        // Keep the old descendant cursors at zero while advancing the root.
        // Reservations can be burned without rebuilding this signer's caches.
        for (uint64_t index = 2; index < boundary; ++index)
        {
            StateReservation reservation = store.ReserveNext();
            store.AbortReservation(reservation);
        }

        allocationCount = 0;
        failurePosition = position;
        countAllocations = true;
        bool threw = false;
        try
        {
            signer.SignMessage(rng, failedMessage, sizeof(failedMessage), signature);
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
            if (threw ||
                !verifier.VerifyMessage(failedMessage, sizeof(failedMessage),
                                        signature, signature.size()))
            {
                std::printf("FAILED: %s control run\n", name);
                return FAILED;
            }
            // The linker did not redirect the library's calls to the wrapper.
            if (positions == 0)
                return SKIPPED;
            continue;
        }

        if (!threw || allocationCount != position ||
            store.RemainingSignatures() != Params::TotalSignatures() - boundary - 1)
        {
            std::printf("FAILED: %s allocation %zu was not thrown and burned\n",
                        name, position);
            return FAILED;
        }

        signer.SignMessage(rng, retryMessage, sizeof(retryMessage), signature);
        if (!verifier.VerifyMessage(retryMessage, sizeof(retryMessage),
                                    signature, signature.size()) ||
            store.RemainingSignatures() != Params::TotalSignatures() - boundary - 2)
        {
            std::printf("FAILED: %s same-signer retry after allocation %zu\n",
                        name, position);
            return FAILED;
        }
    }

    std::printf("passed: %s recovery at all %zu allocation positions\n", name, positions);
    return PASSED;
}

int main()
{
    try
    {
        const Result l3 = TestRecovery<CryptoPP::HSS_SHA256_H5_W8_L3_Params>("HSS L=3", 1024);
        const Result l4 = TestRecovery<CryptoPP::HSS_SHA256_H5_W8_L4_Params>("HSS L=4", 32768);
        if (l3 == FAILED || l4 == FAILED)
            return 1;
        if (l3 == SKIPPED || l4 == SKIPPED)
        {
            std::printf("SKIPPED: allocation wrapper intercepted no calls\n");
            return SKIP_EXIT;
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        std::printf("FAILED: HSS allocation recovery: %s\n", error.what());
        return 1;
    }
}
