# cryptopp-modern 2026.2.0 Release Notes

**Release Date:** February 2026
**Release Type:** Security Release

---

## Overview

cryptopp-modern 2026.2.0 is a security release that fixes **CVE-2024-28285**, a fault-injection vulnerability in hybrid discrete-logarithm decryption (ElGamal, ECIES, DLIES).

---

## Security Fix

### CVE-2024-28285: Harden Hybrid DL Decryption Against Fault Injection

**Component:** Hybrid discrete-logarithm decryption (ElGamal, ECIES, DLIES)

**Vulnerability:** A fault-injection vulnerability in hybrid ElGamal decryption could allow private key recovery. An attacker capable of inducing computational faults during decryption (for example via Rowhammer-style bit flips or other transient execution faults) could collect faulted decryption outputs and use them to recover the private key.

**Security Guarantee:**
> Hybrid DL decrypt never writes plaintext to caller memory unless `DecodingResult` indicates valid decoding. Faults in key-agreement computations are detected via redundant blinded verification before any plaintext is released.

### Changes

- **`pubkey.h`** — Harden `DL_DecryptorBase<T>::Decrypt()`:
  - Validate ciphertext length before processing
  - Exponent blinding verification (`z` vs `z2 = ephemeralPub^(x+k*order)`) to detect faults
  - Decrypt into temporary buffer
  - Copy to caller only on success (no-write-on-failure)

- **`elgamal.h`** — Defence-in-depth in `ElGamalBase::SymmetricDecrypt()`:
  - Validate ciphertext length before computation
  - Validate plaintext length field before writing
  - Decode to temp buffer, copy only on success

- **New test suite** — `validat_cve_2024_28285.cpp` (`cryptest.exe v 95`)

### Why This Fix Is More Complete Than the openSUSE Patch

| Issue | openSUSE Patch | This Fix |
|-------|----------------|----------|
| **Write timing** | Performs symmetric decrypt into caller's buffer *before* completing fault checks | Decrypts into temporary storage, copies only on confirmed success |
| **What gets compared** | Recomputes agreement with the *same* exponent | Uses **blinded verification** (`x + k*order`) for different computational path |
| **Persistent/deterministic faults** | Identical computations can produce the same wrong result | Blinding changes intermediate states to improve detection |
| **Caller buffer on failure** | May already contain faulted/partial plaintext | Remains completely untouched on all failure paths |
| **Enforcement point** | Fault check occurs *after* decrypt has potentially written output | Fault checks performed **before releasing plaintext** |

---

## API Note

**RNG Parameter Now Used:**

`DL_DecryptorBase::Decrypt(RandomNumberGenerator& rng, ...)` now uses the RNG parameter for exponent blinding verification. Previously, this parameter was ignored (`CRYPTOPP_UNUSED(rng);`).

All existing Crypto++ code already passes a real RNG (e.g., `GlobalRNG()` or `AutoSeededRandomPool`), so this change is **backward compatible** with existing usage patterns.

```cpp
// Standard usage (unchanged)
AutoSeededRandomPool rng;
decryptor.Decrypt(rng, ciphertext, ciphertextLen, plaintext);  // Works as before
```

---

## Installation

### CMake

```bash
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

cmake --preset=default
cmake --build build/default
./build/default/cryptest.exe v

sudo cmake --install build/default
```

### GNUmakefile

```bash
# Linux/macOS
make -j$(nproc)
./cryptest.exe v
sudo make install

# Windows (MinGW)
mingw32-make -j10 static-exe
./cryptest.exe v
```

### Visual Studio

Open `cryptest.sln` and build Release configuration.

---

## Migration from 2026.1.0

**No breaking changes.** The `Decrypt()` RNG parameter was previously ignored but is now used for blinding verification. All standard usage patterns (passing `AutoSeededRandomPool` or `GlobalRNG()`) continue to work unchanged.

---

## Previous Features

All features from 2026.1.0 remain available:

- **BLAKE3 AVX-512** - 16-way parallel chunk hashing (~4000+ MiB/s)
- **XAES-256-GCM** - Extended-nonce AES-GCM with 256-bit nonces
- **AES-CTR-HMAC** - Encrypt-then-MAC authenticated encryption
- **Security Hardening** - Improved misuse resistance for authenticated encryption

---

## References

- [NVD CVE-2024-28285](https://nvd.nist.gov/vuln/detail/CVE-2024-28285)
- [Crypto++ Issue #1262](https://github.com/weidai11/cryptopp/issues/1262)
- [cryptopp-modern Issue #12](https://github.com/cryptopp-modern/cryptopp-modern/issues/12)
- Full rationale: [`docs/security/CVE-2024-28285.md`](docs/security/CVE-2024-28285.md)

---

## Links

- **Website:** https://cryptopp-modern.com
- **GitHub:** https://github.com/cryptopp-modern/cryptopp-modern
- **Issues:** https://github.com/cryptopp-modern/cryptopp-modern/issues
- **Discussions:** https://github.com/cryptopp-modern/cryptopp-modern/discussions

---

## Contributors

**cryptopp-modern** is maintained by:
- **Colin Brown** / [CoraleSoft](https://github.com/Coralesoft)

Built upon the excellent work of:
- **Wei Dai** - Original Crypto++ creator
- **Jeffrey Walton** - Crypto++ maintainer
- **The Crypto++ Project** - All upstream contributors

---

## License

- **Compilation:** Boost Software License 1.0
- **Individual files:** Public domain

See [LICENSE](LICENSE) for details.

---

**Thank you for using cryptopp-modern!**
