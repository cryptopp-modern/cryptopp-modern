# cryptopp-modern 2026.2.1 Release Notes

**Release Date:** February 2026
**Release Type:** Minor Release (Correctness Fix)

---

## Overview

cryptopp-modern 2026.2.1 is a minor release that fixes **Crypto++ Issue #1342**, a correctness bug where DSA/ECDSA signing could output an invalid signature with `r = 0` or `s = 0` in release builds.

---

## Bug Fix

### Issue #1342: DSA/ECDSA Invalid Signature (r=0 or s=0)

**Component:** DSA, DSA2, ECDSA, ECGDSA, Nyberg-Rueppel (NR)

**Issue:** DSA/ECDSA signing could output an invalid signature with `r = 0` or `s = 0` in release builds. Per FIPS 186-4, both signature components must be in the range `[1, q-1]`. The existing code only had a `CRYPTOPP_ASSERT` check which is compiled out in release builds.

**Severity:** Low

### Changes

- **`pubkey.h`** — Fix `DL_SignerBase<T>::SignAndRestart()`:
  - **Probabilistic signatures:** Retry with fresh random `k` until valid (64-attempt safety cap)
  - **Deterministic signatures (RFC 6979):** Abort with exception (API returns single k)
  - Safe `dynamic_cast` with proper error handling
  - Consistent use of cached subgroup order `q`

### Why Different Handling for Deterministic Signatures?

RFC 6979 technically allows looping with updated HMAC_DRBG state, but the Crypto++ `GenerateRandom()` API returns a single k value. Given the astronomically low probability (~1/q), throwing an exception is a safe defensive choice.

This is extremely unlikely to occur in practice, but the fix ensures spec compliance and eliminates any theoretical edge-case failures.

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

## Migration from 2026.2.0

**No breaking changes.** All existing DSA/ECDSA signing code continues to work unchanged. The only difference is that:

1. Invalid signatures with `r = 0` or `s = 0` are no longer possible in release builds
2. Deterministic signatures (RFC 6979) will throw an exception in the astronomically unlikely event of `r = 0` or `s = 0`

---

## Previous Features

All features from previous releases remain available:

### From 2026.2.0
- **CVE-2024-28285 Fix** - Hardened hybrid DL decryption against fault injection

### From 2026.1.0
- **BLAKE3 AVX-512** - 16-way parallel chunk hashing
- **XAES-256-GCM** - Extended-nonce AES-GCM with 256-bit nonces
- **AES-CTR-HMAC** - Encrypt-then-MAC authenticated encryption

### From 2025.12.0
- **BLAKE3** - Modern cryptographic hash function
- **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)

---

## References

- [Upstream Issue #1342](https://github.com/weidai11/cryptopp/issues/1342)
- [FIPS 186-4: Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf)
- [FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [RFC 6979: Deterministic DSA and ECDSA](https://tools.ietf.org/html/rfc6979)
- Full analysis: [`docs/security/cryptopp-1342-dsa-signature.md`](docs/security/cryptopp-1342-dsa-signature.md)

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
