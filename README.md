# cryptopp-modern

**A maintained, modernized fork of Crypto++ with new algorithms and security improvements**

[![Version](https://img.shields.io/badge/version-2026.5.2-blue.svg)](https://github.com/cryptopp-modern/cryptopp-modern/releases)
[![License](https://img.shields.io/badge/license-Boost-green.svg)](LICENSE)

---

## Overview

**Website:** [cryptopp-modern.com](https://cryptopp-modern.com)

**cryptopp-modern** is an actively maintained fork of [Crypto++ 8.9.0](https://github.com/weidai11/cryptopp) featuring:

- **Post-Quantum Cryptography** - ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), X-Wing hybrid KEM
- **BLAKE3** - Modern, fast cryptographic hash function
- **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)
- **Security Patches** - Marvin attack fix (CVE-2023-50979), fault injection fix (CVE-2024-28285), F(2^m) and Rabin/ModularSquareRoot hardening (CVE-2023-50980, CVE-2023-50981), ESIGN improvements
- **Calendar Versioning** - Clear release dates (YEAR.MONTH.INCREMENT format)
- **Active Maintenance** - Regular updates and improvements
- **Drop-in Compatible** - Uses same `CryptoPP` namespace

---


## What's New in 2026.5.2

- **ASN.1 DERReencode depth cap** - Caps `DERReencode` recursion at 32 levels, matching OpenSSL's `ASN1_MAX_CONSTRUCTED_NEST`. Prevents stack exhaustion on crafted nested constructed indefinite BER input. Addresses upstream Crypto++ issue 1353.
- **Ed25519 signature scalar canonicality** - Both the Donna verifier and the NaCl C API verifier now reject signatures where `S >= L`. Addresses the signature-scalar part of upstream Crypto++ issue 1352. Conformance fix, not a forgery.
- **Ed25519 small-order public key rejection** - `ed25519PublicKey::Validate` rejects small-order public keys at validation level 2 or higher. Level 0 behaviour is unchanged.

### Previously in 2026.5.1

- **BLAKE3 correctness fix on AArch64** - Removed the fork-local NEON single-block compress that produced incorrect digests on Apple Silicon, ARM64 Linux, and Android arm64-v8a. AArch64 builds now use the portable path, matching the BLAKE3 reference. Stored hashes from affected versions should be recomputed.
- **Android build fixes** - Restored the CMake staging step for `cpu-features.h` and replaced an AArch64-only intrinsic in BLAKE3's NEON code so `armeabi-v7a` builds compile.
- **CI coverage extended** - Android build-only jobs, legacy GCC 9/10 and Clang 13/14 jobs, and `actions/checkout` bumped to v5.

---

## Quick Build

### CMake (Recommended)

```bash
cmake --preset=default
cmake --build build/default
./build/default/cryptest.exe v
```

### GNUmakefile

```bash
make -j$(nproc)
./cryptest.exe v
```

See [CMAKE.md](CMAKE.md) or [GNUMAKEFILE.md](GNUMAKEFILE.md) for detailed build instructions.

---

## Documentation

- **[cryptopp-modern.com](https://cryptopp-modern.com)** - Full API and algorithm documentation
- **[GETTING_STARTED.md](GETTING_STARTED.md)** - Quick start guide with code examples
- **[CMAKE.md](CMAKE.md)** - CMake build system documentation
- **[GNUMAKEFILE.md](GNUMAKEFILE.md)** - GNUmakefile build system documentation
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap and future plans
- **[FORK.md](FORK.md)** - Relationship to upstream Crypto++
- **[Readme.txt](Readme.txt)** - Complete algorithm list and instructions
- **[Install.txt](Install.txt)** - Detailed installation guide
- **[LICENSE](LICENSE)** - Boost Software License 1.0

---

## Why Fork?

**Upstream Crypto++ Status:**
- Last release: 8.9.0 (October 1, 2023)
- Version encoding limitation (cannot represent 8.10.0)
- Slower development pace

**cryptopp-modern Goals:**
- Active maintenance and regular releases
- Modern algorithm support (BLAKE3, Argon2, post-quantum cryptography)
- Better code organization
- Modern CMake build system
- Calendar versioning
- Community-driven development

See [FORK.md](FORK.md) for detailed explanation.

---

## Features

### Cryptographic Algorithms

**Hash Functions:**
- SHA-2, SHA-3, BLAKE2b/s, **BLAKE3** ⭐
- MD5, RIPEMD, Tiger, Whirlpool, SipHash

**Password Hashing / KDF:**
- **Argon2 (d/i/id)** ⭐ RFC 9106
- PBKDF2, Scrypt, HKDF

**Symmetric Encryption:**
- AES, ChaCha20, Serpent, Twofish, Camellia, ARIA
- Modes: GCM, CCM, EAX, CBC, CTR, and more

**Post-Quantum Cryptography:**
- **ML-KEM** (FIPS 203) - Key encapsulation ⭐
- **ML-DSA** (FIPS 204) - Digital signatures ⭐
- **SLH-DSA** (FIPS 205) - Hash-based signatures ⭐
- **X-Wing** - Hybrid KEM (X25519 + ML-KEM-768) ⭐

**Public Key Cryptography:**
- RSA, DSA, ECDSA, Ed25519
- Diffie-Hellman, ECIES, ElGamal

**Message Authentication:**
- HMAC, CMAC, GMAC, Poly1305

See [Readme.txt](Readme.txt) for complete algorithm list.

---

## Migration from Crypto++ 8.9.0

**Good news:** Most code works unchanged!

### Compatible
- All existing algorithms and APIs
- Same `CryptoPP` namespace
- Version checks: `#if CRYPTOPP_VERSION >= N`

### Changed
- Version encoding: Now `YEAR*10000 + MONTH*100 + INCREMENT`
- Version parsing: Use `/10000` for year, `(n/100)%100` for month

**Example:**
```cpp
// Old (8.9.0)
const int major = CRYPTOPP_VERSION / 100;  // Gets 8

// New (2025.11.0)
const int year = CRYPTOPP_VERSION / 10000;  // Gets 2025
const int month = (CRYPTOPP_VERSION / 100) % 100;  // Gets 11
```

---

## Contributing

Contributions are welcome! Areas where you can help:

- Bug reports and fixes
- New algorithm implementations
- Documentation improvements
- Tests and test vectors
- Build system enhancements

If you're migrating from Crypto++ 8.9.0 and encounter any issues, please open an issue. Migration feedback is especially valuable.

Please:
1. Fork the repository
2. Create a feature branch
3. Follow existing code style
4. Add tests for new features
5. Submit a pull request

---


## License

Like the original Crypto++, this library uses:
- **Compilation:** Boost Software License 1.0
- **Individual files:** Public domain

See [LICENSE](LICENSE) for details.

---

## Contact

- **Issues:** [GitHub Issues](https://github.com/cryptopp-modern/cryptopp-modern/issues)
- **Discussions:** [GitHub Discussions](https://github.com/cryptopp-modern/cryptopp-modern/discussions)

---

## Acknowledgments

**cryptopp-modern** builds upon the excellent work of:
- **Wei Dai** - Original Crypto++ creator and maintainer
- **The Crypto++ team** - All contributors to upstream Crypto++
- **BLAKE3 team** - Modern cryptographic hash design
- **Argon2 team** - Password hashing competition winner

---

**Maintained by [CoraleSoft](https://github.com/Coralesoft)**
