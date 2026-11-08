# cryptopp-modern

**A maintained, modernized fork of Crypto++ with new algorithms and security improvements**

[![Version](https://img.shields.io/badge/version-2026.11.1-blue.svg)](https://github.com/cryptopp-modern/cryptopp-modern/releases)
[![License](https://img.shields.io/badge/license-Boost-green.svg)](LICENSE)

---

## Overview

**Website:** [cryptopp-modern.com](https://cryptopp-modern.com)

**cryptopp-modern** is an actively maintained fork of [Crypto++ 8.9.0](https://github.com/weidai11/cryptopp) featuring:

- **Post-Quantum Cryptography** - ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), LMS/HSS (SP 800-208), X-Wing hybrid KEM
- **BLAKE3** - Modern, fast cryptographic hash function
- **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)
- **Security Patches** - PKCS#1 v1.5 depadding timing hardening, fault injection fix (CVE-2024-28285), F(2^m) and Rabin/ModularSquareRoot hardening (CVE-2023-50980, CVE-2023-50981), ESIGN improvements
- **Calendar Versioning** - Clear release dates (YEAR.MONTH.INCREMENT format)
- **Active Maintenance** - Regular updates and improvements
- **Crypto++ Compatibility** - Uses the same `CryptoPP` namespace and preserves most existing APIs

---


## What's New in 2026.11.1

- **BLAKE2** - The BLAKE2b and BLAKE2s constructors and `SetKey` now validate digest size at run time, and the keyed constructors validate key length; release builds previously accepted an over-length key or an over-maximum digest size (GHSA-796q-fcgc-jpr9).
- **SLH-DSA** - Stack secrets are wiped on every exit, including exceptions (#133).
- **Link-time optimisation** - LTO is tested in CI with GCC through both build systems and with Clang through the GNUmakefile, with no need to disable assembly; pass `CXXFLAGS` to the GNUmakefile through the environment, not as a `make` argument (#134, #136).
- **Packagers** - The GNUmakefile no longer installs `validate.h` and `bench.h`; CMake now installs `factory.h` and `xaes_256_gcm.h` (#139).
- **Builds** - GNUmakefile per-file rules work on rebuilds (#137), `-fno-devirtualize` survives a command-line `CXXFLAGS` (#141), flag filtering and CMake probe option splitting are fixed (#142), and `DataDir()` is defined once (#135).
- **ARM** - The Cryptogams asm no longer requests an executable stack and builds on armhf and ARMv8 (#138); 32-bit ARM NEON detection is fixed for Clang and soft-float CMake builds, so configure a fresh build directory (#142).

### Previously in 2026.11.0

- **EAX and AES-CTR-HMAC** - Repeated EAX resynchronisation carried stale CMAC state into the nonce tag, and AES-CTR-HMAC one-shot calls threw `BadState` when an object was reused. Ciphertext produced through the faulty EAX one-shot path will not verify through the corrected path (#119). Debug builds no longer assert on empty AEAD messages (#124).
- **CMAC** - `Restart` no longer runs a block encryption, which makes EAX resynchronisation cheaper (#128).
- **BLAKE3** - The SSE4.1 path is compiled without AVX2, fixing SIGILL on CPUs without AVX, and a QEMU Nehalem CI job runs the suite without AVX (#122). The nmake x64 build links again (#129).
- **Argon2** - Unknown variants and input lengths exceeding the RFC 9106 limits are rejected, and temporary blocks are wiped (#126).
- **ML-DSA** - Key generation, signing and verification are checked against NIST ACVP vectors in the validation suite (#127).
- **Builds** - 32-bit x86 builds with GCC link-time optimisation link again (#131); `msvc-debug` and `msvc-release` are build and test presets on the `msvc` configure preset (#130); the Visual Studio projects keep compiler options inherited from property sheets (#117); `SafeConvert` no longer triggers a Clang mixed-sign warning (#120).

### Previously in 2026.10.0

- **Argon2i and Argon2id corrected** - The first segment read the address block from index 0 instead of 2, producing non-standard hashes for affected parameter sets since 2025.11.0; Argon2d is unaffected. `ARGON2I_LEGACY` and `ARGON2ID_LEGACY` reproduce the previous output for migration, and the reference vectors run in the default test suites (#114, #115).
- **Ed25519 small-order keys** - Reject all small-order public keys during validation, fixing an incomplete check from 2026.5.2. Signature verification and X25519 are unchanged (#112).
- **ML-DSA and ML-KEM stack wipes** - Secret stack buffers are wiped on normal exits and exceptions, and additional sensitive intermediates are cleared (#113).
- **ML-DSA key state** - Failed key generation or private-key import leaves the previous key unchanged, or a fresh key unset (#110).
- **Build fixes** - LM-OTS hash length bounded before sizing buffers, fixing GCC `-Wstringop-overflow` on ARM-32 (#106); the Apple machine-info helper is compiled only on PowerPC (#107).

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
- **SLH-DSA** (FIPS 205) - Hash-based signatures (stateless) ⭐
- **LMS/HSS** (SP 800-208) - Hash-based signatures (stateful) ⭐
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
- Most existing Crypto++ 8.9.0 algorithms and APIs
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
