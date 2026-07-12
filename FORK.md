# FORK.md - Relationship to Upstream Crypto++

**cryptopp-modern** is a maintained fork of [Crypto++](https://github.com/weidai11/cryptopp), separated to add modern algorithms and improve the library structure.

---

## Why Fork?

**Upstream Crypto++ Status:**
- Last release: 8.9.0 (October 1, 2023)
- Development pace: No release since October 2023
- Version encoding limitation: Cannot represent version 8.10.0 without ambiguity
- Modern algorithms: Missing (BLAKE3, Argon2, post-quantum)

**cryptopp-modern Goals:**
- Active maintenance with regular releases
- Modern cryptographic algorithms (BLAKE3, Argon2, post-quantum cryptography)
- Better code organization (Phase 2 complete - categorized src/ directories)
- Calendar versioning (YEAR.MONTH.INCREMENT)
- Improved documentation and organisation
- Community-driven development

---

## Version History

### cryptopp-modern Releases

**2026.7.1** (July 2026) - Packaging (Patch)
- Moved the CMake package config and pkg-config files under `${CMAKE_INSTALL_LIBDIR}` (#47)
- Restored `libcryptopp.pc` for pkg-config compatibility; kept `cryptopp-modern.pc` as a version-pinned alias (#51)
- Added `.tar.gz` release archives and normalised repository line endings to LF (#49)
- Published the release-signing key in `KEYS` and documented verification in `Security.md` (#46)

**2026.7.0** (July 2026) - SLH-DSA External Interface and Stateful-Signing Hardening (Minor)
- Changed SLH-DSA to the FIPS 205 external pure signature interface; restores interoperability with OpenSSL, X.509, and CMS (fixes #40)
- SLH-DSA signatures from 2026.3.0 through 2026.6.0 use the internal message form and are not interoperable with the external-interface format introduced in 2026.7.0
- Added `SetContext` on `SLHDSA_MessageAccumulator` for explicit-context signing; empty context by default
- Hardened LMS/HSS signing to fail closed on invalid state reservations
- Bound `StateReservation` to its issuing store; cross-store use is rejected
- Hardened `FileStateStore`: state-file size validation on open, zero-capacity rejection, POSIX exclusive locking, retry on interrupted I/O
- Fixed HSS capacity helpers and public-header hygiene for the C++11 baseline

**2026.6.0** (June 2026) - LMS/HSS Stateful Signatures (Minor)
- Added LMS single-tree signatures (`LMS_SHA256_H5_W8`, `LMS_SHA256_H10_W8`) following NIST SP 800-208 and RFC 8554
- Added HSS hierarchical signatures (`HSS_SHA256_H5_W8_L2`, `HSS_SHA256_H10_W8_L2`, `HSS_SHA256_H5_W8_L3`) with uniform parameter sets
- Added stateful signing API: `PK_StatefulSigner`, `SignerStateStore`, `StateReservation`, `InsecureMemoryStateStore`, `FileStateStore`
- Added `FileStateStore` durable backend (write-ahead persistence, HMAC-SHA256 integrity, fail-closed poisoning, Win32/POSIX/macOS `F_FULLFSYNC` flush)
- Added ASN.1 wiring for RFC 8708 `id-alg-hss-lms-hashsig` (X.509 SubjectPublicKeyInfo, library-local PKCS#8)
- Added Save/Load round-trip tests for ML-KEM, ML-DSA, SLH-DSA
- Added Android `x86_64` and `x86` build coverage in CI
- Added legacy compiler CI lanes (GCC 9-10, Clang 11-14)
- Fixed sanitizer CI gap so `cryptest tv` output is included in the checked log
- Guarded zero-length `memcpy` in `DL_DecryptorBase::Decrypt` for UBSan hygiene

**2026.5.2** (May 2026) - Security and Conformance Patch
- Capped `DERReencode` recursion depth at 32 levels (upstream Crypto++ issue 1353)
- Rejected Ed25519 signatures where `S >= L` in both Donna and NaCl verifiers (upstream Crypto++ issue 1352, signature-scalar part)
- Rejected small-order Ed25519 public keys in `ed25519PublicKey::Validate` at level 2 or higher (upstream Crypto++ issue 1352, small-order part)

**2026.5.1** (May 2026) - Correctness and Build Fixes
- Fixed BLAKE3 incorrect hashes on AArch64 (removed fork-local NEON single-block compress; AArch64 uses portable path)
- Restored Android CMake builds (auto-staging of NDK `cpu-features.h`)
- Fixed armv7 NEON build failure in `rot8_neon`
- Added Android build-only CI, legacy GCC 9/10 and Clang 13/14 CI, bumped `actions/checkout` to v5
- `ValidateBLAKE3` now in default validation suite

**2026.5.0** (May 2026) - Security Hardening (Defence-in-depth)
- Hardened CVE-2023-50980 path: `BERDecodeGF2NP` strict ordering + field degree cap (`MAX_GF2N_FIELD_DEGREE = 4096`)
- Hardened CVE-2023-50981 path: Rabin `BERDecode` `IsPrime` runtime checks (no longer compiled out in release)
- Hardened CVE-2023-50981 path: `ModularSquareRoot` iteration cap (`MAX_MODULAR_SQRT_ITERATIONS = 10000`)
- Fixed Issue #23: version-metadata drift in CMake and `cryptest`

**2026.4.0** (April 2026) - Security Fix
- Fixed Crypto++ Issue #1348: Ed25519 verification accepts non-canonical public keys
- Validate() and Donna verifiers now reject y >= p per RFC 8032

**2026.3.0** (March 2026) - Post-Quantum Cryptography Release
- Added ML-KEM (FIPS 203) key encapsulation (512/768/1024)
- Added ML-DSA (FIPS 204) digital signatures (44/65/87)
- Added SLH-DSA (FIPS 205) hash-based signatures (all 12 parameter sets)
- Added X-Wing hybrid KEM (X25519 + ML-KEM-768, IETF draft)
- ASN.1/DER key encoding for PQC algorithms (PKCS#8, X.509)
- Added XAES-256-GCM extended-nonce authenticated encryption

**2026.2.1** (February 2026) - Correctness Fix
- Fixed Crypto++ Issue #1342: DSA/ECDSA invalid signature (r=0 or s=0) in release builds
- Probabilistic signatures retry with fresh random k
- Deterministic signatures (RFC 6979) abort with exception

**2026.2.0** (February 2026) - Security Release
- Fixed CVE-2024-28285: Hardened hybrid DL decryption against fault injection
- No-write-on-failure guarantee for ElGamal, ECIES, DLIES decryption
- Exponent blinding verification to detect faulted computations

**2026.1.0** (January 2026) - Minor Release
- Added BLAKE3 AVX-512 16-way parallel chunk hashing (over 4000 MiB/s)
- Added XAES-256-GCM extended-nonce authenticated encryption (C2SP spec)
- Added AES-CTR-HMAC authenticated encryption (encrypt-then-MAC)
- Hardened XAES-256-GCM and AES-CTR-HMAC against misuse
- Improved exception safety and portability

**2025.12.0** (December 2025) - Major Release
- Complete project reorganization (204 source files in categorized src/ directories)
- BLAKE3 SIMD acceleration (SSE4.1/AVX2/NEON parallel chunk processing, ~2500 MiB/s)
- Modern CMake build system (3.20+, presets, find_package() support)
- Updated all build systems (GNUmakefile, MSVC projects, nmake)
- Comprehensive documentation (CMAKE.md, GNUMAKEFILE.md, GETTING_STARTED.md)
- Multi-platform CI/CD with 50+ build configurations
- Maintained full backward compatibility

**2025.11.0** (November 2025) - First Release
- Forked from Crypto++ 8.9.0 (commit 60f81a77)
- Added BLAKE3 cryptographic hash
- Added Argon2 password hashing (RFC 9106)
- Migrated to calendar versioning
- Fixed Marvin attack (CVE-2023-50979)
- Improved ESIGN static analyzer compatibility

### Upstream Crypto++ Releases

**8.9.0** (October 1, 2023)
- Last semantic versioning release
- Fixed spurious assert (GH #1279)

**8.8.0** (January 30, 2023)
- 10 months prior

**8.7.0** (August 7, 2022)
- 6 months prior

---

## Current Status

### Phase 2: Organization (2025.12.0) ✅
- ✅ Complete source reorganization (204 files in categorized directories)
- ✅ Modern CMake build system with presets and find_package() support
- ✅ BLAKE3 SIMD acceleration (SSE4.1, AVX2, ARM NEON)
- ✅ All build systems updated (CMake, GNUmakefile, MSVC, nmake)
- ✅ Comprehensive documentation (CMAKE.md, GNUMAKEFILE.md, GETTING_STARTED.md)
- ✅ Backward compatibility maintained
- ✅ Multi-platform CI/CD with 50+ build configurations

### Phase 1: Foundation (2025.11.0) ✅
- ✅ Fork established
- ✅ Calendar versioning implemented
- ✅ BLAKE3 added
- ✅ Argon2 added
- ✅ Security fixes integrated

---

## Upstream Relationship

This is a maintained fork to:
- Serve users who need modern algorithms and faster development
- Provide an alternative for active maintenance
- Experiment with improvements

**We will:**
- Continue monitoring upstream for security fixes
- Incorporate critical security patches
- Maintain compatibility where practical

---

## Comparison

### cryptopp-modern vs. Upstream Crypto++

| Aspect | Crypto++ 8.9.0 | cryptopp-modern 2026.7.1 |
|--------|----------------|---------------------------|
| **Last Release** | October 1, 2023 | July 2026 |
| **Versioning** | Semantic (8.9.0) | Calendar (2026.7.1) |
| **BLAKE3** | ❌ | ✅ with AVX-512 (over 4000 MiB/s) |
| **Argon2** | ❌ | ✅ RFC 9106 |
| **XAES-256-GCM** | ❌ | ✅ C2SP spec |
| **AES-CTR-HMAC** | ❌ | ✅ Encrypt-then-MAC |
| **Post-Quantum** | ❌ | ✅ ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, X-Wing |
| **Marvin Fix** | ❌ | ✅ CVE-2023-50979 |
| **CMake** | Basic | Modern (presets, find_package) |
| **Organization** | Flat structure | Categorized src/ dirs |
| **CI/CD** | Limited | 50+ configurations |
| **Namespace** | `CryptoPP` | `CryptoPP` (compatible) |
| **License** | Boost 1.0 | Boost 1.0 |

---

## Credits

**cryptopp-modern** builds on decades of work by:
- **Wei Dai** - Original Crypto++ creator and maintainer
- **The Crypto++ team** - All contributors to upstream
- **Jeffrey Walton** - Major Crypto++ contributor and maintainer
- **The cryptography community** - Algorithm designers and security researchers


---

## Contact

- **Website:** https://cryptopp-modern.com
- **Issues:** https://github.com/cryptopp-modern/cryptopp-modern/issues
- **Discussions:** https://github.com/cryptopp-modern/cryptopp-modern/discussions
- **Upstream Crypto++:** https://github.com/weidai11/cryptopp

---

**Last Updated:** 2026-07-12
**Fork Point:** Crypto++ 8.9.0 (commit 60f81a77)
**Current Version:** 2026.7.1
