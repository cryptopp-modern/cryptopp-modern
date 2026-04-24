# cryptopp-modern Development Roadmap

**Current Version:** 2026.4.0

---

## Vision

**cryptopp-modern** is an actively maintained, modernized fork of Crypto++ featuring:
- Modern cryptographic algorithms (BLAKE3, Argon2, post-quantum)
- Better code organization and structure
- Comprehensive documentation
- Active development and community engagement
- Calendar versioning for clarity

---

## Phase 1: Foundation ✅ COMPLETE

**Goal:** Establish working fork with essential modern algorithms

### Completed
- ✅ **BLAKE3 Cryptographic Hash** - Modern, fast hash function
- ✅ **Argon2 Password Hashing** - RFC 9106 (Argon2d, Argon2i, Argon2id)
- ✅ **Calendar Versioning** - Clear release dates (YEAR.MONTH.INCREMENT)
- ✅ **Security Patches** - Marvin attack fix (CVE-2023-50979), ESIGN improvements
- ✅ **Repository Setup** - GitHub repository with documentation
- ✅ **Build System** - Working GNUmakefile builds

**Release:** v2025.11.0

---

## Phase 2: Organization ✅ COMPLETE

**Goal:** Modernize project structure for better navigation

### Completed
- ✅ **Header Organization** - All 194 headers in `include/cryptopp/` directory
- ✅ **Source Organization** - 204 source files organized into categorized `src/` subdirectories:
  - `src/core/` - Core infrastructure (37 files)
  - `src/hash/` - Hash functions (32 files)
  - `src/kdf/` - Key derivation (2 files)
  - `src/symmetric/` - Block/stream ciphers (58 files)
  - `src/pubkey/` - Public key cryptography (26 files)
  - `src/mac/` - Message authentication codes (6 files)
  - `src/modes/` - Cipher modes (9 files)
  - `src/encoding/` - Encoding/compression (8 files)
  - `src/random/` - Random number generation (9 files)
  - `src/util/` - Utilities (3 files)
  - `src/test/` - Test files (23 files)
- ✅ **Include Path Updates** - All source files updated to `<cryptopp/header.h>` format
- ✅ **Build System Updates** - GNUmakefile and MSVC project files updated
- ✅ **Backward Compatibility** - Maintained flat `include/cryptopp/` structure for drop-in replacement
- ✅ **Testing Verified** - All tests pass across all platforms

---

## Phase 3: CMake Build System ✅ COMPLETE

**Goal:** Add CMake alongside existing build system

### Completed
- ✅ **Modern CMakeLists.txt** - CMake 3.20+ with full feature support
- ✅ **Target Exports** - Proper `find_package(cryptopp-modern)` and `cryptopp::cryptopp` target
- ✅ **Install Rules** - Headers, libraries, and CMake config files
- ✅ **CMake Presets** - default, debug, release, msvc, ci-linux, ci-macos, ci-windows, no-asm
- ✅ **SIMD Detection** - Automatic detection and per-file compiler flags (SSE, AVX, AES-NI, SHA-NI)
- ✅ **Cross-Platform** - Tested on Windows (MSVC, MinGW), Linux (GCC, Clang), macOS (Apple Clang)
- ✅ **pkg-config Support** - Generated .pc file for traditional build systems

**Note:** Both CMake and GNUmakefile are maintained as build options.

---

## Phase 4: Documentation ✅ COMPLETE

**Goal:** Comprehensive, modern documentation site

### Completed
- ✅ **Documentation Website** - Hugo + Hextra theme at [cryptopp-modern.com](https://cryptopp-modern.com)
- ✅ **Getting Started Guide** - Installation and Quick Start tutorials
- ✅ **Algorithm Reference** - 60+ pages organized by category (hash, KDF, symmetric, MAC, pubkey, utilities)
- ✅ **Code Examples** - Production-ready examples for all major algorithms
- ✅ **Migration Guide** - Complete guide for migrating from Crypto++ 8.9.0
- ✅ **Educational Content** - Beginner's guide, security concepts, password hashing best practices
- ✅ **Published** - Live at https://cryptopp-modern.com

---


## Phase 5: CI/CD & Quality ✅ COMPLETE

**Goal:** Automated testing and quality assurance

### Completed
- ✅ **Unified CI Workflow** - Single `build-and-test.yml` covering all platforms and build systems
- ✅ **CMake CI Testing**
  - Linux (GCC + Ninja)
  - macOS (Clang + Ninja)
  - Windows (MSVC)
  - No-ASM build (pure C++ fallbacks)
  - Installation and `find_package()` integration test
- ✅ **Makefile CI Testing**
  - Linux GCC 11/12/13 with C++14/17/20
  - Linux Clang 15/16/17 with C++14/17/20
  - macOS Apple Clang with C++14/17/20
  - Windows MSVC x64/Win32
- ✅ **Security Testing**
  - Address Sanitizer (ASan)
  - UndefinedBehavior Sanitizer (UBSan)
- ✅ **Build Verification**
  - 50+ build configurations per push
  - Validation tests and test vectors on all platforms

### Planned (Future)
- **Code Quality Enhancements**
  - Memory Sanitizer (MSan)
  - Static analysis (clang-tidy, cppcheck)
  - Code coverage reporting
  - Benchmark tracking

---

## Phase 6: Post-Quantum Cryptography ✅ COMPLETE

**Goal:** Implement NIST FIPS standardized post-quantum algorithms

### Completed
- ✅ **ML-KEM (FIPS 203)** - Module-Lattice Key Encapsulation Mechanism
  - ML-KEM-512 (Level 1, 128-bit security)
  - ML-KEM-768 (Level 3, 192-bit security)
  - ML-KEM-1024 (Level 5, 256-bit security)
  - NTT-based polynomial multiplication for performance
  - Compliant with FIPS 203 final specification
- ✅ **ML-DSA (FIPS 204)** - Module-Lattice Digital Signature Algorithm
  - ML-DSA-44 (Level 2, 128-bit security)
  - ML-DSA-65 (Level 3, 192-bit security)
  - ML-DSA-87 (Level 5, 256-bit security)
  - Based on CRYSTALS-Dilithium reference implementation
  - PK_Signer/PK_Verifier interface integration
- ✅ **SLH-DSA (FIPS 205)** - Stateless Hash-Based Digital Signature Algorithm
  - All 12 parameter sets (SHA-2 and SHAKE variants)
  - 128-bit, 192-bit, and 256-bit security levels
  - Small (s) and fast (f) variants
- ✅ **X-Wing** - Hybrid KEM combining X25519 + ML-KEM-768 (IETF draft)

**Note:** Post-quantum algorithms provide security against both classical and quantum computer attacks, preparing applications for the post-quantum era.

---

## Contributing

We welcome contributions in these areas:

- **Bug Reports** - Find and report issues
- **New Algorithms** - Implement modern crypto algorithms
- **Documentation** - Improve docs and examples
- **Testing** - Add tests and test vectors
- **Build System** - Improve CMake and cross-platform support
- **Packaging** - Help with package manager integration

See [FORK.md](FORK.md) for project details and direction.

---

## Version History

### 2026.4.0 (April 2026) - Security Fix
- **Ed25519 Canonicality** - Fixed accepting non-canonical public keys (Issue #1348)
- Regression test covering canonical and non-canonical y vectors

### 2026.3.0 (March 2026) - Post-Quantum Cryptography Release
- **ML-KEM (FIPS 203)** - Module-Lattice Key Encapsulation (512/768/1024)
- **ML-DSA (FIPS 204)** - Module-Lattice Digital Signatures (44/65/87)
- **SLH-DSA (FIPS 205)** - Stateless Hash-Based Signatures (all 12 parameter sets)
- **X-Wing** - Hybrid KEM combining X25519 + ML-KEM-768 (IETF draft)
- ASN.1/DER key encoding for PQC algorithms (PKCS#8, X.509)
- NIST ACVP test vectors for all PQC algorithms
- Updated build systems (GNUmakefile, nmake, Visual Studio)

### 2026.2.1 (February 2026) - Correctness Fix
- **DSA/ECDSA Fix** - Fixed invalid signature (r=0 or s=0) in release builds (Issue #1342)

### 2026.2.0 (February 2026) - Security Release
- **CVE-2024-28285 Fix** - Hardened hybrid DL decryption (ElGamal, ECIES, DLIES) against fault injection
- **No-Write-on-Failure** - Plaintext buffer untouched unless decryption succeeds
- **Blinded Verification** - Detects faulted key-agreement computations before releasing plaintext

### 2026.1.0 (January 2026) - New Algorithms Release
- **BLAKE3 AVX-512** - 16-way parallel chunk hashing
  - over 4000 MiB/s on supported processors
  - Automatic runtime CPU detection with graceful fallback
- **XAES-256-GCM** - Extended-nonce AES-GCM (C2SP specification)
  - 256-bit (32-byte) nonces safe for random generation
  - Solves nonce management problem for AES-GCM users
- **AES-CTR-HMAC** - Encrypt-then-MAC authenticated encryption
  - Template-based: works with any block cipher and hash function
  - HKDF key derivation for encryption and MAC keys
- Hardened XAES-256-GCM and AES-CTR-HMAC against misuse
- Improved exception safety and portability
- Dropped non-standard stdext namespace usage

### 2025.12.0 (December 2025) - Organization & CMake Release
- Complete project reorganization (Phase 2)
- Organized 204 source files into categorized `src/` directories
- Maintained backward compatibility with flat include structure
- Modern CMake build system with presets and `find_package()` support (Phase 3)
- BLAKE3 SIMD parallel chunk processing
  - SSE4.1 4-way and AVX2 8-way parallel hashing (~2500 MiB/s)
  - ARM NEON support with graceful fallback
- Unified CI/CD workflow with 50+ build configurations (Phase 5)
- Updated build systems (GNUmakefile, MSVC, nmake, CMake)
- Comprehensive documentation (CMAKE.md, GNUMAKEFILE.md, GETTING_STARTED.md)
- Comprehensive testing across all platforms

### 2025.11.0 (November 2025) - Foundation Release
- First release with calendar versioning
- Added BLAKE3 cryptographic hash
- Added Argon2 password hashing (d/i/id variants)
- Fixed Marvin attack (CVE-2023-50979)
- Improved ESIGN static analyzer compatibility

---

## Questions or Suggestions?

- **GitHub Issues:** [Report bugs or request features](https://github.com/cryptopp-modern/cryptopp-modern/issues)
- **GitHub Discussions:** [Ask questions or discuss ideas](https://github.com/cryptopp-modern/cryptopp-modern/discussions)

---

**Maintained By:** [CoraleSoft](https://github.com/Coralesoft)
