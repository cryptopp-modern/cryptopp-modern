# cryptopp-modern 2025.12.0 Release Notes

**Release Date:** December 2025
**Release Type:** Major Release

---

## Overview

cryptopp-modern 2025.12.0 is a major release featuring complete project reorganisation, a modern CMake build system, high-performance BLAKE3 SIMD optimisations, and comprehensive documentation.

### Roadmap Progress

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Foundation (BLAKE3, Argon2, security fixes) | ✅ Complete (2025.11.0) |
| Phase 2 | Organisation (source reorganisation) | ✅ Complete |
| Phase 3 | CMake Build System | ✅ Complete |
| Phase 4 | Documentation | ✅ Complete |
| Phase 5 | CI/CD & Quality (50+ configurations) | ✅ Complete |

See [ROADMAP.md](ROADMAP.md) for full details.

---

## Highlights

- **Complete Project Reorganisation** - 204 source files organised into logical `src/` subdirectories
- **Modern CMake Build System** - CMake 3.20+ with presets and `find_package()` support
- **BLAKE3 SIMD Acceleration** - SSE4.1/AVX2/NEON parallel chunk processing (~2500 MiB/s)
- **Comprehensive Documentation** - Build guides, getting started, and algorithm reference
- **50+ CI Build Configurations** - Multi-platform, multi-compiler testing

---

## What's New

### Complete Project Reorganization

All 204 source files organized into categorized `src/` subdirectories:

| Directory | Description | Files |
|-----------|-------------|-------|
| `src/core/` | Core infrastructure | 37 |
| `src/hash/` | Hash functions (SHA, BLAKE2/3, etc.) | 32 |
| `src/kdf/` | Key derivation (Argon2, Scrypt) | 2 |
| `src/symmetric/` | Block/stream ciphers (AES, ChaCha, etc.) | 58 |
| `src/pubkey/` | Public key cryptography (RSA, EC, etc.) | 26 |
| `src/mac/` | Message authentication codes | 6 |
| `src/modes/` | Cipher modes (GCM, CCM, XTS, etc.) | 9 |
| `src/encoding/` | Encoding/compression | 8 |
| `src/random/` | Random number generation | 9 |
| `src/util/` | Utilities | 3 |
| `src/test/` | Test files | 23 |

### Modern CMake Build System

- **CMake 3.20+** with modern best practices
- **Presets** - default, debug, release, msvc, no-asm, ci-linux, ci-macos, ci-windows
- **`find_package(cryptopp-modern)`** - Proper CMake package support
- **`cryptopp::cryptopp`** - Modern imported target
- **Automatic SIMD detection** - Per-file compiler flags for SSE, AVX, AES-NI, SHA-NI
- **pkg-config support** - For traditional build systems

```cmake
find_package(cryptopp-modern REQUIRED)
target_link_libraries(myapp PRIVATE cryptopp::cryptopp)
```

### BLAKE3 SIMD Parallel Chunk Processing

High-performance BLAKE3 implementation with parallel chunk processing:

| Platform | Implementation | Performance |
|----------|---------------|-------------|
| x86-64 AVX2 | 8-way parallel | ~2500 MiB/s |
| x86-64 SSE4.1 | 4-way parallel | ~1200 MiB/s |
| ARM NEON | Vectorized | Optimized |
| Fallback | Pure C++ | Compatible |

Performance comparison (Intel Core Ultra 7 155H):
- BLAKE3 AVX2: **2599 MiB/s**
- BLAKE2b SSE4.1: 837 MiB/s
- BLAKE3 is **3.1x faster** than BLAKE2b

### Comprehensive Documentation

- **[CMAKE.md](CMAKE.md)** - CMake build system documentation
- **[GNUMAKEFILE.md](GNUMAKEFILE.md)** - GNUmakefile build system documentation
- **[GETTING_STARTED.md](GETTING_STARTED.md)** - Quick start guide with code examples
- **[Website](https://cryptopp-modern.com)** - Full documentation site

### Build System Updates

All build systems updated:

- **CMake** - New modern build system
- **GNUmakefile** - Updated with `static-exe` target for MinGW
- **MSVC Projects** - Updated for Visual Studio 2022
- **nmake** - Updated for command-line builds

### CI/CD Testing

**50+ build configurations** tested on every push:

- **Platforms:** Windows, Linux, macOS (including Apple Silicon)
- **Compilers:** MSVC 2022, GCC 11/12/13/14, Clang 15/16/17, Apple Clang
- **Standards:** C++14, C++17, C++20
- **Sanitizers:** AddressSanitizer, UndefinedBehaviorSanitizer
- **Build Types:** CMake, GNUmakefile, MSVC, nmake
- **Special:** No-ASM pure C++ build, installation tests

---

## Previous Features (from 2025.11.0)

- **BLAKE3** - Modern, fast cryptographic hash function
- **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)
- **Security Patches** - Marvin attack fix (CVE-2023-50979)
- **ESIGN Improvements** - Better static analyzer compatibility
- **Calendar Versioning** - YEAR.MONTH.INCREMENT format

---

## Installation

### CMake

```bash
# Clone and build
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

cmake --preset=default
cmake --build build/default
./build/default/cryptest.exe v

# Install
sudo cmake --install build/default
```

### GNUmakefile

```bash
# Linux/macOS
make -j$(nproc)
./cryptest.exe v
sudo make install

# Windows (MinGW) - static linking
mingw32-make -j10 static-exe
./cryptest.exe v
```

### Visual Studio

Open `cryptest.sln` and build Release configuration.

---

## Migration from Crypto++ 8.9.0

**No code changes required!** This is a drop-in replacement.

### What Works Unchanged

- All existing algorithms and APIs
- Same `CryptoPP` namespace
- Same include paths: `#include <cryptopp/aes.h>`
- Version checks: `#if CRYPTOPP_VERSION >= N`

### Version Encoding Change

```cpp
// Old (Crypto++ 8.9.0): 890
const int major = CRYPTOPP_VERSION / 100;  // Gets 8

// New (2025.12.0): 20251200
const int year = CRYPTOPP_VERSION / 10000;           // Gets 2025
const int month = (CRYPTOPP_VERSION / 100) % 100;   // Gets 12
const int increment = CRYPTOPP_VERSION % 100;       // Gets 0
```

---

## Breaking Changes

None. This release maintains full backward compatibility with Crypto++ 8.9.0.

---

## Known Issues

None at this time.

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
- **BLAKE3 team** - Modern hash function design
- **Argon2 team** - Password hashing competition winner

---

## License

- **Compilation:** Boost Software License 1.0
- **Individual files:** Public domain

See [License.txt](License.txt) for details.

---

**Thank you for using cryptopp-modern!**
