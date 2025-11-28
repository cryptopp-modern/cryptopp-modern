# cryptopp-modern 2025.12.0-rc1 Release Notes

**Release Type:** Release Candidate 1
**Release Date:** November 23, 2025
**Final Release:** Planned December 2025

---

## Overview

This is the first release candidate for cryptopp-modern 2025.12.0, marking the completion of **Phase 2: Organization**.

This major release completely reorganizes the project structure with 204 source files now categorized into logical `src/` subdirectories while maintaining full backward compatibility.

---

## What's New

### Complete Project Reorganization (Phase 2)

All 204 source files have been organized into categorized `src/` subdirectories:

- **`src/core/`** - Core infrastructure (37 files)
  - cryptlib, cpu, integer, algebra, filters, etc.

- **`src/hash/`** - Hash functions (32 files)
  - SHA, BLAKE2/BLAKE3, Keccak, MD5, Tiger, Whirlpool, etc.

- **`src/kdf/`** - Key derivation (2 files)
  - Argon2, Scrypt

- **`src/symmetric/`** - Block/stream ciphers (58 files)
  - AES, ChaCha, Salsa, Camellia, ARIA, etc.

- **`src/pubkey/`** - Public key cryptography (26 files)
  - RSA, DSA, EC, DH, x25519, etc.

- **`src/mac/`** - Message authentication codes (6 files)
  - HMAC, CMAC, Poly1305, VMAC, etc.

- **`src/modes/`** - Cipher modes (9 files)
  - GCM, CCM, EAX, XTS, etc.

- **`src/encoding/`** - Encoding/compression (8 files)
  - Base64, Hex, GZIP, ZLIB, etc.

- **`src/random/`** - Random number generation (9 files)
  - OSRNG, RDRAND, DARN, etc.

- **`src/util/`** - Utilities (3 files)
  - Timer, IDA, simple

- **`src/test/`** - Test files (23 files)
  - All validation and test programs

### Build System Updates

All build systems updated for new structure:

- ✅ **GNUmakefile** - Updated for Linux/macOS/MSYS builds
- ✅ **MSVC Project Files** (.vcxproj) - Updated for Visual Studio 2003-2022
- ✅ **nmake** (cryptest.nmake) - Updated for command-line MSVC builds

### Backward Compatibility

- **Header structure unchanged** - All 194 headers remain in flat `include/cryptopp/` directory
- **Drop-in replacement** - Compatible with code using Crypto++ 8.9.0
- **Same namespace** - `CryptoPP` namespace unchanged
- **Same APIs** - All existing interfaces preserved

### CI/CD Testing

Comprehensive multi-platform testing with **45+ build configurations**:

- **Windows** - MSVC 2022 (x64, Win32, Debug, Release) + nmake
- **Linux** - GCC 9-13, Clang 14-17 (C++11, C++14, C++17)
- **macOS** - Apple Clang (C++11, C++14, C++17)
- **Sanitizers** - ASan, UBSan for memory safety testing
- **Build Types** - Static library, dynamic library, installation testing

---

## Previous Features (from 2025.11.0)

- ✨ **BLAKE3** - Modern, fast cryptographic hash function
- ✨ **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)
- 🔒 **Security Patches** - Marvin attack fix (CVE-2023-50979)
- 🔒 **ESIGN Improvements** - Better static analyzer compatibility
- 📅 **Calendar Versioning** - YEAR.MONTH.INCREMENT format

---

## Migration from Crypto++ 8.9.0

**No code changes required!** This is a drop-in replacement.

### What Works Unchanged ✓

- All existing algorithms and APIs
- Same `CryptoPP` namespace
- Same include paths: `#include <cryptopp/aes.h>`
- Version checks: `#if CRYPTOPP_VERSION >= N`

### What Changed ⚠️

**Version encoding only:**
- Old: `8.9.0` encoded as `890`
- New: `2025.12.0` encoded as `20251200`

```cpp
// Old version check (Crypto++ 8.9.0)
const int major = CRYPTOPP_VERSION / 100;  // Gets 8

// New version check (2025.12.0)
const int year = CRYPTOPP_VERSION / 10000;           // Gets 2025
const int month = (CRYPTOPP_VERSION / 100) % 100;   // Gets 12
const int increment = CRYPTOPP_VERSION % 100;       // Gets 0
```

---

## Testing Period

**Timeline:**
- **Now - December 2025:** Release Candidate testing period
- **December 2025:** Final 2025.12.0 release (after testing)

**What to test:**
- Build on your platform(s)
- Run validation tests: `cryptest.exe v`
- Run test vectors: `cryptest.exe tv all`
- Test in your application
- Report any issues on GitHub

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Checkout release candidate
git checkout v2025.12.0-rc1

# Linux/macOS
make
make test
sudo make install

# Windows (Visual Studio)
# Open cryptest.sln and build

# Windows (nmake)
nmake /f cryptest.nmake
```

---

## Known Issues

None at this time. Please report issues at:
https://github.com/cryptopp-modern/cryptopp-modern/issues

---

## Upgrade Notes

### For Library Users

Simply replace your Crypto++ 8.9.0 installation with cryptopp-modern 2025.12.0-rc1:

1. Remove old Crypto++ headers
2. Install cryptopp-modern headers from `include/cryptopp/`
3. Recompile your application
4. Test thoroughly

### For Library Developers

If you're contributing or building from source:

- Source files are now in categorized `src/` directories
- Headers remain in flat `include/cryptopp/` structure
- All source files use `#include <cryptopp/header.h>` format
- Update your IDE/build system to find sources in `src/` subdirectories

---

## Next Steps

### Phase 3: CMake Build System (Planned)

- Modern CMakeLists.txt (CMake 3.15+)
- Proper target exports and find_package support
- Install rules and package configuration
- CMake presets for common configurations
- Continue maintaining GNUmakefile alongside CMake

### Phase 4: Documentation (Planned)

- Documentation website (MkDocs Material or Docusaurus)
- Getting started guide
- Algorithm reference by category
- Code examples for every algorithm
- Migration guide from Crypto++ 8.9.0
- API reference (Doxygen integration)

---

## Links

- **GitHub Repository:** https://github.com/cryptopp-modern/cryptopp-modern
- **Issues:** https://github.com/cryptopp-modern/cryptopp-modern/issues
- **Discussions:** https://github.com/cryptopp-modern/cryptopp-modern/discussions
- **Roadmap:** [ROADMAP.md](ROADMAP.md)
- **Fork Details:** [FORK.md](FORK.md)

---

## Contributors

**cryptopp-modern** is maintained by:
- **Colin Brown** / [CoraleSoft](https://github.com/Coralesoft)

Built upon the excellent work of:
- **Wei Dai** - Original Crypto++ creator
- **Jeffrey Walton** - Crypto++ maintainer and build system contributions
- **The Crypto++ Project** - All upstream contributors

---

## License

Like the original Crypto++, cryptopp-modern uses:
- **Compilation:** Boost Software License 1.0
- **Individual files:** Public domain

See [License.txt](License.txt) for details.

---

**Thank you for testing cryptopp-modern 2025.12.0-rc1!**

Please report any issues or feedback on GitHub.
