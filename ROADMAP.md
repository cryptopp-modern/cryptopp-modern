# cryptopp-modern Development Roadmap

**Current Version:** 2025.12.0 (Release Candidate)

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
- ✅ **Security Patches** - Marvin attack fix (CVE-2022-4304), ESIGN improvements
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

## Phase 3: CMake Build System 📋 PLANNED

**Goal:** Add CMake alongside existing build system

### Planned
- 🔨 Add modern CMakeLists.txt (CMake 3.15+)
- 📦 Proper target exports and find_package support
- 🔧 Install rules and package configuration
- 📊 CMake presets for common configurations
- ⚙️ Continue maintaining GNUmakefile

**Note:** Both CMake and GNUmakefile will be maintained as build options.

---

## Phase 4: Documentation 📋 PLANNED

**Goal:** Comprehensive, modern documentation site

### Planned
- 🌐 Documentation website (MkDocs Material or Docusaurus)
- 📖 Getting started guide
- 📋 Algorithm reference by category
- 💡 Code examples for every algorithm
- 🔄 Migration guide from Crypto++ 8.9.0
- 🔍 API reference (Doxygen integration)
- 🚀 Publish to Pages

---


## Phase 5: CI/CD & Quality 🔄 IN PROGRESS

**Goal:** Automated testing and quality assurance

### Completed
- ✅ **GitHub Actions Workflows**
  - Multi-platform builds (Windows MSVC 2022, Linux, macOS)
  - Multiple compilers (GCC 9-13, Clang 14-17, MSVC, Apple Clang)
  - Multiple C++ standards (C++11, C++14, C++17)
  - 45+ build configurations per push
- ✅ **Security Testing**
  - Address Sanitizer (ASan)
  - UndefinedBehavior Sanitizer (UBSan)
- ✅ **Build Verification**
  - Static and dynamic library builds
  - Installation testing
  - Validation tests and test vectors on all platforms

### Planned
- 📊 **Code Quality**
  - Memory Sanitizer (MSan)
  - Static analysis (clang-tidy, cppcheck)
  - Code coverage reporting
  - Benchmark tracking


---

## Contributing

We welcome contributions in these areas:

- 🐛 **Bug Reports** - Find and report issues
- ✨ **New Algorithms** - Implement modern crypto algorithms
- 📚 **Documentation** - Improve docs and examples
- 🧪 **Testing** - Add tests and test vectors
- 🔧 **Build System** - Improve CMake and cross-platform support
- 📦 **Packaging** - Help with package manager integration

See [FORK.md](FORK.md) for project details and direction.

---

## Version History

### 2025.12.0 (December 2025) - Organization Release
- 📁 Complete project reorganization (Phase 2)
- 🏗️ Organized 204 source files into categorized `src/` directories
- 📦 Maintained backward compatibility with flat include structure
- ✅ Multi-platform CI/CD with 45+ build configurations
- 🔧 Updated build systems (GNUmakefile, MSVC project files, nmake)
- 🧪 Comprehensive testing across all platforms

### 2025.11.0 (November 2025) - Foundation Release
- 🎉 First release with calendar versioning
- ✨ Added BLAKE3 cryptographic hash
- ✨ Added Argon2 password hashing (d/i/id variants)
- 🔒 Fixed Marvin attack (CVE-2022-4304)
- 🔒 Improved ESIGN static analyzer compatibility

---

## Questions or Suggestions?

- **GitHub Issues:** [Report bugs or request features](https://github.com/Coralesoft/cryptopp-modern/issues)
- **GitHub Discussions:** [Ask questions or discuss ideas](https://github.com/Coralesoft/cryptopp-modern/discussions)

---

**Maintained By:** [CoraleSoft](https://github.com/Coralesoft)
