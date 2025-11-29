# FORK.md - Relationship to Upstream Crypto++

**cryptopp-modern** is a friendly fork of [Crypto++](https://github.com/weidai11/cryptopp), maintained separately to add modern algorithms and improve the library structure.

---

## Why Fork?

**Upstream Crypto++ Status:**
- Last release: 8.9.0 (October 1, 2023)
- Development pace: Very slow (14+ months since last release)
- Version encoding limitation: Cannot represent version 8.10.0 without ambiguity
- Modern algorithms: Missing (BLAKE3, Argon2, post-quantum)

**cryptopp-modern Goals:**
- Active maintenance with regular releases
- Modern cryptographic algorithms (BLAKE3, Argon2, post-quantum planned)
- Better code organization (Phase 2 complete - categorized src/ directories)
- Calendar versioning (YEAR.MONTH.INCREMENT)
- Improved documentation and organisation
- Community-driven development

---

## Version History

### cryptopp-modern Releases

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

This is a friendly fork to:
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

| Aspect | Crypto++ 8.9.0 | cryptopp-modern 2025.12.0 |
|--------|----------------|---------------------------|
| **Last Release** | October 1, 2023 | December 2025 |
| **Versioning** | Semantic (8.9.0) | Calendar (2025.12.0) |
| **BLAKE3** | ❌ | ✅ with SIMD (~2500 MiB/s) |
| **Argon2** | ❌ | ✅ RFC 9106 |
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

**Last Updated:** 2025-11-29
**Fork Point:** Crypto++ 8.9.0 (commit 60f81a77)
**Current Version:** 2025.12.0
