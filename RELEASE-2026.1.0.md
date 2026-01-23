# cryptopp-modern 2026.1.0 Release Notes

**Release Date:** January 2026
**Release Type:** Minor Release

---

## Overview

cryptopp-modern 2026.1.0 adds BLAKE3 AVX-512 acceleration, two new authenticated encryption modes (XAES-256-GCM and AES-CTR-HMAC), security hardening, and portability improvements.

---

## Highlights

- **BLAKE3 AVX-512** - 16-way parallel chunk hashing for maximum throughput
- **XAES-256-GCM** - Extended-nonce AES-GCM with 256-bit nonces (C2SP specification)
- **AES-CTR-HMAC** - Encrypt-then-MAC authenticated encryption
- **Security Hardening** - Improved misuse resistance for authenticated encryption
- **Portability** - Enhanced exception safety and cross-platform compatibility

---

## What's New

### BLAKE3 AVX-512 Acceleration

Added 16-way parallel chunk hashing using AVX-512 instructions:

- **16-way parallel processing** - Hash 16 chunks simultaneously
- **16KB chunk buffer** - Optimal for large data processing
- **Native rotate instructions** - Uses AVX-512 `vprord` for efficient rotations
- **Automatic detection** - Runtime CPU feature detection with graceful fallback

| SIMD Level | Parallel Chunks | Performance |
|------------|-----------------|-------------|
| SSE4.1 | 4-way | ~1200 MiB/s |
| AVX2 | 8-way | ~2500 MiB/s |
| **AVX-512** | **16-way** | **~4000+ MiB/s** |

### XAES-256-GCM (Extended-Nonce AES-GCM)

Extended-nonce variant of AES-GCM based on the C2SP specification:

- **256-bit (32-byte) nonces** - Safe for random generation without collision risk
- **Solves nonce management** - No need to track nonce state across messages
- **AES-256 security** - Full 256-bit key strength
- **Standard AES-GCM under the hood** - Uses key derivation to create per-message subkey

```cpp
#include <cryptopp/xaes_256_gcm.h>

using namespace CryptoPP;

// 256-bit key
SecByteBlock key(32);
prng.GenerateBlock(key, key.size());

// 256-bit nonce - safe to generate randomly!
SecByteBlock nonce(32);
prng.GenerateBlock(nonce, nonce.size());

// Encrypt
XAES_256_GCM<true>::Encryption enc;
enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

std::string cipher;
StringSource(plaintext, true,
    new AuthenticatedEncryptionFilter(enc,
        new StringSink(cipher)));

// Decrypt
XAES_256_GCM<false>::Decryption dec;
dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

std::string recovered;
StringSource(cipher, true,
    new AuthenticatedDecryptionFilter(dec,
        new StringSink(recovered)));
```

### AES-CTR-HMAC Authenticated Encryption

Encrypt-then-MAC construction using AES-CTR and HMAC:

- **Encrypt-then-MAC** - Industry-standard authenticated encryption pattern
- **Template-based** - Works with any block cipher and hash function
- **HKDF key derivation** - Separate encryption and MAC keys derived from master key
- **96-bit IV** - Standard 12-byte initialization vector
- **128-bit authentication tag** - Strong message authentication

```cpp
#include <cryptopp/aes_ctr_hmac.h>

using namespace CryptoPP;

// Default: AES-CTR with HMAC-SHA256
AES_CTR_HMAC<AES, SHA256>::Encryption enc;
AES_CTR_HMAC<AES, SHA256>::Decryption dec;

// 256-bit key
SecByteBlock key(32);
prng.GenerateBlock(key, key.size());

// 96-bit IV
SecByteBlock iv(12);
prng.GenerateBlock(iv, iv.size());

// Encrypt
enc.SetKeyWithIV(key, key.size(), iv, iv.size());
std::string cipher;
StringSource(plaintext, true,
    new AuthenticatedEncryptionFilter(enc,
        new StringSink(cipher)));

// Decrypt
dec.SetKeyWithIV(key, key.size(), iv, iv.size());
std::string recovered;
StringSource(cipher, true,
    new AuthenticatedDecryptionFilter(dec,
        new StringSink(recovered)));
```

### Security Hardening

- **XAES-256-GCM** - Hardened against streaming misuse and side channels
- **AES-CTR-HMAC** - Hardened against misuse with enforced tag size bounds
- **Exception safety** - Improved error handling and resource cleanup
- **Portability** - Better cross-platform compatibility

### Other Changes

- Dropped non-standard `stdext` namespace usage for better portability
- Fixed MSVC warnings and updated CI workflows
- Added `/arch:AVX2` flag for BLAKE3 SIMD on MSVC
- Added `branch-build-and-test.yml` for manual CI triggers
- Consolidated license files
- Improved README layout and discoverability

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

## Migration from 2025.12.0

**No breaking changes.** This is a minor release with new features only.

### New Headers

- `#include <cryptopp/xaes_256_gcm.h>` - XAES-256-GCM
- `#include <cryptopp/aes_ctr_hmac.h>` - AES-CTR-HMAC

---

## Previous Features

All features from 2025.12.0 remain available:

- **BLAKE3** - Modern, fast cryptographic hash (~2500 MiB/s with AVX2)
- **Argon2** - RFC 9106 password hashing (Argon2d, Argon2i, Argon2id)
- **Modern CMake** - Presets, `find_package()`, proper target exports
- **Organized Source** - 204 files in categorized `src/` directories
- **50+ CI Configurations** - Multi-platform, multi-compiler testing

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

---

## License

- **Compilation:** Boost Software License 1.0
- **Individual files:** Public domain

See [LICENSE](LICENSE) for details.

---

**Thank you for using cryptopp-modern!**
