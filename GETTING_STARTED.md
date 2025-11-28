# Getting Started with cryptopp-modern

Quick start guide with practical examples to get you up and running with cryptopp-modern.

**Full documentation:** https://cryptopp-modern.com

## Table of Contents

- [Installation](#installation)
- [Your First Program](#your-first-program)
- [Common Use Cases](#common-use-cases)
  - [Hashing Data](#hashing-data)
  - [Encrypting Data](#encrypting-data)
  - [Password Hashing](#password-hashing)
  - [Message Authentication](#message-authentication)
  - [Random Number Generation](#random-number-generation)
  - [Digital Signatures](#digital-signatures)
  - [Key Exchange](#key-exchange)
- [Building Your Application](#building-your-application)
- [Next Steps](#next-steps)

---

## Installation

### Build Systems Overview

| Build System | Best For | Platforms |
|--------------|----------|-----------|
| **CMake** | IDE integration, presets, `find_package()` support | All |
| **GNUmakefile** | Traditional Make-based workflows, packaging scripts | Linux, macOS, MinGW |
| **Visual Studio** | Native Windows development with full IDE | Windows |
| **nmake** | Windows command-line builds without IDE | Windows |

### Prerequisites

**Linux (Debian/Ubuntu):**
```bash
sudo apt install build-essential cmake ninja-build
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install gcc-c++ cmake ninja-build
```

**macOS:**
```bash
xcode-select --install
brew install cmake ninja
```

**Windows:**
- Visual Studio 2019+ with "Desktop development with C++" workload
- Or MinGW-w64 for GCC-based builds

---

### CMake

CMake provides IDE integration, presets for common configurations, and proper `find_package()` support for consuming projects.

#### Linux / macOS

```bash
# Clone or download
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Configure and build
cmake --preset=default
cmake --build build/default -j$(nproc)

# Run tests
./build/default/cryptest.exe v

# Install (optional)
sudo cmake --install build/default --prefix /usr/local
```

#### Windows (MSVC)

```powershell
# Clone or download
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Configure and build
cmake --preset=msvc
cmake --build build/msvc --config Release

# Run tests
./build/msvc/Release/cryptest.exe v
```

#### Available CMake Presets

| Preset | Description |
|--------|-------------|
| `default` | Release build with Ninja |
| `debug` | Debug build |
| `release` | Release build |
| `msvc` | Visual Studio 2022 |
| `no-asm` | Pure C++ (no assembly) |

---

### GNUmakefile

The GNUmakefile provides a straightforward Make-based build, suitable for classic command-line workflows and packaging scripts.

#### Linux

```bash
# Download latest release
wget https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.12.0/cryptopp-modern-2025.12.0.zip
unzip cryptopp-modern-2025.12.0.zip -d cryptopp-modern
cd cryptopp-modern

# Build and install
make -j$(nproc)
sudo make install PREFIX=/usr/local
sudo ldconfig
```

#### macOS

```bash
# Download and extract
wget https://github.com/cryptopp-modern/cryptopp-modern/releases/download/2025.12.0/cryptopp-modern-2025.12.0.zip
unzip cryptopp-modern-2025.12.0.zip -d cryptopp-modern
cd cryptopp-modern

# Build and install
make -j$(sysctl -n hw.ncpu)
sudo make install PREFIX=/usr/local
```

#### Windows (MinGW)

```bash
# Download and extract cryptopp-modern-2025.12.0.zip
# Open MinGW terminal in extracted folder

# Build
mingw32-make.exe -j10
```

---

### Visual Studio

Visual Studio provides native Windows development with full IDE support, debugging, and IntelliSense.

1. Download and extract cryptopp-modern-2025.12.0.zip
2. Open `cryptest.sln` in Visual Studio
3. Build → Build Solution (Ctrl+Shift+B)

---

### nmake

nmake provides Windows command-line builds without requiring the full Visual Studio IDE, using the MSVC compiler toolchain.

```powershell
# Open "Developer Command Prompt for VS" or "Developer PowerShell for VS"

# Clone or download
git clone https://github.com/cryptopp-modern/cryptopp-modern.git
cd cryptopp-modern

# Build
nmake /f makefile.nmake

# Run tests
cryptest.exe v
```

---

📖 **Detailed build documentation:**
- [CMAKE.md](CMAKE.md) - Full CMake options, presets, and configuration
- [GNUMAKEFILE.md](GNUMAKEFILE.md) - GNUmakefile targets and variables

---

## Your First Program

Create `hello_crypto.cpp`:

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::BLAKE3 hash;
    std::string message = "Hello, cryptopp-modern!";
    std::string digest;

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "Message: " << message << std::endl;
    std::cout << "BLAKE3:  " << digest << std::endl;

    return 0;
}
```

**Compile and run:**

```bash
g++ -std=c++11 hello_crypto.cpp -o hello_crypto -lcryptopp
./hello_crypto
```

**Expected output:**
```
Message: Hello, cryptopp-modern!
BLAKE3:  d1...f3 (64 hex characters)
```

---

## Common Use Cases

### Hashing Data

**Use when:** File integrity checks, checksums, content addressing

#### BLAKE3 (Fast, Modern)

```cpp
#include <cryptopp/blake3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

std::string hashWithBLAKE3(const std::string& data) {
    CryptoPP::BLAKE3 hash;
    std::string digest;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    std::string hash = hashWithBLAKE3("Some data to hash");
    std::cout << "BLAKE3: " << hash << std::endl;
    return 0;
}
```

#### SHA-256 (Industry Standard)

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

std::string hashWithSHA256(const std::string& data) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    std::string hash = hashWithSHA256("Some data to hash");
    std::cout << "SHA-256: " << hash << std::endl;
    return 0;
}
```

#### Hashing Files

```cpp
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>

std::string hashFile(const std::string& filename) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::FileSource(filename.c_str(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

int main() {
    try {
        std::string hash = hashFile("document.pdf");
        std::cout << "File hash: " << hash << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    return 0;
}
```

---

### Encrypting Data

**Use when:** Protecting sensitive data (messages, files, database entries)

#### AES-GCM (Recommended)

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate key and nonce
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock nonce(12);  // 96-bit nonce for GCM
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(nonce, nonce.size());

    std::string plaintext = "Secret message";
    std::string ciphertext, recovered;

    try {
        // Encrypt
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        std::cout << "Encrypted " << plaintext.size() << " bytes" << std::endl;

        // Decrypt
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::AuthenticatedDecryptionFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        std::cout << "Decrypted: " << recovered << std::endl;
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
```

**⚠️ Critical Security Warning:** Always generate a new nonce for each encryption! Reusing a nonce with the same key completely breaks GCM security and can leak your encryption key.

📖 **Learn more:** [Why nonce reuse is catastrophic](https://cryptopp-modern.com/docs/guides/security-concepts#nonce-and-iv-management)

---

### Password Hashing

**Use when:** Storing user passwords securely

#### Argon2 (Recommended for Passwords)

```cpp
#include <cryptopp/argon2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    std::string password = "user_password_123";

    // Generate random salt
    CryptoPP::SecByteBlock salt(16);
    prng.GenerateBlock(salt, salt.size());

    // Hash password
    CryptoPP::SecByteBlock hash(32);
    CryptoPP::Argon2id argon2;

    argon2.DeriveKey(
        hash, hash.size(),
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, salt.size(),
        nullptr, 0,    // No secret
        nullptr, 0,    // No additional data
        3,             // Time cost (iterations)
        65536          // Memory cost (64 MB)
    );

    // Convert to hex for storage
    std::string hashHex;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashHex));
    encoder.Put(hash, hash.size());
    encoder.MessageEnd();

    std::cout << "Password hash: " << hashHex << std::endl;
    std::cout << "Store this hash (and salt) in your database" << std::endl;

    return 0;
}
```

**To verify a password later:**

```cpp
// Compute hash again with same salt and parameters
CryptoPP::SecByteBlock computedHash(32);
argon2.DeriveKey(
    computedHash, computedHash.size(),
    (const CryptoPP::byte*)inputPassword.data(), inputPassword.size(),
    storedSalt, storedSalt.size(),
    nullptr, 0, nullptr, 0,
    3, 65536
);

// Compare using constant-time comparison (prevents timing attacks)
bool valid = CryptoPP::VerifyBufsEqual(computedHash, storedHash, 32);

// 📖 Learn why constant-time matters:
// https://cryptopp-modern.com/docs/guides/security-concepts#constant-time-operations
```

---

### Message Authentication

**Use when:** Verifying data integrity and authenticity (APIs, message signing)

#### HMAC-SHA256

```cpp
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate authentication key
    CryptoPP::SecByteBlock key(32);
    prng.GenerateBlock(key, key.size());

    std::string message = "Important message";
    std::string mac;

    // Create HMAC
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key.size());

    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(mac)
            )
        )
    );

    std::cout << "Message: " << message << std::endl;
    std::cout << "HMAC:    " << mac << std::endl;

    // Verify HMAC
    try {
        CryptoPP::HMAC<CryptoPP::SHA256> verifier(key, key.size());

        // In practice, you'd receive message + mac and verify
        std::string computedMac;
        CryptoPP::StringSource(message, true,
            new CryptoPP::HashFilter(verifier,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(computedMac)
                )
            )
        );

        if (computedMac == mac) {
            std::cout << "HMAC verified: Message is authentic" << std::endl;
        }
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "HMAC verification failed" << std::endl;
    }

    return 0;
}
```

---

### Random Number Generation

**Use when:** Generating keys, tokens, session IDs, nonces

```cpp
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate random bytes
    CryptoPP::SecByteBlock random(32);  // 256 bits
    prng.GenerateBlock(random, random.size());

    // Convert to hex
    std::string randomHex;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(randomHex));
    encoder.Put(random, random.size());
    encoder.MessageEnd();

    std::cout << "Random token: " << randomHex << std::endl;

    // Generate encryption key
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    std::cout << "Generated " << key.size() * 8 << "-bit key" << std::endl;

    return 0;
}
```

**⚠️ Never use `rand()` or `srand()` for cryptographic purposes!** Always use `AutoSeededRandomPool`.

📖 **Learn more:** [Why weak RNGs are dangerous](https://cryptopp-modern.com/docs/guides/security-concepts#secure-random-numbers)

---

### Digital Signatures

**Use when:** Proving authenticity of messages, code signing, document verification

#### Ed25519 (Recommended)

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool rng;

    // Generate key pair
    CryptoPP::ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(rng);

    // Get public key for verification
    CryptoPP::ed25519::Verifier verifier(signer);

    // Sign a message
    std::string message = "Important document content";
    std::string signature;

    CryptoPP::StringSource(message, true,
        new CryptoPP::SignerFilter(rng, signer,
            new CryptoPP::StringSink(signature)
        )
    );

    std::cout << "Message signed, signature size: " << signature.size() << " bytes" << std::endl;

    // Verify signature
    std::string recovered;
    CryptoPP::StringSource(signature + message, true,
        new CryptoPP::SignatureVerificationFilter(verifier,
            new CryptoPP::StringSink(recovered)
        )
    );

    if (recovered == message) {
        std::cout << "Signature verified: Message is authentic" << std::endl;
    }

    return 0;
}
```

---

### Key Exchange

**Use when:** Establishing secure channels, TLS-like protocols

#### X25519 (Recommended)

```cpp
#include <cryptopp/xed25519.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <iostream>

int main() {
    CryptoPP::AutoSeededRandomPool rng;

    // Alice generates her key pair
    CryptoPP::x25519 alice;
    CryptoPP::SecByteBlock privA(CryptoPP::x25519::SECRET_KEYLENGTH);
    CryptoPP::SecByteBlock pubA(CryptoPP::x25519::PUBLIC_KEYLENGTH);
    alice.GeneratePrivateKey(rng, privA);
    alice.GeneratePublicKey(rng, privA, pubA);

    // Bob generates his key pair
    CryptoPP::x25519 bob;
    CryptoPP::SecByteBlock privB(CryptoPP::x25519::SECRET_KEYLENGTH);
    CryptoPP::SecByteBlock pubB(CryptoPP::x25519::PUBLIC_KEYLENGTH);
    bob.GeneratePrivateKey(rng, privB);
    bob.GeneratePublicKey(rng, privB, pubB);

    // Both compute shared secret
    CryptoPP::SecByteBlock sharedA(CryptoPP::x25519::SHARED_KEYLENGTH);
    CryptoPP::SecByteBlock sharedB(CryptoPP::x25519::SHARED_KEYLENGTH);

    alice.Agree(sharedA, privA, pubB);  // Alice uses Bob's public key
    bob.Agree(sharedB, privB, pubA);    // Bob uses Alice's public key

    if (sharedA == sharedB) {
        std::cout << "Key exchange successful" << std::endl;
        std::cout << "Both parties have the same shared secret" << std::endl;
        // Use sharedA/sharedB as encryption key
    }

    return 0;
}
```

---

## Building Your Application

### CMake Project (Recommended)

Create a `CMakeLists.txt` for your project:

```cmake
cmake_minimum_required(VERSION 3.20)
project(myapp)

find_package(cryptopp-modern REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE cryptopp::cryptopp)
```

Build your project:

```bash
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/cryptopp-install
cmake --build build
```

### Basic Compilation (Manual)

```bash
g++ -std=c++14 myapp.cpp -o myapp -lcryptopp
```

### With Static Linking

```bash
g++ -std=c++14 myapp.cpp -o myapp -lcryptopp -static
```

### Makefile Example

```makefile
CXX = g++
CXXFLAGS = -std=c++14 -Wall -O2
LDFLAGS = -lcryptopp

myapp: main.cpp
	$(CXX) $(CXXFLAGS) -o myapp main.cpp $(LDFLAGS)

clean:
	rm -f myapp
```

### Multi-file Project

```bash
# Compile
g++ -std=c++14 -c crypto_utils.cpp -o crypto_utils.o
g++ -std=c++14 -c main.cpp -o main.o

# Link
g++ crypto_utils.o main.o -o myapp -lcryptopp
```

---

## Next Steps

### Essential Reading

**📚 Security Fundamentals:** Read the [Security Concepts Guide](https://cryptopp-modern.com/docs/guides/security-concepts) to understand:
- **Constant-time operations** - Preventing timing attacks
- **Nonce management** - Why GCM nonce reuse is catastrophic
- **Key separation** - Using different keys for different purposes
- **Authenticate-then-decrypt** - Proper verification order
- **Secure random numbers** - Why `rand()` is dangerous
- **Key storage** - Safely storing cryptographic keys

**Common Pitfalls to Avoid:**
- ❌ Don't reuse nonces/IVs with the same key (especially GCM!)
- ❌ Don't use the same key for encryption and authentication
- ❌ Don't decrypt before verifying authentication tags
- ❌ Don't use `rand()`, `srand()`, or other weak RNGs
- ❌ Don't hard-code keys in source code or commit them to git
- ❌ Don't ignore exceptions from decryption/verification

### Full Documentation

Visit **https://cryptopp-modern.com** for comprehensive guides:

- **[Beginner's Guide](https://cryptopp-modern.com/docs/guides/beginners-guide)** - Detailed examples with wrapper classes
- **[Algorithm Reference](https://cryptopp-modern.com/docs/algorithms/reference)** - Complete list of all supported algorithms
- **[BLAKE3 Documentation](https://cryptopp-modern.com/docs/algorithms/blake3)** - Modern hash function
- **[Argon2 Guide](https://cryptopp-modern.com/docs/algorithms/argon2)** - Password hashing best practices
- **[Symmetric Encryption](https://cryptopp-modern.com/docs/algorithms/symmetric)** - AES, ChaCha20, modes of operation
- **[Public-Key Cryptography](https://cryptopp-modern.com/docs/algorithms/public-key)** - Ed25519, X25519, RSA, ECDSA
- **[Hash Functions](https://cryptopp-modern.com/docs/algorithms/hashing)** - SHA-2, SHA-3, BLAKE2
- **[Migration Guide](https://cryptopp-modern.com/docs/migration/from-cryptopp)** - Moving from Crypto++ 8.9.0

### Algorithm Support

cryptopp-modern includes:

- **Hash Functions:** SHA-2, SHA-3, BLAKE2, BLAKE3, MD5, RIPEMD, Tiger, Whirlpool, SipHash
- **Symmetric Encryption:** AES, ChaCha20, Serpent, Twofish, Camellia, ARIA
- **Modes:** GCM, CCM, EAX, CBC, CTR, CFB, OFB
- **Public Key:** RSA, DSA, ECDSA, Ed25519, Diffie-Hellman, ECIES, ElGamal
- **Key Derivation:** Argon2, PBKDF2, HKDF, Scrypt
- **MACs:** HMAC, CMAC, GMAC, Poly1305

### Getting Help

- **Documentation:** https://cryptopp-modern.com
- **Issues:** https://github.com/cryptopp-modern/cryptopp-modern/issues
- **Discussions:** https://github.com/cryptopp-modern/cryptopp-modern/discussions

### Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**cryptopp-modern** - Modern cryptography for modern applications.

Licensed under the Boost Software License 1.0.
