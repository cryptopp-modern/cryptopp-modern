# GNUmakefile Build System

This document describes the GNUmakefile build system for cryptopp-modern.

## Requirements

- **GNU Make** (3.81 or higher recommended)
- **GCC** or **Clang** compiler with C++11 support (C++14 or higher recommended)
- Standard POSIX tools (ar, ranlib, grep, sed)

## Quick Start

### Linux

```bash
# Build everything (static library, shared library, and tests)
make -j$(nproc)

# Run validation tests
./cryptest.exe v

# Run all test vectors
./cryptest.exe tv all

# Install (default: /usr/local)
sudo make install
```

### macOS

```bash
# Build
make -j$(sysctl -n hw.ncpu)

# Run tests
./cryptest.exe v

# Install
sudo make install PREFIX=/usr/local
```

### Windows (MinGW)

```bash
# Build with static linking (no DLL dependencies)
mingw32-make.exe -j10 static-exe

# Or build with explicit flags
mingw32-make.exe -j10 LDFLAGS="-static -static-libgcc -static-libstdc++"

# Run tests
./cryptest.exe v
```

## Make Targets

### Primary Targets

| Target | Description |
|--------|-------------|
| `default` | Build `cryptest.exe` (test program) |
| `all` | Build static library, shared library, and `cryptest.exe` |
| `static` | Build static library (`libcryptopp.a`) |
| `dynamic` | Build shared library (`libcryptopp.so` / `libcryptopp.dylib`) |
| `cryptest.exe` | Build the test executable |
| `static-exe` | Build `cryptest.exe` with static linking (no DLL dependencies, MinGW) |
| `lean` | Build static, dynamic, and cryptest.exe |

### Installation Targets

| Target | Description |
|--------|-------------|
| `install` | Install library, headers, and test program |
| `install-lib` | Install only the library and headers |

### Testing Targets

| Target | Description |
|--------|-------------|
| `native` | Build with native CPU optimizations (`-march=native`) |
| `no-asm` | Build without assembly optimizations (pure C++) |
| `asan` | Build with Address Sanitizer |
| `ubsan` | Build with Undefined Behavior Sanitizer |
| `valgrind` | Build for Valgrind testing |
| `lcov` / `coverage` | Build with code coverage instrumentation |
| `gcov` / `codecov` | Build for gcov/codecov coverage |

### Cleanup Targets

| Target | Description |
|--------|-------------|
| `clean` | Remove object files and executables |
| `distclean` | Remove all generated files |

## Environment Variables

### Compiler Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CXX` | `g++` | C++ compiler |
| `CC` | `gcc` | C compiler (for assembly files on ARM) |
| `CXXFLAGS` | `-g2 -O3` | Compiler flags |
| `CPPFLAGS` | `-DNDEBUG` | Preprocessor flags |
| `LDFLAGS` | | Linker flags |
| `ARFLAGS` | `-cr` | Archive flags |

### Installation Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `PREFIX` | `/usr/local` | Installation prefix |
| `LIBDIR` | `$(PREFIX)/lib` | Library installation directory |
| `INCLUDEDIR` | `$(PREFIX)/include` | Header installation directory |
| `BINDIR` | `$(PREFIX)/bin` | Binary installation directory |
| `DATADIR` | `$(PREFIX)/share` | Data installation directory |

## Build Examples

### Basic Build

```bash
# Default build (Release, with debug symbols)
make

# Parallel build
make -j$(nproc)
```

### Debug Build

```bash
make CXXFLAGS="-g3 -O0 -DDEBUG"
```

### Release Build (No Debug Symbols)

```bash
make CXXFLAGS="-O3 -DNDEBUG"
```

### Specify C++ Standard

```bash
# C++14
make CXXFLAGS="-std=c++14 -g2 -O3 -DNDEBUG"

# C++17
make CXXFLAGS="-std=c++17 -g2 -O3 -DNDEBUG"

# C++20
make CXXFLAGS="-std=c++20 -g2 -O3 -DNDEBUG"
```

### Use Clang Instead of GCC

```bash
make CXX=clang++
```

### Static Linking (MinGW)

```bash
make LDFLAGS="-static -static-libgcc -static-libstdc++"
```

### Native CPU Optimizations

```bash
# Automatically detect and use all CPU features
make native
```

### Disable Assembly Optimizations

```bash
# Pure C++ build (no SIMD)
make no-asm
```

Or with explicit flag:
```bash
make CXXFLAGS="-DCRYPTOPP_DISABLE_ASM -g2 -O3"
```

## Sanitizer Builds

### Address Sanitizer (ASan)

Detects memory errors like buffer overflows, use-after-free, etc.

```bash
make asan
./cryptest.exe v
```

### Undefined Behavior Sanitizer (UBSan)

Detects undefined behavior like integer overflow, null pointer dereference, etc.

```bash
make ubsan
./cryptest.exe v
```

## Code Coverage

### Using lcov

```bash
make coverage
# This runs tests and generates coverage report
```

### Using gcov

```bash
make gcov
```

## Running Tests

### Validation Tests

```bash
./cryptest.exe v
```

### Test Vectors

```bash
# All test vectors
./cryptest.exe tv all

# Specific algorithm
./cryptest.exe tv aes
./cryptest.exe tv sha
./cryptest.exe tv blake2
```

### Benchmarks

```bash
# Full benchmark
./cryptest.exe b

# Quick benchmark (0.25 seconds per algorithm)
./cryptest.exe b 0.25

# Benchmark specific algorithm
./cryptest.exe b2 aes
```

### Other Test Options

```bash
# Help
./cryptest.exe h

# Version info
./cryptest.exe V

# Test specific algorithm
./cryptest.exe tv sha256
```

## Installation

### Default Installation

```bash
sudo make install
```

This installs to:
- `/usr/local/lib/libcryptopp.a`
- `/usr/local/lib/libcryptopp.so` (or `.dylib` on macOS)
- `/usr/local/include/cryptopp/*.h`
- `/usr/local/bin/cryptest.exe`
- `/usr/local/share/cryptopp/TestData/`
- `/usr/local/share/cryptopp/TestVectors/`

### Custom Installation Prefix

```bash
sudo make install PREFIX=/opt/cryptopp
```

### Install Library Only (No Test Program)

```bash
sudo make install-lib
```

## SIMD Auto-Detection

The GNUmakefile automatically detects and enables CPU features:

### x86/x64
- SSE2, SSE3, SSSE3, SSE4.1, SSE4.2
- AVX, AVX2
- AES-NI
- PCLMUL (CLMUL)
- SHA-NI

**BLAKE3 Parallel Hashing**: BLAKE3 uses SSE4.1 (4-way) and AVX2 (8-way) parallel chunk processing for high performance (~2500 MiB/s with AVX2).

### ARM
- NEON
- AES instructions
- PMULL
- SHA1/SHA2 instructions

### PowerPC
- Altivec
- POWER7/8/9 features

To check detected features:
```bash
make
./cryptest.exe v
# Look for "hasSSE2", "hasAESNI", etc. in output
```

## Disabling Specific Features

You can disable specific SIMD features via CXXFLAGS:

```bash
# Disable AES-NI
make CXXFLAGS="-DCRYPTOPP_DISABLE_AESNI -g2 -O3"

# Disable SHA-NI
make CXXFLAGS="-DCRYPTOPP_DISABLE_SHANI -g2 -O3"

# Disable all assembly
make CXXFLAGS="-DCRYPTOPP_DISABLE_ASM -g2 -O3"
```

Available disable flags:
- `CRYPTOPP_DISABLE_ASM` - All assembly
- `CRYPTOPP_DISABLE_SSE2` - SSE2
- `CRYPTOPP_DISABLE_SSSE3` - SSSE3
- `CRYPTOPP_DISABLE_SSE4` - SSE4.1/4.2
- `CRYPTOPP_DISABLE_AESNI` - AES-NI
- `CRYPTOPP_DISABLE_CLMUL` - CLMUL/PCLMUL
- `CRYPTOPP_DISABLE_SHANI` - SHA-NI
- `CRYPTOPP_DISABLE_AVX` - AVX
- `CRYPTOPP_DISABLE_AVX2` - AVX2

## Troubleshooting

### Build Fails with Missing Dependencies

Ensure you have development tools installed:

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"

# macOS
xcode-select --install
```

### Test Vectors Not Found

Tests must be run from the source directory where `TestData/` and `TestVectors/` exist:

```bash
cd /path/to/cryptopp-modern
./cryptest.exe v
```

### Undefined Reference Errors

Ensure you're linking against the library:

```bash
g++ myapp.cpp -o myapp -lcryptopp
```

Or with explicit path:
```bash
g++ myapp.cpp -o myapp -L/path/to/cryptopp -lcryptopp
```

### Slow Build

Use parallel compilation:

```bash
make -j$(nproc)
```

### MinGW DLL Dependencies

Build with static linking to avoid runtime DLL dependencies:

```bash
make LDFLAGS="-static -static-libgcc -static-libstdc++"
```

## Using the Library in Your Project

### Compile and Link

```bash
g++ -std=c++14 myapp.cpp -o myapp -lcryptopp
```

### With Custom Installation Path

```bash
g++ -std=c++14 -I/opt/cryptopp/include myapp.cpp -o myapp -L/opt/cryptopp/lib -lcryptopp
```

### Static Linking

```bash
g++ -std=c++14 myapp.cpp -o myapp /usr/local/lib/libcryptopp.a
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

## Comparison with CMake

| Feature | GNUmakefile | CMake |
|---------|-------------|-------|
| Cross-platform | Yes (with caveats) | Yes |
| IDE integration | Limited | Excellent |
| `find_package()` support | No | Yes |
| Presets | No | Yes |
| SIMD auto-detection | Yes | Yes |
| Parallel builds | Yes | Yes |
| Installation | Yes | Yes |
| Minimal dependencies | Yes | Requires CMake |

Choose GNUmakefile for:
- Simple command-line builds
- Minimal build system dependencies
- Compatibility with traditional Unix workflows
- Quick testing and development

Choose CMake for:
- IDE integration (VS Code, CLion, Visual Studio)
- Using cryptopp-modern as a CMake dependency
- Windows MSVC builds
- Cross-platform project generation

## License

The GNUmakefile is distributed under the same license as cryptopp-modern (Boost Software License 1.0).
