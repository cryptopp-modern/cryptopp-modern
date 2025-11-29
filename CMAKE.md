# CMake Build System

This document describes the CMake build system for cryptopp-modern.

## Requirements

- **CMake 3.20** or higher
- **C++11** compatible compiler (C++14 or higher recommended)
- **Ninja** (recommended) or Make for Linux/macOS
- **Visual Studio 2022** for Windows MSVC builds

## Quick Start

### Linux / macOS

```bash
# Configure with default preset (Release, Ninja)
cmake --preset=default

# Build
cmake --build build/default -j$(nproc)

# Run tests
./build/default/cryptest.exe v

# Install (optional)
sudo cmake --install build/default --prefix /usr/local
```

### Windows (MSVC)

```powershell
# Configure with MSVC preset
cmake --preset=msvc

# Build Release configuration
cmake --build build/msvc --config Release

# Run tests
./build/msvc/Release/cryptest.exe v
```

### Windows (MinGW)

```bash
# Configure with default preset
cmake --preset=default

# Build
cmake --build build/default -j10

# Run tests
./build/default/cryptest.exe v
```

## CMake Presets

The project includes `CMakePresets.json` with pre-configured build configurations:

| Preset | Generator | Build Type | Description |
|--------|-----------|------------|-------------|
| `default` | Ninja | Release | Default build for Linux/macOS/MinGW |
| `debug` | Ninja | Debug | Debug build with symbols |
| `release` | Ninja | Release | Optimized release build |
| `relwithdebinfo` | Ninja | RelWithDebInfo | Release with debug info |
| `msvc` | Visual Studio 17 2022 | - | Windows MSVC build |
| `msvc-debug` | Visual Studio 17 2022 | Debug | MSVC debug build |
| `msvc-release` | Visual Studio 17 2022 | Release | MSVC release build |
| `no-asm` | Ninja | Release | Pure C++ (no assembly) |
| `install-test` | Ninja | Release | For testing installation |
| `ci-linux` | Ninja | Release | CI configuration for Linux |
| `ci-macos` | Ninja | Release | CI configuration for macOS |
| `ci-windows` | Visual Studio 17 2022 | Release | CI configuration for Windows |

### Using Presets

```bash
# List available presets
cmake --list-presets

# Configure with a specific preset
cmake --preset=debug

# Build with a specific preset
cmake --build --preset=debug
```

## CMake Options

### General Options

| Option | Default | Description |
|--------|---------|-------------|
| `CRYPTOPP_BUILD_TESTING` | `ON` | Build the test executable (cryptest.exe) |
| `CRYPTOPP_INSTALL` | `ON` | Generate install targets |
| `CRYPTOPP_BUILD_SHARED` | `OFF` | Build shared library (NOT supported - Crypto++ doesn't properly support DLLs) |
| `CRYPTOPP_USE_OPENMP` | `OFF` | Enable OpenMP for parallel algorithms |
| `CRYPTOPP_INCLUDE_PREFIX` | `cryptopp` | Header installation directory name |

### x86/x64 SIMD Options

| Option | Default | Description |
|--------|---------|-------------|
| `CRYPTOPP_DISABLE_ASM` | `OFF` | Disable all assembly optimizations |
| `CRYPTOPP_DISABLE_SSSE3` | `OFF` | Disable SSSE3 instructions |
| `CRYPTOPP_DISABLE_SSE4` | `OFF` | Disable SSE4.1/SSE4.2 instructions |
| `CRYPTOPP_DISABLE_AESNI` | `OFF` | Disable AES-NI instructions |
| `CRYPTOPP_DISABLE_CLMUL` | `OFF` | Disable CLMUL (carryless multiply) |
| `CRYPTOPP_DISABLE_SHA` | `OFF` | Disable SHA-NI instructions |
| `CRYPTOPP_DISABLE_AVX` | `OFF` | Disable AVX instructions |
| `CRYPTOPP_DISABLE_AVX2` | `OFF` | Disable AVX2 instructions |

### ARM Options

| Option | Default | Description |
|--------|---------|-------------|
| `CRYPTOPP_DISABLE_ARM_NEON` | `OFF` | Disable ARM NEON |
| `CRYPTOPP_DISABLE_ARM_AES` | `OFF` | Disable ARM AES instructions |
| `CRYPTOPP_DISABLE_ARM_PMULL` | `OFF` | Disable ARM PMULL |
| `CRYPTOPP_DISABLE_ARM_SHA` | `OFF` | Disable ARM SHA instructions |

### PowerPC Options

| Option | Default | Description |
|--------|---------|-------------|
| `CRYPTOPP_DISABLE_ALTIVEC` | `OFF` | Disable Altivec |
| `CRYPTOPP_DISABLE_POWER7` | `OFF` | Disable POWER7 optimizations |
| `CRYPTOPP_DISABLE_POWER8` | `OFF` | Disable POWER8 optimizations |
| `CRYPTOPP_DISABLE_POWER9` | `OFF` | Disable POWER9 optimizations |

### Example: Custom Build

```bash
# Build without assembly (pure C++)
cmake -B build -DCRYPTOPP_DISABLE_ASM=ON

# Build without tests
cmake -B build -DCRYPTOPP_BUILD_TESTING=OFF

# Build with OpenMP
cmake -B build -DCRYPTOPP_USE_OPENMP=ON
```

## Using cryptopp-modern in Your CMake Project

After installing cryptopp-modern, you can use it in your CMake project:

```cmake
cmake_minimum_required(VERSION 3.20)
project(myapp)

# Find cryptopp-modern
find_package(cryptopp-modern REQUIRED)

# Create your executable
add_executable(myapp main.cpp)

# Link against cryptopp
target_link_libraries(myapp PRIVATE cryptopp::cryptopp)
```

### Build Your Project

```bash
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/cryptopp-install
cmake --build build
```

### Component Selection

You can explicitly request static or shared components (though only static is currently supported):

```cmake
find_package(cryptopp-modern REQUIRED COMPONENTS static)
```

## Installation

### Default Installation

```bash
cmake --preset=default
cmake --build build/default
sudo cmake --install build/default
```

### Custom Installation Prefix

```bash
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/cryptopp
cmake --build build
cmake --install build
```

### What Gets Installed

| Directory | Contents |
|-----------|----------|
| `include/cryptopp/` | All header files |
| `lib/` | Static library (`libcryptopp.a` or `cryptopp.lib`) |
| `lib/pkgconfig/` | pkg-config file (`cryptopp.pc`) |
| `share/cmake/cryptopp-modern/` | CMake config files for `find_package()` |
| `share/cryptopp/` | TestData and TestVectors |
| `bin/` | Test executable (`cryptest.exe`) |

## SIMD Auto-Detection

The build system automatically detects CPU capabilities and enables appropriate SIMD optimizations:

### x86/x64
- SSE2, SSSE3, SSE4.1, SSE4.2
- AVX, AVX2
- AES-NI (hardware AES acceleration)
- CLMUL (carryless multiplication for GCM)
- SHA-NI (hardware SHA acceleration)

**BLAKE3 Parallel Hashing**: BLAKE3 uses SSE4.1 (4-way) and AVX2 (8-way) parallel chunk processing for high performance (~2500 MiB/s with AVX2).

### ARM
- NEON
- AES instructions
- PMULL
- SHA instructions

### PowerPC
- Altivec
- POWER7/8/9 optimizations

The appropriate compiler flags are automatically applied to specific source files that use these instructions.

## Running Tests

### Using CTest

```bash
# Configure and build
cmake --preset=default
cmake --build build/default

# Run CTest
ctest --preset=default
```

### Running cryptest Directly

```bash
# Validation tests
./build/default/cryptest.exe v

# Test vectors
./build/default/cryptest.exe tv all

# Benchmarks
./build/default/cryptest.exe b

# Specific algorithm test
./build/default/cryptest.exe tv aes
```

## Troubleshooting

### Ninja Not Found

Install Ninja:
- **Linux**: `sudo apt-get install ninja-build`
- **macOS**: `brew install ninja`
- **Windows**: `choco install ninja` or download from [ninja-build.org](https://ninja-build.org/)

Or use a different generator:
```bash
cmake -B build -G "Unix Makefiles"
```

### MSVC Not Found

Ensure Visual Studio 2022 is installed with the "Desktop development with C++" workload.

### Tests Fail to Find TestVectors

The CMake build automatically copies `TestData/` and `TestVectors/` to the build directory. If running from a different directory, set the working directory to the build directory.

### Static Linking on MinGW

The CMake build automatically adds static linking flags for MinGW to avoid runtime DLL dependencies:
```
-static -static-libgcc -static-libstdc++
```

## File Structure

```
cryptopp-modern/
├── CMakeLists.txt           # Main CMake build file
├── CMakePresets.json        # Build presets
├── cmake/
│   ├── cmake_minimum_required.cmake
│   ├── ConfigFiles.cmake    # Package config generation
│   ├── config.pc.in         # pkg-config template
│   ├── cryptopp-modernConfig.cmake  # find_package() config
│   ├── GetGitRevisionDescription.cmake
│   ├── GetGitRevisionDescription.cmake.in
│   ├── sources.cmake        # Source file lists
│   └── TargetArch.cmake     # Architecture detection
├── include/cryptopp/        # Header files
├── src/                     # Source files (organized by category)
├── TestData/                # Test data files
└── TestVectors/             # Test vector files
```

## Comparison with GNUmakefile

Both build systems are maintained and produce compatible results:

| Feature | CMake | GNUmakefile |
|---------|-------|-------------|
| Cross-platform | Yes | Yes (with caveats) |
| IDE integration | Excellent | Limited |
| `find_package()` support | Yes | No |
| Presets | Yes | No |
| SIMD auto-detection | Yes | Yes |
| Parallel builds | Yes | Yes |
| Installation | Yes | Yes |

Choose CMake for:
- IDE integration (VS Code, CLion, Visual Studio)
- Using cryptopp-modern as a dependency in CMake projects
- Cross-platform development

Choose GNUmakefile for:
- Simple command-line builds
- Compatibility with existing Crypto++ workflows
- Minimal dependencies

## License

The CMake build system is distributed under the same license as cryptopp-modern (Boost Software License 1.0).
