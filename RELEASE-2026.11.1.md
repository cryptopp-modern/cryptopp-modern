# 2026.11.1 Release Notes

2026.11.1 fixes BLAKE2 argument validation, SLH-DSA stack-secret wiping, and several build and packaging issues.

* **BLAKE2** - Keyed constructors now validate key length at runtime, and all constructors and `SetKey` validate digest size. Previously, oversized keys could overflow the key buffer and oversized digests could read past the hash state. Salt, personalization and tree mode are now validated before changing state. Null pointers with nonzero lengths are rejected. Invalid arguments throw `InvalidKeyLength` or `InvalidArgument`. See GHSA-796q-fcgc-jpr9.
* **SLH-DSA** - Stack secrets are now wiped on exceptions as well as normal exits. This also covers the `thash_f` buffers and full `prf_msg` HMAC output (#133).
* **Link-time optimisation** - LTO is tested in CI on x86-64 with GCC through GNUmakefile and CMake, and Clang through GNUmakefile. The GNUmakefile feature probes no longer disable SIMD under `-flto` (#136). Export `CXXFLAGS` rather than passing it on the `make` command line, which overrides flags such as `-fPIC`. Closes #134.
* **Packagers** - GNUmakefile no longer installs the test-only headers `validate.h` and `bench.h`. CMake now installs `factory.h` and `xaes_256_gcm.h`. Explicit install file lists need updating (#139).
* **GNUmakefile** - Per-file rules now retain SIMD flags, `CRYPTOPP_DATA_DIR` and the Cryptogams AES rule on rebuilds (#137). Command-line `CXXFLAGS` retains `-fno-devirtualize` (#141). Flag filtering and NEON-disabled assembly handling are corrected (#142). `DataDir()` is defined once (#135).
* **CMake 32-bit ARM** - Corrected NEON probe arguments restore detection for Clang and soft-float builds. Cryptogams assembly requires a successful NEON probe, and Clang ASM builds receive `-mthumb`. Use a fresh build directory to clear cached probe results (#142).
* **ARM assembly** - Cryptogams sources no longer request an executable stack. The `--noexecstack` check no longer matches `-Wall`, CMake no longer forces `-march=armv7-a`, and GNUmakefile recognises ARMv8. New armhf and armel CI jobs build with both systems and test under QEMU (#138, #142).

**Compatibility:** No public API or ABI changes. The shared-library SONAME remains `libcryptopp.so.9`. Invalid BLAKE2 arguments may now throw where release builds previously accepted them. GNUmakefile no longer installs `validate.h` and `bench.h`.
