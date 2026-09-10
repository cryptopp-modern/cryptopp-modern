# 2026.9.1 Release Notes

2026.9.1 is a patch release. It restores ARM CRC32 and PMULL acceleration lost since 2025.12.0, enables the hardware paths on Apple arm64, fixes HSS signing recovery and LMS/HSS key-generation failure handling, and lets CMake build the shared and static libraries in one pass, with packaging and feature-detection fixes.

* Restore ARM CRC32 and PMULL acceleration in default CMake and GNUmakefile builds. Since 2025.12.0, their feature probes could not find `arm_simd.h`, leaving CRC32 and GCM multiplication on the software paths (#91).
* Enable hardware AES, PMULL, SHA-1 and SHA-256 on Apple arm64 devices, and detect the optional CRC32, SHA-3 and SHA-512 extensions through `sysctl` (#92; weidai11/cryptopp#1373).
* Rebuild the HSS signer's caches from the root after a failed signing attempt. A retry on the same signer could otherwise produce an invalid signature and a burned index (#99).
* Leave LMS and HSS private keys unchanged when key generation fails partway (#99).
* Fix GCC -Warray-bounds warnings in HSSSigner for the single-level parameter sets (#97, #98).
* Add `CRYPTOPP_BUILD_STATIC` so the shared and static libraries can be built and installed in one CMake configure pass (#86).
* Honour `BUILD_SHARED_LIBS` when selecting the CMake library type. An explicit `CRYPTOPP_BUILD_SHARED` still takes precedence (#90).
* Export the configured include directory from the CMake package config, so find_package works when headers are installed outside the library prefix (#94).
* Write the debug postfix into the pkg-config file for single-configuration Debug builds that set one (#95).
* Generate the pkg-config file per build configuration and fix ctest under multi-config generators (#96).
* Compile the CMake feature probes with warnings silenced, so a `-Werror` in the incoming compiler flags no longer disables SSE4.1 and AVX-512 detection, and add the `CRYPTOPP_WERROR` option (#100).
* Define `CRYPTOPP_DISABLE_AVX512` when the AVX-512 probe fails, so the build falls back instead of failing in the intrinsics headers (#101).
* Run the CMake target-architecture probe once per configure instead of nine times (#87, #88).

**Upgrade note:** No API changes. ARM builds regain hardware CRC32 and GCM multiplication; Apple arm64 builds also gain hardware AES, SHA-1 and SHA-256. The CMake library type now follows `BUILD_SHARED_LIBS`: a configure that sets it to ON selects a shared library unless `CRYPTOPP_BUILD_SHARED` is set explicitly, where earlier releases ignored it and built static. On Windows, shared builds remain unsupported; set `CRYPTOPP_BUILD_SHARED=OFF` if your configuration supplies `BUILD_SHARED_LIBS=ON`. Without either variable the default is still a static library, and `CRYPTOPP_BUILD_STATIC` only matters alongside `CRYPTOPP_BUILD_SHARED`. `CRYPTOPP_WERROR` is off by default.

There is no ABI series change. The shared-library SONAME remains `libcryptopp.so.9`.
