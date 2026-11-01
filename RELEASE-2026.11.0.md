# 2026.11.0 Release Notes

2026.11.0 is a minor release that fixes EAX and AES-CTR-HMAC resynchronisation, a BLAKE3 crash on CPUs without AVX, and 32-bit x86 builds under GCC link-time optimisation, and adds ML-DSA known-answer tests.

* **EAX and AES-CTR-HMAC** - Repeated EAX resynchronisation carried stale CMAC state into the nonce tag, producing incorrect output or rejecting valid ciphertext, and an abandoned header let nonces of different lengths share a keystream. The CMAC is now restarted before the nonce tag. AES-CTR-HMAC one-shot calls threw `BadState` when an object was reused. Ciphertext produced through the faulty EAX one-shot path will not verify through the corrected path (#119). Debug builds no longer assert on empty AEAD messages (#124).
* **CMAC** - CMAC Restart no longer runs a block encryption, which makes EAX resynchronisation cheaper (#128).
* **BLAKE3** - The SSE4.1 path was compiled with AVX2 enabled, so CPUs without AVX could fault with SIGILL. The AVX2 code is now its own translation unit and a QEMU Nehalem CI job runs the suite without AVX (#122). The nmake x64 build links again; `blake3_avx512.cpp` had been missing from `cryptest.nmake` since 2025.12.0 (#129).
* **Argon2** - Argon2 now rejects invalid variants and input lengths exceeding the RFC 9106 limits, and wipes its temporary blocks (#126).
* **ML-DSA** - ML-DSA key generation, signing and verification are now checked against NIST ACVP vectors in the validation suite (#127).
* **32-bit x86 LTO** - 32-bit x86 builds with GCC link-time optimisation link again. `integer.cpp` referenced SSE2 assembler labels across functions, which LTO partitioning broke; distributions that disabled LTO on i686 as a workaround can drop it (#131).
* **Visual Studio** - The `msvc-debug` and `msvc-release` configure presets are now build and test presets. Configure once with `msvc` and choose the configuration at build time (#130). The project files keep compiler options inherited from property sheets, such as the Conan 2 MSBuild toolchain, while still accepting `/p:AdditionalOptions` (#117).
* **Build and test fixes** - `SafeConvert` uses a round-trip comparison for integral types, fixing a Clang mixed-sign warning on macOS (#120). CMake instruction-set checks now report compiler support and the tested flags, so the output is not mistaken for CPU detection (#123). Three test drivers in `datatest.cpp` recreated the object for every vector instead of reusing it for the same algorithm (#125).

**EAX upgrade note:** Ciphertext produced through the faulty EAX one-shot path will not verify through the corrected path.

**Compatibility:** No public API or ABI changes. Argon2 now throws `InvalidArgument` for unknown variants and for password, salt, secret or associated data longer than 2^32-1 bytes. The `msvc-debug` and `msvc-release` configure preset names are removed. The shared-library SONAME remains `libcryptopp.so.9`.
