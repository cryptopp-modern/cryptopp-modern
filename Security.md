# Security Policy

## Supported Versions

Currently supported:
- 2026.7.0 (current release)

Older releases are not actively supported. Users on earlier versions should upgrade to receive security fixes. We incorporate critical security fixes from upstream Crypto++ and monitor for security issues in the cryptographic algorithms we implement.

## Reporting a Vulnerability

You can report a security related bug in the [cryptopp-modern GitHub Issues](https://github.com/cryptopp-modern/cryptopp-modern/issues) or [GitHub Discussions](https://github.com/cryptopp-modern/cryptopp-modern/discussions).

For sensitive security issues, you may also contact the maintainer directly through GitHub.

If we receive a report of a security related bug then we will:
1. Open a GitHub issue (unless the issue requires private disclosure initially)
2. Investigate and develop a fix
3. Release a patched version as soon as possible
4. Credit the reporter (unless they prefer to remain anonymous)

All information will be made public after a fix is available. We do not withhold information from users because stakeholders need accurate information to assess risk and place controls to remediate the risk.

## Security Advisories

### ASN.1 DERReencode unbounded recursion (fixed in 2026.5.2)

`DERReencode` walked nested constructed indefinite BER without a depth limit. A crafted chain of `0x30 0x80` sequences could exhaust the thread stack. `PKCS8PrivateKey` import reaches this path through `BERDecodeOptionalAttributes`, so any caller that imports untrusted PKCS#8 material was exposed.

**Severity:** Availability. Reporter rated this CVSS 7.5. No confidentiality or integrity impact.

**Affected versions:** all releases up to and including 2026.5.1.

**Fix:** Capped the recursion depth at 32 levels, matching OpenSSL's `ASN1_MAX_CONSTRUCTED_NEST`. Deeper inputs now throw `BERDecodeError` instead of recursing further.

**Upstream:** addresses upstream Crypto++ issue 1353. Upstream PR weidai11/cryptopp#1354 ports the same fix to Crypto++ master.

### Ed25519 non-canonical signature scalars (fixed in 2026.5.2)

The Ed25519 verifiers accepted signatures where the scalar `S` was not canonically encoded. The previous check only masked the top three bits of `S`, leaving the gap `L <= S < 2^253`. A valid signature changed from `S'` to `S' + L` could still verify because the verification equation holds modulo the subgroup order.

Both the Donna verifier and the NaCl C API verifier (`crypto_sign_open` in `tweetnacl.cpp`) had this defect.

**Severity:** Low. Conformance, not forgery. Matters for systems that key behaviour on raw signature bytes, such as replay caches, audit trails, deduplication, allowlists, and interoperability with stricter Ed25519 implementations.

**Affected versions:** all releases up to and including 2026.5.1.

**Fix:** Both verifiers now reject `S >= L` before continuing with verification.

**Upstream:** addresses the signature-scalar part of upstream Crypto++ issue 1352. Upstream PR weidai11/cryptopp#1355 ports the same fix to Crypto++ master.

### Ed25519 small-order public keys (fixed in 2026.5.2)

`ed25519PublicKey::Validate` did not reject small-order Ed25519 public keys. Some downstream consumers rely on `Validate` at level 2 or higher to filter weak keys.

**Severity:** Low. Conformance. Validation-level behaviour only; the verifier itself was not changed.

**Affected versions:** all releases up to and including 2026.5.1.

**Fix:** `Validate` now rejects small-order public keys at level 2 or higher. The existing canonical encoding check still runs at all validation levels. Level 0 behaviour is unchanged.

**Upstream:** addresses the small-order public key part of upstream Crypto++ issue 1352. Upstream commit weidai11/cryptopp@4775a166 covers the same case on upstream master.

### BLAKE3 incorrect hashes on AArch64 (fixed in 2026.5.1)

`BLAKE3_Compress_NEON` was a fork-local single-block compress that diverged from the BLAKE3 reference and produced incorrect digests against the official BLAKE3 test vectors on AArch64 hosts (Apple Silicon macOS, ARM64 Linux, Android arm64-v8a). The bug shipped in 2026.1.0; CI did not catch it because `ValidateBLAKE3()` was not called from `ValidateAll()`.

**Severity:** Correctness. BLAKE3 output on AArch64 differed from every other implementation. Anyone using BLAKE3 for content addressing, pinning, allowlists, deduplication, or audit trails on AArch64 should recompute and replace stored hashes.

**Affected versions:** 2026.1.0 through 2026.5.0 on AArch64. x86 and other architectures were not affected.

**Fix:** Removed the fork-local NEON single-block compress; AArch64 builds now use the portable `compress_internal`, matching the BLAKE3 reference architecture. `ValidateBLAKE3()` is now wired into `ValidateAll()` so CI catches regressions.

**References:**
- [Pull Request #30](https://github.com/cryptopp-modern/cryptopp-modern/pull/30)
- [GitHub Issue #27](https://github.com/cryptopp-modern/cryptopp-modern/issues/27)

---

### CVE-2023-50980 and CVE-2023-50981 hardening (defence-in-depth, fixed in 2026.5.0)

`BERDecodeGF2NP` accepted malformed F(2^m) parameters that could reach `PolynomialMod2` with relaxed runtime checks, and `InvertibleRabinFunction::BERDecode` checked primality with `CRYPTOPP_ASSERT` only (compiled out in release). Published PoCs for both CVEs were already blocked from 2025.11.0 onward via upstream patches; the 2026.5.0 release tightens the same paths at the DER boundary.

**Severity:** Low. PoCs already failed before this release; this is defence-in-depth, not a new vulnerability surface.

**Affected versions:** 2025.11.0 through 2026.4.0 (defence-in-depth gap). Earlier versions had the underlying CVEs.

**Fix:**
- `BERDecodeGF2NP`: strict ordering on trinomial/pentanomial exponents; field degree capped at `MAX_GF2N_FIELD_DEGREE = 4096`
- `InvertibleRabinFunction::BERDecode`: `IsPrime` checks now throw `BERDecodeError` at runtime
- `ModularSquareRoot`: non-residue search and Tonelli-Shanks loop both capped at `MAX_MODULAR_SQRT_ITERATIONS = 10000`

**References:**
- [NVD CVE-2023-50980](https://nvd.nist.gov/vuln/detail/CVE-2023-50980)
- [NVD CVE-2023-50981](https://nvd.nist.gov/vuln/detail/CVE-2023-50981)
- [GitHub Issue #21](https://github.com/cryptopp-modern/cryptopp-modern/issues/21)
- [Pull Request #22](https://github.com/cryptopp-modern/cryptopp-modern/pull/22)

---

### Ed25519 non-canonical public key acceptance (fixed in 2026.4.0)

`ed25519PublicKey::Validate()` returned true unconditionally, and the Donna verifiers unpacked public keys without checking canonicality. Per RFC 8032, the encoded y coordinate must be less than p = 2^255 - 19. Without this check, y = p + 1 and similar aliases were accepted as the identity point.

**Severity:** Low. Conformance issue, no forgery risk. Matters where raw pubkey bytes are authoritative: pinning, allowlists, dedup, audit trails, interop with stricter verifiers.

**Affected versions:** All versions prior to 2026.4.0.

**Fix:** `Validate()` and both Donna verifiers (32-bit and 64-bit) now reject y >= p. Regression test in `ValidateEd25519` covers canonical (y = 1, p-1) and non-canonical (p, p+1, 2^255-1) vectors.

See [upstream issue #1348](https://github.com/weidai11/cryptopp/issues/1348).

---

### Crypto++ Issue #1342: DSA/ECDSA Invalid Signature (Fixed in 2026.2.1)

**Component:** DSA, ECDSA, and related signature schemes (DSA2, ECGDSA, NR)

**Issue:** DSA/ECDSA signing could output an invalid signature with `r = 0` or `s = 0` in release builds. Per FIPS 186-4, both components must be in `[1, q-1]`. The code only had a `CRYPTOPP_ASSERT` check which is compiled out in release builds.

**Affected Versions:** All versions prior to 2026.2.1

**Fix Summary:**
- Probabilistic signatures: retry with fresh random `k` until `r != 0` and `s != 0`
- Deterministic signatures (RFC 6979): abort with exception per FIPS 186-5 guidance
- Safe `dynamic_cast` with proper error handling
- Consistent use of cached subgroup order

**Severity:** Low (probability ~2^(-255), invalid signatures fail verification anyway)

**References:**
- [Upstream Issue #1342](https://github.com/weidai11/cryptopp/issues/1342)
- [Full Analysis](docs/security/cryptopp-1342-dsa-signature.md)

---

### CVE-2024-28285 (Fixed in 2026.2.0)

**Component:** Hybrid discrete-logarithm decryption (ElGamal, ECIES, DLIES)

**Vulnerability:** A fault-injection vulnerability in hybrid ElGamal decryption could allow private key recovery. An attacker capable of inducing computational faults during decryption (for example via Rowhammer-style bit flips or other transient execution faults) could collect faulted decryption outputs and use them to recover the private key.

**Affected Versions:** All versions prior to 2026.2.0

**Fix Summary:**
- Validate ciphertext length before processing
- Exponent blinding verification to detect faulted key-agreement computations
- Decrypt into a temporary buffer and copy to the caller only on confirmed success
- Defence-in-depth validation in ElGamal symmetric decryption

**Security Guarantee:**
> Hybrid DL decrypt never writes plaintext to caller memory unless `DecodingResult` indicates valid decoding (and any integrity/MAC checks pass where applicable). Faults in key-agreement computations are detected via redundant blinded verification before any plaintext is released.

**API note:**
- `DL_DecryptorBase::Decrypt(RandomNumberGenerator& rng, ...)` now uses the RNG parameter for blinding verification. Previously this parameter was ignored (`CRYPTOPP_UNUSED(rng);`). All existing code already passes a real RNG, so this change is backward compatible.

**References:**
- [NVD CVE-2024-28285](https://nvd.nist.gov/vuln/detail/CVE-2024-28285)
- [Crypto++ Issue #1262](https://github.com/weidai11/cryptopp/issues/1262)
- [cryptopp-modern Issue #12](https://github.com/cryptopp-modern/cryptopp-modern/issues/12)
- [openSUSE patch](https://build.opensuse.org/projects/home%3Adgarcia%3Alibxml2%3Aalpha/packages/libcryptopp/files/libcryptopp-CVE-2024-28285.patch)
- [Ubuntu CVE tracker](https://ubuntu.com/security/CVE-2024-28285)

---

## Security Updates from Upstream

cryptopp-modern monitors upstream Crypto++ for security fixes and incorporates them as appropriate. If you discover a security issue that affects both cryptopp-modern and upstream Crypto++, please report it to both projects.
