# cryptopp-modern 2026.5.0 Release Notes

**Release Date:** May 2026
**Release Type:** Minor Release (Security Hardening)

---

## Overview

cryptopp-modern 2026.5.0 adds defence-in-depth hardening for the code paths
behind CVE-2023-50980 and CVE-2023-50981. These are assessed as low severity
because the published proof-of-concept inputs for both CVEs are already
blocked from 2025.11.0 onward; this release tightens the same paths against
malformed input that could previously progress too far before being rejected.

A version-metadata fix is also included so that CMake and `cryptest.exe V`
report the correct release version (Issue #23).

---

## Security Hardening

### CVE-2023-50980: BERDecodeGF2NP

**Component:** F(2^m) curve parameter decoder

**Issue:** The DER decoder for F(2^m) curve parameters previously accepted
invalid reduction polynomial exponents and allowed `m` values up to 2^32.
That meant malformed input could reach `PolynomialMod2::Trinomial` or
`Pentanomial`, where the runtime checks are deliberately relaxed for
`ECIES<EC2N>` compatibility. Separately, `m` was unbounded and went straight
into `PolynomialMod2`'s bit-vector allocation.

**Change:** Validation moved to the DER boundary in `BERDecodeGF2NP`,
requiring strict ordering (`0 < t1 < m` for trinomial,
`0 < k1 < k2 < k3 < m` for pentanomial) and capping the field degree at
`MAX_GF2N_FIELD_DEGREE = 4096`. The cap covers B-571 with substantial
headroom.

### CVE-2023-50981: InvertibleRabinFunction::BERDecode

**Component:** Rabin private-key DER decoder

**Issue:** The Rabin private-key decoder checked `m_p` and `m_q` for
primality with `CRYPTOPP_ASSERT`, which is compiled out in release builds.
A non-prime `m_p` or `m_q` could then reach `CalculateInverse`, where
`ModularSquareRoot`'s Jacobi search loop can spin indefinitely on a
non-prime modulus.

**Change:** The primality checks now throw `BERDecodeError` at runtime.
`CalculateInverse` keeps its defensive `CRYPTOPP_ASSERT` as a double-check.

**Cost:** One additional `IsPrime` call per private-key load. In local testing
this is approximately 500ms on a 2048-bit modulus. This is on a key-load path,
not a hot one.

### CVE-2023-50981: ModularSquareRoot iteration cap

**Component:** Tonelli-Shanks square root

**Issue:** `ModularSquareRoot` assumes a prime modulus. Its non-residue
search and outer Tonelli-Shanks loop were both unbounded. On a non-prime
`p`, either loop could spin indefinitely, while the
`CRYPTOPP_ASSERT(IsPrime(p))` guard is compiled out in release builds.

**Change:** Both loops are now capped at
`MAX_MODULAR_SQRT_ITERATIONS = 10000`, throwing `InvalidArgument` when
exceeded. For valid prime moduli this should not get close to the cap.

---

## Other Fixes

### Issue #23: Version metadata drift

`CMakeLists.txt` and `include/cryptopp/config_ver.h` had drifted from the
released version. CMake reported `v2025.12.0` and `cryptest.exe V` reported
`2026.3.0`. Both are now bumped to `2026.5.0`. Release tooling has been
updated so this should not recur.

---

## References

- [GitHub Issue #21](https://github.com/cryptopp-modern/cryptopp-modern/issues/21)
- [GitHub Issue #23](https://github.com/cryptopp-modern/cryptopp-modern/issues/23)
- [Pull Request #22](https://github.com/cryptopp-modern/cryptopp-modern/pull/22)
- [NVD CVE-2023-50980](https://nvd.nist.gov/vuln/detail/CVE-2023-50980)
- [NVD CVE-2023-50981](https://nvd.nist.gov/vuln/detail/CVE-2023-50981)

---

## Upgrade Notes

No breaking API changes.

Callers loading hand-rolled malformed F(2^m) parameters or non-prime Rabin
private keys will now throw `BERDecodeError` where they previously loaded
without error.
