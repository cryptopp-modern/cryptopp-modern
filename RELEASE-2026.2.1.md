# cryptopp-modern 2026.2.1 Release Notes

**Release Date:** February 2026
**Release Type:** Minor Release (Correctness Fix)

---

## Overview

cryptopp-modern 2026.2.1 is a minor release that fixes **Crypto++ Issue #1342**, a correctness bug where DSA/ECDSA signing could output an invalid signature with `r = 0` or `s = 0` in release builds.

---

## Bug Fix

### Issue #1342: DSA/ECDSA Invalid Signature (r=0 or s=0)

**Component:** DSA, DSA2, ECDSA, ECGDSA, Nyberg-Rueppel (NR)

**Issue:** DSA/ECDSA signing could output an invalid signature with `r = 0` or `s = 0` in release builds. Per FIPS 186-4, both signature components must be in the valid range. The existing code only had a `CRYPTOPP_ASSERT` check which is compiled out in release builds.

**Severity:** Low

### Changes

- **`pubkey.h`** — Fix `DL_SignerBase<T>::SignAndRestart()`:
  - **Probabilistic signatures:** Retry with fresh random `k` until valid (64-attempt safety cap)
  - **Deterministic signatures (RFC 6979):** Abort with exception (API returns single k)
