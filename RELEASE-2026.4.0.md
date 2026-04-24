# cryptopp-modern 2026.4.0 Release Notes

**Release Date:** April 2026
**Release Type:** Minor Release (Security Fix)

---

## Overview

cryptopp-modern 2026.4.0 fixes **Crypto++ Issue #1348**, a canonicality
bug in Ed25519 verification where public keys with y >= p were accepted.

---

## Security Fix

### Issue #1348: Ed25519 Accepts Non-Canonical Public Keys

**Component:** Ed25519 signature verification and public-key validation

**Issue:** `ed25519PublicKey::Validate()` returned true unconditionally,
and the Donna verifiers unpacked public keys without checking
canonicality. Per RFC 8032, the encoded y coordinate must be less than
p = 2^255 - 19. Without this check, y = p + 1 and similar aliases were
accepted as the identity point. Multiple byte encodings mapped to one
group element.

**Severity:** Low. Conformance issue, no forgery risk. Matters where
raw pubkey bytes are authoritative: pinning, allowlists, dedup, audit
trails, interop with stricter verifiers.

**Affected Versions:** All versions prior to 2026.4.0

### Changes

- `src/pubkey/xed25519.cpp`: `IsCanonicalY` helper; `Validate()` now
  rejects y >= p
- `src/pubkey/donna_32.cpp` / `donna_64.cpp`: `ed25519_pubkey_is_canonical`
  helper; verify path rejects y >= p before unpacking
- `src/test/validat9.cpp`: regression test covering y = 1, y = p - 1
  (canonical) and y = p, y = p + 1, y = 2^255 - 1 (non-canonical)
  against the RFC 8032 witness signature

### References

- [Upstream Issue #1348](https://github.com/weidai11/cryptopp/issues/1348)

---

## Upgrade Notes

`ed25519PublicKey::Validate()` is stricter. Code that relied on it
always returning true will see false for non-canonical keys. Keys
produced by compliant implementations are unaffected.
