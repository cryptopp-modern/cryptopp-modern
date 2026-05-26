## 2026.5.2 Release Notes

**Release Date:** 26 May 2026
**Release Type:** Patch release

---

## Overview

cryptopp-modern 2026.5.2 hardens ASN.1 BER re-encoding and tightens Ed25519 verification behaviour.

This release adds:

- a recursion depth cap for `DERReencode`
- rejection of non-canonical Ed25519 signatures where `S >= L`
- strict-validation rejection of small-order Ed25519 public keys

There are no API changes in this release.

---

## ASN.1 DERReencode depth cap

`DERReencode` walked nested constructed indefinite BER without a depth limit. A crafted chain of `0x30 0x80` sequences could recurse until the thread stack was exhausted. `PKCS8PrivateKey` import reaches this path through `BERDecodeOptionalAttributes`.

This release caps the recursion depth at 32 levels, matching OpenSSL's `ASN1_MAX_CONSTRUCTED_NEST`. Deeper inputs now throw `BERDecodeError` instead of recursing further.

This addresses upstream Crypto++ issue 1353. The reporter rated the issue CVSS 7.5 for availability impact.

---

## Ed25519 signature scalar canonicality

The Ed25519 verifiers accepted non-canonical signatures where `S >= L`. The previous check only masked the top three bits of `S`, leaving the gap `L <= S < 2^253`. A valid signature changed from `S'` to `S' + L` could still verify because the verification equation holds modulo the subgroup order.

Both affected verification paths are now patched:

- the Donna verifier
- the NaCl C API verifier, `crypto_sign_open` in `tweetnacl.cpp`

Both now reject `S >= L` before continuing with verification.

This addresses the signature-scalar part of upstream Crypto++ issue 1352.

Severity: Low. This is a conformance fix, not a forgery. It matters for systems that key behaviour on raw signature bytes, such as replay caches, audit trails, deduplication, allowlists, and interoperability with stricter Ed25519 implementations.

---

## Ed25519 small-order public key rejection

`ed25519PublicKey::Validate` now rejects small-order Ed25519 public keys when validation level is 2 or higher. The existing canonical encoding check still runs at all validation levels.

This addresses the small-order public key part of upstream Crypto++ issue 1352. Level 0 behaviour is unchanged.

---

## Validation

New regression coverage was added for:

- `DERReencode` depth limits in `validat0.cpp`
- Ed25519 scalar canonicality in the Donna verifier path
- Ed25519 scalar canonicality in the NaCl verifier path
- Ed25519 small-order public key validation

Local validation passed with:

- `cryptest v`
- `cryptest tv all`

---

## References

- PR #35: Harden DERReencode and Ed25519 verification
- PR #36: Reject small-order Ed25519 public keys in Validate
- Upstream Crypto++ issue 1353
- Upstream Crypto++ issue 1352
- Upstream Crypto++ PR 1354
- Upstream Crypto++ PR 1355
- Upstream Crypto++ commit `4775a166`, covering the small-order public key check on upstream master

---

## Upgrade notes

No breaking changes.

Existing valid signatures and valid public keys continue to verify. The stricter checks only reject:

- non-canonical Ed25519 signatures where `S >= L`
- small-order Ed25519 public keys when `ed25519PublicKey::Validate` is called at level 2 or higher
