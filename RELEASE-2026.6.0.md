## 2026.6.0 Release Notes

**Release Date:** 3 June 2026
**Release Type:** Minor release

## Overview

cryptopp-modern 2026.6.0 adds LMS and HSS stateful hash-based signatures
following NIST SP 800-208 and RFC 8554.

This release includes:

- LMS single-tree signatures for H5 and H10 with Winternitz W=8
- HSS hierarchical signatures at L=2 and L=3 with uniform parameter sets
- a new stateful signing API, separate from `PK_Signer`
- `FileStateStore`, a durable file-backed state store for signing indexes
- ASN.1 public-key support using RFC 8708 `id-alg-hss-lms-hashsig`

There are no breaking API changes.

## LMS and HSS

LMS and HSS are stateful hash-based signature schemes. Each signature consumes
a one-time signing index, and reusing an index breaks security.

The supported types are:

- `LMS_SHA256_H5_W8`
- `LMS_SHA256_H10_W8`
- `HSS_SHA256_H5_W8_L2`
- `HSS_SHA256_H10_W8_L2`
- `HSS_SHA256_H5_W8_L3`

Public keys are encoded as X.509 `SubjectPublicKeyInfo` using the RFC 8708
OID. Private keys use a library-local PKCS#8 wrapper carrying `SEED || I`.
Signing progress is not serialised into the private key; it lives in the
state store.

## Stateful signing API

This release adds:

- `PK_StatefulSigner`
- `SignerStateStore`
- `StateReservation`
- `InsecureMemoryStateStore`
- `FileStateStore`

`PK_StatefulSigner` is deliberately not a subtype of `PK_Signer`. Stateful
signers have different safety rules, so keeping the API separate avoids
accidentally using a stateful signer through the stateless signer interface.

The core rule is simple: once a signing index has been reserved, it must not
be issued again. Safe failure may burn an unused index. Unsafe failure is
index reuse.

## FileStateStore

`FileStateStore` is the durable reference backend for desktop and server use.

It reserves indexes ahead of signing using write-ahead persistence, with a
fixed-size on-disk record protected by HMAC-SHA256. On invalid state or
integrity failure, the store fails closed and poisons itself.

Platform support includes Win32 file handling, POSIX `fsync`, and macOS
`F_FULLFSYNC`.

`FileStateStore` does not claim to solve every rollback scenario. If an
application needs protection against backup restore, VM snapshot rollback, or
external file replacement, it should use a rollback-protected backing store or
provide its own `SignerStateStore` implementation.

## Other changes

This release also includes:

- Save/Load round-trip tests for ML-KEM, ML-DSA, and SLH-DSA keys
- Android x86_64 and x86 build coverage in CI
- legacy compiler CI lanes for GCC 9-10 and Clang 11-14
- a sanitizer CI fix so `cryptest tv` output is included in the checked log
- a zero-length `memcpy` guard in `DL_DecryptorBase::Decrypt` for UBSan hygiene
- documentation updates for LMS/HSS

## Validation

LMS and HSS coverage includes ACVP and RFC test vectors, malformed-signature
rejection, exhaustion handling, HSS subtree boundary handling, signer
reconstruction, and `FileStateStore` corruption and poisoning cases.

Validation is wired into `ValidateAll`.

## Upgrade notes

No breaking changes.

Existing signers, verifiers, and serialisation paths are unaffected.

Users adopting LMS or HSS should review the SP 800-208 guidance on state
management before deploying. Each signature permanently consumes signer state.
`FileStateStore` is suitable as a reference backend for desktop and server
platforms. Embedded targets should implement `SignerStateStore` against a
rollback-protected backing store.
