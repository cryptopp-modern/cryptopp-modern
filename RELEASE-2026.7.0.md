2026.7.0

Minor release: SLH-DSA external interface and stateful-signing hardening.

## SLH-DSA external interface (fixes #40)

SLH-DSA now signs and verifies with the FIPS 205 external pure interface.
This restores interoperability with OpenSSL, X.509, and CMS. The default
context is empty. SLHDSA_MessageAccumulator now supports SetContext for
explicit-context signing.

Compatibility: signatures produced by 2026.3.0 through 2026.6.0 used the
internal message form and will not verify under 2026.7.0, or vice versa.
Re-sign stored SLH-DSA signatures with 2026.7.0. LMS/HSS and other algorithms
are unaffected.

## Stateful-signing hardening

* LMS/HSS signing now fails closed on invalid state reservations.
* StateReservation is bound to its issuing store; cross-store use is rejected.
* Null state-store access throws SignerStateIntegrityFailure.
* FileStateStore validates state-file size on open and rejects zero-capacity stores.
* FileStateStore uses POSIX exclusive locking and retries interrupted I/O.
* HSS capacity helpers and public-header hygiene were fixed for C++11.
