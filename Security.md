# Security Policy

## Supported Versions

We support modern versions of cryptopp-modern. Modern versions include the main branch and the latest release.

Currently supported versions:
- 2026.2.0
- 2026.1.0
- 2025.12.0

We also incorporate critical security fixes from upstream Crypto++ and monitor for security issues in the cryptographic algorithms we implement.

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
