# 2026.7.1 Release Notes

2026.7.1 is a packaging patch. No cryptographic code changed.

* Move CMake and pkg-config files under `${CMAKE_INSTALL_LIBDIR}` (#47).
* Restore `libcryptopp.pc`; keep `cryptopp-modern.pc` as an alias (#51).
* Add `.tar.gz` releases and normalise line endings (#49).
* Publish the release-signing key and verification steps (#46).

Standard CMake and pkg-config discovery continues to work. Consumers using hard-coded paths under `share/` must update them.
