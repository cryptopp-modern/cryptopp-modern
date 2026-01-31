# ===-----------------------------------------------------------------------===#
# Distributed under the 3-Clause BSD License. See accompanying file LICENSE or
# copy at https://opensource.org/licenses/BSD-3-Clause).
# SPDX-License-Identifier: BSD-3-Clause
# ===-----------------------------------------------------------------------===#
#
# Source file lists for cryptopp-modern
# Organized by category matching the src/ directory structure
#

# ***** Core sources *****
set(cryptopp_SOURCES_CORE
    src/core/cryptlib.cpp
    src/core/cpu.cpp
    src/core/integer.cpp
    src/core/algebra.cpp
    src/core/algparam.cpp
    src/core/allocate.cpp
    src/core/asn.cpp
    src/core/channels.cpp
    src/core/dll.cpp
    src/core/files.cpp
    src/core/filters.cpp
    src/core/fips140.cpp
    src/core/fipsalgt.cpp
    src/core/gf2_32.cpp
    src/core/gf256.cpp
    src/core/gf2n.cpp
    src/core/gf2n_simd.cpp
    src/core/iterhash.cpp
    src/core/misc.cpp
    src/core/mqueue.cpp
    src/core/nbtheory.cpp
    src/core/neon_simd.cpp
    src/core/polynomi.cpp
    src/core/power7_ppc.cpp
    src/core/power8_ppc.cpp
    src/core/power9_ppc.cpp
    src/core/ppc_simd.cpp
    src/core/primetab.cpp
    src/core/queue.cpp
    src/core/rdtables.cpp
    src/core/sse_simd.cpp
    src/core/strciphr.cpp
    src/core/tftables.cpp
    src/core/tweetnacl.cpp
)

# ***** Hash sources *****
set(cryptopp_SOURCES_HASH
    src/hash/adler32.cpp
    src/hash/blake2.cpp
    src/hash/blake2b_simd.cpp
    src/hash/blake2s_simd.cpp
    src/hash/blake3.cpp
    src/hash/blake3_simd.cpp
    src/hash/blake3_avx512.cpp
    src/hash/crc.cpp
    src/hash/crc_simd.cpp
    src/hash/keccak.cpp
    src/hash/keccak_core.cpp
    src/hash/keccak_simd.cpp
    src/hash/lsh256.cpp
    src/hash/lsh256_avx.cpp
    src/hash/lsh256_sse.cpp
    src/hash/lsh512.cpp
    src/hash/lsh512_avx.cpp
    src/hash/lsh512_sse.cpp
    src/hash/md2.cpp
    src/hash/md4.cpp
    src/hash/md5.cpp
    src/hash/panama.cpp
    src/hash/ripemd.cpp
    src/hash/sha.cpp
    src/hash/sha_simd.cpp
    src/hash/sha3.cpp
    src/hash/shake.cpp
    src/hash/sm3.cpp
    src/hash/tiger.cpp
    src/hash/tigertab.cpp
    src/hash/whrlpool.cpp
)

# ***** KDF sources *****
set(cryptopp_SOURCES_KDF
    src/kdf/argon2.cpp
    src/kdf/scrypt.cpp
)

# ***** Symmetric cipher sources *****
set(cryptopp_SOURCES_SYMMETRIC
    src/symmetric/3way.cpp
    src/symmetric/arc4.cpp
    src/symmetric/aria.cpp
    src/symmetric/ariatab.cpp
    src/symmetric/bfinit.cpp
    src/symmetric/blowfish.cpp
    src/symmetric/camellia.cpp
    src/symmetric/cast.cpp
    src/symmetric/casts.cpp
    src/symmetric/chacha.cpp
    src/symmetric/chacha_avx.cpp
    src/symmetric/chacha_simd.cpp
    src/symmetric/cham.cpp
    src/symmetric/cham_simd.cpp
    src/symmetric/des.cpp
    src/symmetric/dessp.cpp
    src/symmetric/gost.cpp
    src/symmetric/hc128.cpp
    src/symmetric/hc256.cpp
    src/symmetric/hight.cpp
    src/symmetric/idea.cpp
    src/symmetric/kalyna.cpp
    src/symmetric/kalynatab.cpp
    src/symmetric/lea.cpp
    src/symmetric/lea_simd.cpp
    src/symmetric/mars.cpp
    src/symmetric/marss.cpp
    src/symmetric/rabbit.cpp
    src/symmetric/rc2.cpp
    src/symmetric/rc5.cpp
    src/symmetric/rc6.cpp
    src/symmetric/rijndael.cpp
    src/symmetric/rijndael_simd.cpp
    src/symmetric/safer.cpp
    src/symmetric/salsa.cpp
    src/symmetric/seal.cpp
    src/symmetric/seed.cpp
    src/symmetric/serpent.cpp
    src/symmetric/shacal2.cpp
    src/symmetric/shacal2_simd.cpp
    src/symmetric/shark.cpp
    src/symmetric/sharkbox.cpp
    src/symmetric/simeck.cpp
    src/symmetric/simon.cpp
    src/symmetric/simon128_simd.cpp
    src/symmetric/skipjack.cpp
    src/symmetric/sm4.cpp
    src/symmetric/sm4_simd.cpp
    src/symmetric/sosemanuk.cpp
    src/symmetric/speck.cpp
    src/symmetric/speck128_simd.cpp
    src/symmetric/square.cpp
    src/symmetric/squaretb.cpp
    src/symmetric/tea.cpp
    src/symmetric/threefish.cpp
    src/symmetric/twofish.cpp
    src/symmetric/wake.cpp
)

# ***** Public key sources *****
set(cryptopp_SOURCES_PUBKEY
    src/pubkey/dh.cpp
    src/pubkey/dh2.cpp
    src/pubkey/donna_32.cpp
    src/pubkey/donna_64.cpp
    src/pubkey/donna_sse.cpp
    src/pubkey/dsa.cpp
    src/pubkey/ec2n.cpp
    src/pubkey/eccrypto.cpp
    src/pubkey/ecp.cpp
    src/pubkey/elgamal.cpp
    src/pubkey/emsa2.cpp
    src/pubkey/eprecomp.cpp
    src/pubkey/esign.cpp
    src/pubkey/gfpcrypt.cpp
    src/pubkey/luc.cpp
    src/pubkey/mqv.cpp
    src/pubkey/oaep.cpp
    src/pubkey/pkcspad.cpp
    src/pubkey/pssr.cpp
    src/pubkey/pubkey.cpp
    src/pubkey/rabin.cpp
    src/pubkey/rsa.cpp
    src/pubkey/rw.cpp
    src/pubkey/xed25519.cpp
    src/pubkey/xtr.cpp
    src/pubkey/xtrcrypt.cpp
)

# ***** MAC sources *****
set(cryptopp_SOURCES_MAC
    src/mac/cbcmac.cpp
    src/mac/cmac.cpp
    src/mac/hmac.cpp
    src/mac/poly1305.cpp
    src/mac/ttmac.cpp
    src/mac/vmac.cpp
)

# ***** Modes sources *****
set(cryptopp_SOURCES_MODES
    src/modes/authenc.cpp
    src/modes/ccm.cpp
    src/modes/chachapoly.cpp
    src/modes/default.cpp
    src/modes/eax.cpp
    src/modes/gcm.cpp
    src/modes/gcm_simd.cpp
    src/modes/modes.cpp
    src/modes/xts.cpp
)

# ***** Encoding sources *****
set(cryptopp_SOURCES_ENCODING
    src/encoding/base32.cpp
    src/encoding/base64.cpp
    src/encoding/basecode.cpp
    src/encoding/gzip.cpp
    src/encoding/hex.cpp
    src/encoding/zdeflate.cpp
    src/encoding/zinflate.cpp
    src/encoding/zlib.cpp
)

# ***** Random sources *****
set(cryptopp_SOURCES_RANDOM
    src/random/blumshub.cpp
    src/random/darn.cpp
    src/random/osrng.cpp
    src/random/padlkrng.cpp
    src/random/randpool.cpp
    src/random/rdrand.cpp
    src/random/rng.cpp
)

# ***** Utility sources *****
set(cryptopp_SOURCES_UTIL
    src/util/hrtimer.cpp
    src/util/ida.cpp
)

# ***** Combine all library sources *****
set(cryptopp_SOURCES
    ${cryptopp_SOURCES_CORE}
    ${cryptopp_SOURCES_HASH}
    ${cryptopp_SOURCES_KDF}
    ${cryptopp_SOURCES_SYMMETRIC}
    ${cryptopp_SOURCES_PUBKEY}
    ${cryptopp_SOURCES_MAC}
    ${cryptopp_SOURCES_MODES}
    ${cryptopp_SOURCES_ENCODING}
    ${cryptopp_SOURCES_RANDOM}
    ${cryptopp_SOURCES_UTIL}
)

# ***** Test sources *****
set(cryptopp_SOURCES_TEST
    src/test/test.cpp
    src/test/bench1.cpp
    src/test/bench2.cpp
    src/test/bench3.cpp
    src/test/datatest.cpp
    src/test/dlltest.cpp
    src/test/fipstest.cpp
    src/test/validat0.cpp
    src/test/validat1.cpp
    src/test/validat2.cpp
    src/test/validat3.cpp
    src/test/validat4.cpp
    src/test/validat5.cpp
    src/test/validat6.cpp
    src/test/validat7.cpp
    src/test/validat8.cpp
    src/test/validat9.cpp
    src/test/validat10.cpp
    src/test/validat_cve_2024_28285.cpp
    src/test/regtest1.cpp
    src/test/regtest2.cpp
    src/test/regtest3.cpp
    src/test/regtest4.cpp
)

# ***** Header files *****
set(cryptopp_HEADERS
    include/cryptopp/3way.h
    include/cryptopp/adler32.h
    include/cryptopp/adv_simd.h
    include/cryptopp/aes.h
    include/cryptopp/aes_armv4.h
    include/cryptopp/aes_ctr_hmac.h
    include/cryptopp/algebra.h
    include/cryptopp/algparam.h
    include/cryptopp/allocate.h
    include/cryptopp/arc4.h
    include/cryptopp/argnames.h
    include/cryptopp/argon2.h
    include/cryptopp/aria.h
    include/cryptopp/arm_simd.h
    include/cryptopp/asn.h
    include/cryptopp/authenc.h
    include/cryptopp/base32.h
    include/cryptopp/base64.h
    include/cryptopp/basecode.h
    include/cryptopp/blake2.h
    include/cryptopp/blake3.h
    include/cryptopp/blowfish.h
    include/cryptopp/blumshub.h
    include/cryptopp/camellia.h
    include/cryptopp/cast.h
    include/cryptopp/cbcmac.h
    include/cryptopp/ccm.h
    include/cryptopp/chacha.h
    include/cryptopp/chachapoly.h
    include/cryptopp/cham.h
    include/cryptopp/channels.h
    include/cryptopp/cmac.h
    include/cryptopp/config.h
    include/cryptopp/config_align.h
    include/cryptopp/config_asm.h
    include/cryptopp/config_cpu.h
    include/cryptopp/config_cxx.h
    include/cryptopp/config_dll.h
    include/cryptopp/config_int.h
    include/cryptopp/config_misc.h
    include/cryptopp/config_ns.h
    include/cryptopp/config_os.h
    include/cryptopp/config_ver.h
    include/cryptopp/cpu.h
    include/cryptopp/crc.h
    include/cryptopp/cryptlib.h
    include/cryptopp/darn.h
    include/cryptopp/default.h
    include/cryptopp/des.h
    include/cryptopp/dh.h
    include/cryptopp/dh2.h
    include/cryptopp/dll.h
    include/cryptopp/dmac.h
    include/cryptopp/donna.h
    include/cryptopp/donna_32.h
    include/cryptopp/donna_64.h
    include/cryptopp/donna_sse.h
    include/cryptopp/drbg.h
    include/cryptopp/dsa.h
    include/cryptopp/eax.h
    include/cryptopp/ec2n.h
    include/cryptopp/eccrypto.h
    include/cryptopp/ecp.h
    include/cryptopp/ecpoint.h
    include/cryptopp/elgamal.h
    include/cryptopp/emsa2.h
    include/cryptopp/eprecomp.h
    include/cryptopp/esign.h
    include/cryptopp/fhmqv.h
    include/cryptopp/files.h
    include/cryptopp/filters.h
    include/cryptopp/fips140.h
    include/cryptopp/fltrimpl.h
    include/cryptopp/gcm.h
    include/cryptopp/gf2_32.h
    include/cryptopp/gf256.h
    include/cryptopp/gf2n.h
    include/cryptopp/gfpcrypt.h
    include/cryptopp/gost.h
    include/cryptopp/gzip.h
    include/cryptopp/hashfwd.h
    include/cryptopp/hc128.h
    include/cryptopp/hc256.h
    include/cryptopp/hex.h
    include/cryptopp/hight.h
    include/cryptopp/hkdf.h
    include/cryptopp/hmac.h
    include/cryptopp/hmqv.h
    include/cryptopp/hrtimer.h
    include/cryptopp/ida.h
    include/cryptopp/idea.h
    include/cryptopp/integer.h
    include/cryptopp/iterhash.h
    include/cryptopp/kalyna.h
    include/cryptopp/keccak.h
    include/cryptopp/lea.h
    include/cryptopp/lsh.h
    include/cryptopp/lubyrack.h
    include/cryptopp/luc.h
    include/cryptopp/mars.h
    include/cryptopp/md2.h
    include/cryptopp/md4.h
    include/cryptopp/md5.h
    include/cryptopp/mdc.h
    include/cryptopp/mersenne.h
    include/cryptopp/misc.h
    include/cryptopp/modarith.h
    include/cryptopp/modes.h
    include/cryptopp/modexppc.h
    include/cryptopp/mqueue.h
    include/cryptopp/mqv.h
    include/cryptopp/naclite.h
    include/cryptopp/nbtheory.h
    include/cryptopp/nr.h
    include/cryptopp/oaep.h
    include/cryptopp/oids.h
    include/cryptopp/osrng.h
    include/cryptopp/ossig.h
    include/cryptopp/padlkrng.h
    include/cryptopp/panama.h
    include/cryptopp/pch.h
    include/cryptopp/pkcspad.h
    include/cryptopp/poly1305.h
    include/cryptopp/polynomi.h
    include/cryptopp/ppc_simd.h
    include/cryptopp/pssr.h
    include/cryptopp/pubkey.h
    include/cryptopp/pwdbased.h
    include/cryptopp/queue.h
    include/cryptopp/rabbit.h
    include/cryptopp/rabin.h
    include/cryptopp/randpool.h
    include/cryptopp/rc2.h
    include/cryptopp/rc5.h
    include/cryptopp/rc6.h
    include/cryptopp/rdrand.h
    include/cryptopp/rijndael.h
    include/cryptopp/ripemd.h
    include/cryptopp/rng.h
    include/cryptopp/rsa.h
    include/cryptopp/rw.h
    include/cryptopp/safer.h
    include/cryptopp/salsa.h
    include/cryptopp/scrypt.h
    include/cryptopp/seal.h
    include/cryptopp/secblock.h
    include/cryptopp/secblockfwd.h
    include/cryptopp/seckey.h
    include/cryptopp/seed.h
    include/cryptopp/serpent.h
    include/cryptopp/serpentp.h
    include/cryptopp/sha.h
    include/cryptopp/sha1_armv4.h
    include/cryptopp/sha256_armv4.h
    include/cryptopp/sha3.h
    include/cryptopp/sha512_armv4.h
    include/cryptopp/shacal2.h
    include/cryptopp/shake.h
    include/cryptopp/shark.h
    include/cryptopp/simeck.h
    include/cryptopp/simon.h
    include/cryptopp/simple.h
    include/cryptopp/siphash.h
    include/cryptopp/skipjack.h
    include/cryptopp/sm3.h
    include/cryptopp/sm4.h
    include/cryptopp/smartptr.h
    include/cryptopp/sosemanuk.h
    include/cryptopp/speck.h
    include/cryptopp/square.h
    include/cryptopp/stdcpp.h
    include/cryptopp/strciphr.h
    include/cryptopp/tea.h
    include/cryptopp/threefish.h
    include/cryptopp/tiger.h
    include/cryptopp/trap.h
    include/cryptopp/trunhash.h
    include/cryptopp/ttmac.h
    include/cryptopp/tweetnacl.h
    include/cryptopp/twofish.h
    include/cryptopp/vmac.h
    include/cryptopp/wake.h
    include/cryptopp/whrlpool.h
    include/cryptopp/words.h
    include/cryptopp/xed25519.h
    include/cryptopp/xtr.h
    include/cryptopp/xtrcrypt.h
    include/cryptopp/xts.h
    include/cryptopp/zdeflate.h
    include/cryptopp/zinflate.h
    include/cryptopp/zlib.h
)

# ***** Test headers *****
set(cryptopp_HEADERS_TEST
    include/cryptopp/bench.h
    include/cryptopp/factory.h
    include/cryptopp/validate.h
)

# ***** ASM sources (MSVC/MASM for x64 Windows) *****
set(cryptopp_SOURCES_ASM_MASM
    src/core/cpuid64.asm
    src/core/x64dll.asm
    src/core/x64masm.asm
    src/random/rdrand.asm
    src/random/rdseed.asm
)

# ***** ASM sources (ARM - GNU assembler) *****
set(cryptopp_SOURCES_ASM_ARM
    src/symmetric/aes_armv4.S
    src/hash/sha1_armv4.S
    src/hash/sha256_armv4.S
    src/hash/sha512_armv4.S
)

# Build the sources lists with full paths
macro(cryptopp_prepend_path var prefix)
    set(_tmp)
    foreach(src ${${var}})
        list(APPEND _tmp "${prefix}/${src}")
    endforeach()
    set(${var} ${_tmp})
endmacro()

# Prepend PROJECT_SOURCE_DIR to all source paths
cryptopp_prepend_path(cryptopp_SOURCES ${PROJECT_SOURCE_DIR})
cryptopp_prepend_path(cryptopp_SOURCES_TEST ${PROJECT_SOURCE_DIR})
cryptopp_prepend_path(cryptopp_HEADERS ${PROJECT_SOURCE_DIR})
cryptopp_prepend_path(cryptopp_HEADERS_TEST ${PROJECT_SOURCE_DIR})
cryptopp_prepend_path(cryptopp_SOURCES_ASM_MASM ${PROJECT_SOURCE_DIR})
cryptopp_prepend_path(cryptopp_SOURCES_ASM_ARM ${PROJECT_SOURCE_DIR})

# Initially we start with an empty list for ASM sources. It will be populated
# based on the compiler, target architecture and whether the user requested to
# disable ASM or not.
set(cryptopp_SOURCES_ASM)
