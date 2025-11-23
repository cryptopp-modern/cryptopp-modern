#!/usr/bin/env python3
"""
Update Visual Studio project files for Phase 2 directory structure.
Updates all .cpp and .h file paths from root to src/ and include/ directories.
"""

import re
import sys

# Mapping of filename to directory
CPP_FILE_TO_DIR = {
    # Core files
    'algebra.cpp': 'src\\core', 'algparam.cpp': 'src\\core', 'allocate.cpp': 'src\\core',
    'asn.cpp': 'src\\core', 'channels.cpp': 'src\\core', 'cpu.cpp': 'src\\core',
    'cryptlib.cpp': 'src\\core', 'dll.cpp': 'src\\core', 'files.cpp': 'src\\core',
    'filters.cpp': 'src\\core', 'fips140.cpp': 'src\\core', 'fipsalgt.cpp': 'src\\core',
    'gf256.cpp': 'src\\core', 'gf2_32.cpp': 'src\\core', 'gf2n.cpp': 'src\\core',
    'gf2n_simd.cpp': 'src\\core', 'integer.cpp': 'src\\core', 'iterhash.cpp': 'src\\core',
    'misc.cpp': 'src\\core', 'mqueue.cpp': 'src\\core', 'nbtheory.cpp': 'src\\core',
    'neon_simd.cpp': 'src\\core', 'pch.cpp': 'src\\core', 'polynomi.cpp': 'src\\core',
    'power7_ppc.cpp': 'src\\core', 'power8_ppc.cpp': 'src\\core', 'power9_ppc.cpp': 'src\\core',
    'ppc_simd.cpp': 'src\\core', 'primetab.cpp': 'src\\core', 'queue.cpp': 'src\\core',
    'rdtables.cpp': 'src\\core', 'sse_simd.cpp': 'src\\core', 'strciphr.cpp': 'src\\core',
    'tftables.cpp': 'src\\core', 'tweetnacl.cpp': 'src\\core',
    'cpuid64.asm': 'src\\core', 'x64dll.asm': 'src\\core', 'x64masm.asm': 'src\\core',

    # Encoding
    'base32.cpp': 'src\\encoding', 'base64.cpp': 'src\\encoding', 'basecode.cpp': 'src\\encoding',
    'gzip.cpp': 'src\\encoding', 'hex.cpp': 'src\\encoding', 'zdeflate.cpp': 'src\\encoding',
    'zinflate.cpp': 'src\\encoding', 'zlib.cpp': 'src\\encoding',

    # Hash
    'adler32.cpp': 'src\\hash', 'blake2.cpp': 'src\\hash', 'blake2b_simd.cpp': 'src\\hash',
    'blake2s_simd.cpp': 'src\\hash', 'blake3.cpp': 'src\\hash', 'crc.cpp': 'src\\hash',
    'crc_simd.cpp': 'src\\hash', 'keccak.cpp': 'src\\hash', 'keccak_core.cpp': 'src\\hash',
    'keccak_simd.cpp': 'src\\hash', 'lsh256.cpp': 'src\\hash', 'lsh256_avx.cpp': 'src\\hash',
    'lsh256_sse.cpp': 'src\\hash', 'lsh512.cpp': 'src\\hash', 'lsh512_avx.cpp': 'src\\hash',
    'lsh512_sse.cpp': 'src\\hash', 'md2.cpp': 'src\\hash', 'md4.cpp': 'src\\hash',
    'md5.cpp': 'src\\hash', 'panama.cpp': 'src\\hash', 'ripemd.cpp': 'src\\hash',
    'sha.cpp': 'src\\hash', 'sha3.cpp': 'src\\hash', 'sha_simd.cpp': 'src\\hash',
    'shake.cpp': 'src\\hash', 'sm3.cpp': 'src\\hash', 'tiger.cpp': 'src\\hash',
    'tigertab.cpp': 'src\\hash', 'whrlpool.cpp': 'src\\hash',

    # KDF
    'argon2.cpp': 'src\\kdf', 'scrypt.cpp': 'src\\kdf',

    # MAC
    'cbcmac.cpp': 'src\\mac', 'cmac.cpp': 'src\\mac', 'hmac.cpp': 'src\\mac',
    'poly1305.cpp': 'src\\mac', 'ttmac.cpp': 'src\\mac', 'vmac.cpp': 'src\\mac',

    # Modes
    'authenc.cpp': 'src\\modes', 'ccm.cpp': 'src\\modes', 'chachapoly.cpp': 'src\\modes',
    'default.cpp': 'src\\modes', 'eax.cpp': 'src\\modes', 'gcm.cpp': 'src\\modes',
    'gcm_simd.cpp': 'src\\modes', 'modes.cpp': 'src\\modes', 'xts.cpp': 'src\\modes',

    # Public key
    'dh.cpp': 'src\\pubkey', 'dh2.cpp': 'src\\pubkey', 'donna_32.cpp': 'src\\pubkey',
    'donna_64.cpp': 'src\\pubkey', 'donna_sse.cpp': 'src\\pubkey', 'dsa.cpp': 'src\\pubkey',
    'ec2n.cpp': 'src\\pubkey', 'eccrypto.cpp': 'src\\pubkey', 'ecp.cpp': 'src\\pubkey',
    'elgamal.cpp': 'src\\pubkey', 'emsa2.cpp': 'src\\pubkey', 'eprecomp.cpp': 'src\\pubkey',
    'esign.cpp': 'src\\pubkey', 'gfpcrypt.cpp': 'src\\pubkey', 'luc.cpp': 'src\\pubkey',
    'mqv.cpp': 'src\\pubkey', 'oaep.cpp': 'src\\pubkey', 'pkcspad.cpp': 'src\\pubkey',
    'pssr.cpp': 'src\\pubkey', 'pubkey.cpp': 'src\\pubkey', 'rabin.cpp': 'src\\pubkey',
    'rsa.cpp': 'src\\pubkey', 'rw.cpp': 'src\\pubkey', 'xed25519.cpp': 'src\\pubkey',
    'xtr.cpp': 'src\\pubkey', 'xtrcrypt.cpp': 'src\\pubkey',

    # Random
    'blumshub.cpp': 'src\\random', 'darn.cpp': 'src\\random', 'osrng.cpp': 'src\\random',
    'padlkrng.cpp': 'src\\random', 'randpool.cpp': 'src\\random', 'rdrand.cpp': 'src\\random',
    'rng.cpp': 'src\\random', 'rdrand.asm': 'src\\random', 'rdseed.asm': 'src\\random',

    # Symmetric
    '3way.cpp': 'src\\symmetric', 'arc4.cpp': 'src\\symmetric', 'aria.cpp': 'src\\symmetric',
    'ariatab.cpp': 'src\\symmetric', 'bfinit.cpp': 'src\\symmetric', 'blowfish.cpp': 'src\\symmetric',
    'camellia.cpp': 'src\\symmetric', 'cast.cpp': 'src\\symmetric', 'casts.cpp': 'src\\symmetric',
    'chacha.cpp': 'src\\symmetric', 'chacha_avx.cpp': 'src\\symmetric', 'chacha_simd.cpp': 'src\\symmetric',
    'cham.cpp': 'src\\symmetric', 'cham_simd.cpp': 'src\\symmetric', 'des.cpp': 'src\\symmetric',
    'dessp.cpp': 'src\\symmetric', 'gost.cpp': 'src\\symmetric', 'hc128.cpp': 'src\\symmetric',
    'hc256.cpp': 'src\\symmetric', 'hight.cpp': 'src\\symmetric', 'idea.cpp': 'src\\symmetric',
    'kalyna.cpp': 'src\\symmetric', 'kalynatab.cpp': 'src\\symmetric', 'lea.cpp': 'src\\symmetric',
    'lea_simd.cpp': 'src\\symmetric', 'mars.cpp': 'src\\symmetric', 'marss.cpp': 'src\\symmetric',
    'rabbit.cpp': 'src\\symmetric', 'rc2.cpp': 'src\\symmetric', 'rc5.cpp': 'src\\symmetric',
    'rc6.cpp': 'src\\symmetric', 'rijndael.cpp': 'src\\symmetric', 'rijndael_simd.cpp': 'src\\symmetric',
    'safer.cpp': 'src\\symmetric', 'salsa.cpp': 'src\\symmetric', 'seal.cpp': 'src\\symmetric',
    'seed.cpp': 'src\\symmetric', 'serpent.cpp': 'src\\symmetric', 'shacal2.cpp': 'src\\symmetric',
    'shacal2_simd.cpp': 'src\\symmetric', 'shark.cpp': 'src\\symmetric', 'sharkbox.cpp': 'src\\symmetric',
    'simeck.cpp': 'src\\symmetric', 'simon.cpp': 'src\\symmetric', 'simon128_simd.cpp': 'src\\symmetric',
    'skipjack.cpp': 'src\\symmetric', 'sm4.cpp': 'src\\symmetric', 'sm4_simd.cpp': 'src\\symmetric',
    'sosemanuk.cpp': 'src\\symmetric', 'speck.cpp': 'src\\symmetric', 'speck128_simd.cpp': 'src\\symmetric',
    'square.cpp': 'src\\symmetric', 'squaretb.cpp': 'src\\symmetric', 'tea.cpp': 'src\\symmetric',
    'threefish.cpp': 'src\\symmetric', 'twofish.cpp': 'src\\symmetric', 'wake.cpp': 'src\\symmetric',

    # Test
    'bench1.cpp': 'src\\test', 'bench2.cpp': 'src\\test', 'bench3.cpp': 'src\\test',
    'datatest.cpp': 'src\\test', 'dlltest.cpp': 'src\\test', 'fipstest.cpp': 'src\\test',
    'regtest1.cpp': 'src\\test', 'regtest2.cpp': 'src\\test', 'regtest3.cpp': 'src\\test',
    'regtest4.cpp': 'src\\test', 'test.cpp': 'src\\test', 'validat0.cpp': 'src\\test',
    'validat1.cpp': 'src\\test', 'validat10.cpp': 'src\\test', 'validat2.cpp': 'src\\test',
    'validat3.cpp': 'src\\test', 'validat4.cpp': 'src\\test', 'validat5.cpp': 'src\\test',
    'validat6.cpp': 'src\\test', 'validat7.cpp': 'src\\test', 'validat8.cpp': 'src\\test',
    'validat9.cpp': 'src\\test',

    # Util
    'hrtimer.cpp': 'src\\util', 'ida.cpp': 'src\\util', 'simple.cpp': 'src\\util',
}

def update_source_paths(content):
    """Update source file paths (.cpp and .asm)."""
    for filename, directory in CPP_FILE_TO_DIR.items():
        # Update ClCompile and CustomBuild Include paths
        old_pattern = f'Include="{filename}"'
        new_path = f'Include="{directory}\\{filename}"'
        content = content.replace(old_pattern, new_path)
    return content

def update_header_paths(content):
    """Update .h file paths to include/cryptopp/."""
    # Pattern to match Include="something.h"
    def replace_header(match):
        full_match = match.group(0)
        header_path = match.group(1)

        # Don't update if already in include/cryptopp/
        if 'include\\cryptopp\\' in header_path:
            return full_match

        # Don't update resource.h
        if header_path == 'resource.h':
            return full_match

        # Extract just the filename (in case it has a path)
        filename = header_path.split('\\')[-1]

        # Return updated path
        return f'Include="include\\cryptopp\\{filename}"'

    # Match Include="*.h" patterns
    content = re.sub(r'Include="([^"]+\.h)"', replace_header, content)
    return content

def update_vcxproj_file(filepath):
    """Update a single .vcxproj file."""
    print(f"Updating {filepath}...")

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Update source file paths
    content = update_source_paths(content)

    # Update header file paths
    content = update_header_paths(content)

    # Check if anything changed
    if content == original_content:
        print(f"  No changes needed for {filepath}")
        return False

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  Updated {filepath}")
    return True

def main():
    """Update all .vcxproj files."""
    vcxproj_files = [
        'cryptlib.vcxproj',
        'cryptest.vcxproj',
        'cryptdll.vcxproj',
        'dlltest.vcxproj'
    ]

    updated_count = 0
    for filepath in vcxproj_files:
        try:
            if update_vcxproj_file(filepath):
                updated_count += 1
        except FileNotFoundError:
            print(f"Warning: {filepath} not found, skipping...")
        except Exception as e:
            print(f"Error updating {filepath}: {e}")
            return 1

    print(f"\nUpdated {updated_count} of {len(vcxproj_files)} files.")
    return 0

if __name__ == '__main__':
    sys.exit(main())
