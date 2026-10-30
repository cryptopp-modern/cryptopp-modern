// blake3_avx2.cpp - written and placed in the public domain by
//                   Colin Brown.
//
//    AVX2 implementation for 8-way parallel chunk hashing.
//    Kept separate from the SSE4.1 implementation.
//
//    AVX2 implementation based on the BLAKE3 team's reference at
//    https://github.com/BLAKE3-team/BLAKE3 (public domain).

#include <cryptopp/pch.h>
#include <cryptopp/config.h>
#include <cryptopp/misc.h>
#include <cryptopp/blake3.h>

#if (CRYPTOPP_AVX2_AVAILABLE)
# include <immintrin.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char BLAKE3_AVX2_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// BLAKE3 IV - same as SHA-256 (aligned in blake3.cpp)
extern const word32 BLAKE3_IV[8];

// Message schedule for BLAKE3 - 7 rounds
extern const byte BLAKE3_MSG_SCHEDULE[7][16];

#if CRYPTOPP_AVX2_AVAILABLE

// BLAKE3 constants
static const size_t BLAKE3_BLOCK_LEN = 64;
static const size_t BLAKE3_CHUNK_LEN = 1024;
static const byte BLAKE3_CHUNK_START = 1;
static const byte BLAKE3_CHUNK_END = 2;

// AVX2 helper macros and functions
#define LOADU256(p)    _mm256_loadu_si256((const __m256i *)(const void*)(p))
#define STOREU256(p,r) _mm256_storeu_si256((__m256i *)(void*)(p), r)

inline __m256i addv256(__m256i a, __m256i b) { return _mm256_add_epi32(a, b); }
inline __m256i xorv256(__m256i a, __m256i b) { return _mm256_xor_si256(a, b); }
inline __m256i set1_256(word32 x) { return _mm256_set1_epi32((int)x); }

inline __m256i set8(word32 a, word32 b, word32 c, word32 d,
                    word32 e, word32 f, word32 g, word32 h) {
    return _mm256_setr_epi32((int)a, (int)b, (int)c, (int)d,
                             (int)e, (int)f, (int)g, (int)h);
}

// Rotation by 16 bits using byte shuffle (AVX2)
inline __m256i rot16_256(__m256i x) {
    return _mm256_shuffle_epi8(x,
        _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
                        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
}

// Rotation by 12 bits using shift and OR
inline __m256i rot12_256(__m256i x) {
    return xorv256(_mm256_srli_epi32(x, 12), _mm256_slli_epi32(x, 20));
}

// Rotation by 8 bits using byte shuffle (AVX2)
inline __m256i rot8_256(__m256i x) {
    return _mm256_shuffle_epi8(x,
        _mm256_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1,
                        12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1));
}

// Rotation by 7 bits using shift and OR
inline __m256i rot7_256(__m256i x) {
    return xorv256(_mm256_srli_epi32(x, 7), _mm256_slli_epi32(x, 25));
}

// Transpose 8x8 matrix of 32-bit words (processes two 4x4 blocks)
inline void transpose_vecs256(__m256i *a, __m256i *b, __m256i *c, __m256i *d,
                               __m256i *e, __m256i *f, __m256i *g, __m256i *h)
{
    __m256i t0 = _mm256_unpacklo_epi32(*a, *b);
    __m256i t1 = _mm256_unpackhi_epi32(*a, *b);
    __m256i t2 = _mm256_unpacklo_epi32(*c, *d);
    __m256i t3 = _mm256_unpackhi_epi32(*c, *d);
    __m256i t4 = _mm256_unpacklo_epi32(*e, *f);
    __m256i t5 = _mm256_unpackhi_epi32(*e, *f);
    __m256i t6 = _mm256_unpacklo_epi32(*g, *h);
    __m256i t7 = _mm256_unpackhi_epi32(*g, *h);

    __m256i s0 = _mm256_unpacklo_epi64(t0, t2);
    __m256i s1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i s2 = _mm256_unpacklo_epi64(t1, t3);
    __m256i s3 = _mm256_unpackhi_epi64(t1, t3);
    __m256i s4 = _mm256_unpacklo_epi64(t4, t6);
    __m256i s5 = _mm256_unpackhi_epi64(t4, t6);
    __m256i s6 = _mm256_unpacklo_epi64(t5, t7);
    __m256i s7 = _mm256_unpackhi_epi64(t5, t7);

    *a = _mm256_permute2x128_si256(s0, s4, 0x20);
    *b = _mm256_permute2x128_si256(s1, s5, 0x20);
    *c = _mm256_permute2x128_si256(s2, s6, 0x20);
    *d = _mm256_permute2x128_si256(s3, s7, 0x20);
    *e = _mm256_permute2x128_si256(s0, s4, 0x31);
    *f = _mm256_permute2x128_si256(s1, s5, 0x31);
    *g = _mm256_permute2x128_si256(s2, s6, 0x31);
    *h = _mm256_permute2x128_si256(s3, s7, 0x31);
}

// Load and transpose message words from 8 blocks into 16 transposed vectors
inline void transpose_msg_vecs8(const byte *const *inputs, size_t block_offset,
                                __m256i out[16])
{
    // Load 4 words from each of 8 inputs, 4 times (for 16 total words)
    __m256i t0 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 0],
        *(const int*)&inputs[1][block_offset + 0],
        *(const int*)&inputs[2][block_offset + 0],
        *(const int*)&inputs[3][block_offset + 0],
        *(const int*)&inputs[4][block_offset + 0],
        *(const int*)&inputs[5][block_offset + 0],
        *(const int*)&inputs[6][block_offset + 0],
        *(const int*)&inputs[7][block_offset + 0]);
    __m256i t1 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 4],
        *(const int*)&inputs[1][block_offset + 4],
        *(const int*)&inputs[2][block_offset + 4],
        *(const int*)&inputs[3][block_offset + 4],
        *(const int*)&inputs[4][block_offset + 4],
        *(const int*)&inputs[5][block_offset + 4],
        *(const int*)&inputs[6][block_offset + 4],
        *(const int*)&inputs[7][block_offset + 4]);
    __m256i t2 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 8],
        *(const int*)&inputs[1][block_offset + 8],
        *(const int*)&inputs[2][block_offset + 8],
        *(const int*)&inputs[3][block_offset + 8],
        *(const int*)&inputs[4][block_offset + 8],
        *(const int*)&inputs[5][block_offset + 8],
        *(const int*)&inputs[6][block_offset + 8],
        *(const int*)&inputs[7][block_offset + 8]);
    __m256i t3 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 12],
        *(const int*)&inputs[1][block_offset + 12],
        *(const int*)&inputs[2][block_offset + 12],
        *(const int*)&inputs[3][block_offset + 12],
        *(const int*)&inputs[4][block_offset + 12],
        *(const int*)&inputs[5][block_offset + 12],
        *(const int*)&inputs[6][block_offset + 12],
        *(const int*)&inputs[7][block_offset + 12]);
    __m256i t4 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 16],
        *(const int*)&inputs[1][block_offset + 16],
        *(const int*)&inputs[2][block_offset + 16],
        *(const int*)&inputs[3][block_offset + 16],
        *(const int*)&inputs[4][block_offset + 16],
        *(const int*)&inputs[5][block_offset + 16],
        *(const int*)&inputs[6][block_offset + 16],
        *(const int*)&inputs[7][block_offset + 16]);
    __m256i t5 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 20],
        *(const int*)&inputs[1][block_offset + 20],
        *(const int*)&inputs[2][block_offset + 20],
        *(const int*)&inputs[3][block_offset + 20],
        *(const int*)&inputs[4][block_offset + 20],
        *(const int*)&inputs[5][block_offset + 20],
        *(const int*)&inputs[6][block_offset + 20],
        *(const int*)&inputs[7][block_offset + 20]);
    __m256i t6 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 24],
        *(const int*)&inputs[1][block_offset + 24],
        *(const int*)&inputs[2][block_offset + 24],
        *(const int*)&inputs[3][block_offset + 24],
        *(const int*)&inputs[4][block_offset + 24],
        *(const int*)&inputs[5][block_offset + 24],
        *(const int*)&inputs[6][block_offset + 24],
        *(const int*)&inputs[7][block_offset + 24]);
    __m256i t7 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 28],
        *(const int*)&inputs[1][block_offset + 28],
        *(const int*)&inputs[2][block_offset + 28],
        *(const int*)&inputs[3][block_offset + 28],
        *(const int*)&inputs[4][block_offset + 28],
        *(const int*)&inputs[5][block_offset + 28],
        *(const int*)&inputs[6][block_offset + 28],
        *(const int*)&inputs[7][block_offset + 28]);
    __m256i t8 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 32],
        *(const int*)&inputs[1][block_offset + 32],
        *(const int*)&inputs[2][block_offset + 32],
        *(const int*)&inputs[3][block_offset + 32],
        *(const int*)&inputs[4][block_offset + 32],
        *(const int*)&inputs[5][block_offset + 32],
        *(const int*)&inputs[6][block_offset + 32],
        *(const int*)&inputs[7][block_offset + 32]);
    __m256i t9 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 36],
        *(const int*)&inputs[1][block_offset + 36],
        *(const int*)&inputs[2][block_offset + 36],
        *(const int*)&inputs[3][block_offset + 36],
        *(const int*)&inputs[4][block_offset + 36],
        *(const int*)&inputs[5][block_offset + 36],
        *(const int*)&inputs[6][block_offset + 36],
        *(const int*)&inputs[7][block_offset + 36]);
    __m256i t10 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 40],
        *(const int*)&inputs[1][block_offset + 40],
        *(const int*)&inputs[2][block_offset + 40],
        *(const int*)&inputs[3][block_offset + 40],
        *(const int*)&inputs[4][block_offset + 40],
        *(const int*)&inputs[5][block_offset + 40],
        *(const int*)&inputs[6][block_offset + 40],
        *(const int*)&inputs[7][block_offset + 40]);
    __m256i t11 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 44],
        *(const int*)&inputs[1][block_offset + 44],
        *(const int*)&inputs[2][block_offset + 44],
        *(const int*)&inputs[3][block_offset + 44],
        *(const int*)&inputs[4][block_offset + 44],
        *(const int*)&inputs[5][block_offset + 44],
        *(const int*)&inputs[6][block_offset + 44],
        *(const int*)&inputs[7][block_offset + 44]);
    __m256i t12 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 48],
        *(const int*)&inputs[1][block_offset + 48],
        *(const int*)&inputs[2][block_offset + 48],
        *(const int*)&inputs[3][block_offset + 48],
        *(const int*)&inputs[4][block_offset + 48],
        *(const int*)&inputs[5][block_offset + 48],
        *(const int*)&inputs[6][block_offset + 48],
        *(const int*)&inputs[7][block_offset + 48]);
    __m256i t13 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 52],
        *(const int*)&inputs[1][block_offset + 52],
        *(const int*)&inputs[2][block_offset + 52],
        *(const int*)&inputs[3][block_offset + 52],
        *(const int*)&inputs[4][block_offset + 52],
        *(const int*)&inputs[5][block_offset + 52],
        *(const int*)&inputs[6][block_offset + 52],
        *(const int*)&inputs[7][block_offset + 52]);
    __m256i t14 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 56],
        *(const int*)&inputs[1][block_offset + 56],
        *(const int*)&inputs[2][block_offset + 56],
        *(const int*)&inputs[3][block_offset + 56],
        *(const int*)&inputs[4][block_offset + 56],
        *(const int*)&inputs[5][block_offset + 56],
        *(const int*)&inputs[6][block_offset + 56],
        *(const int*)&inputs[7][block_offset + 56]);
    __m256i t15 = _mm256_setr_epi32(
        *(const int*)&inputs[0][block_offset + 60],
        *(const int*)&inputs[1][block_offset + 60],
        *(const int*)&inputs[2][block_offset + 60],
        *(const int*)&inputs[3][block_offset + 60],
        *(const int*)&inputs[4][block_offset + 60],
        *(const int*)&inputs[5][block_offset + 60],
        *(const int*)&inputs[6][block_offset + 60],
        *(const int*)&inputs[7][block_offset + 60]);

    out[0] = t0; out[1] = t1; out[2] = t2; out[3] = t3;
    out[4] = t4; out[5] = t5; out[6] = t6; out[7] = t7;
    out[8] = t8; out[9] = t9; out[10] = t10; out[11] = t11;
    out[12] = t12; out[13] = t13; out[14] = t14; out[15] = t15;
}

// Perform one round of BLAKE3 compression on 8 parallel states
inline void round_fn8(__m256i v[16], __m256i m[16], size_t r)
{
    v[0]  = addv256(v[0], m[BLAKE3_MSG_SCHEDULE[r][0]]);
    v[1]  = addv256(v[1], m[BLAKE3_MSG_SCHEDULE[r][2]]);
    v[2]  = addv256(v[2], m[BLAKE3_MSG_SCHEDULE[r][4]]);
    v[3]  = addv256(v[3], m[BLAKE3_MSG_SCHEDULE[r][6]]);
    v[0]  = addv256(v[0], v[4]);
    v[1]  = addv256(v[1], v[5]);
    v[2]  = addv256(v[2], v[6]);
    v[3]  = addv256(v[3], v[7]);
    v[12] = xorv256(v[12], v[0]);
    v[13] = xorv256(v[13], v[1]);
    v[14] = xorv256(v[14], v[2]);
    v[15] = xorv256(v[15], v[3]);
    v[12] = rot16_256(v[12]);
    v[13] = rot16_256(v[13]);
    v[14] = rot16_256(v[14]);
    v[15] = rot16_256(v[15]);
    v[8]  = addv256(v[8], v[12]);
    v[9]  = addv256(v[9], v[13]);
    v[10] = addv256(v[10], v[14]);
    v[11] = addv256(v[11], v[15]);
    v[4]  = xorv256(v[4], v[8]);
    v[5]  = xorv256(v[5], v[9]);
    v[6]  = xorv256(v[6], v[10]);
    v[7]  = xorv256(v[7], v[11]);
    v[4]  = rot12_256(v[4]);
    v[5]  = rot12_256(v[5]);
    v[6]  = rot12_256(v[6]);
    v[7]  = rot12_256(v[7]);
    v[0]  = addv256(v[0], m[BLAKE3_MSG_SCHEDULE[r][1]]);
    v[1]  = addv256(v[1], m[BLAKE3_MSG_SCHEDULE[r][3]]);
    v[2]  = addv256(v[2], m[BLAKE3_MSG_SCHEDULE[r][5]]);
    v[3]  = addv256(v[3], m[BLAKE3_MSG_SCHEDULE[r][7]]);
    v[0]  = addv256(v[0], v[4]);
    v[1]  = addv256(v[1], v[5]);
    v[2]  = addv256(v[2], v[6]);
    v[3]  = addv256(v[3], v[7]);
    v[12] = xorv256(v[12], v[0]);
    v[13] = xorv256(v[13], v[1]);
    v[14] = xorv256(v[14], v[2]);
    v[15] = xorv256(v[15], v[3]);
    v[12] = rot8_256(v[12]);
    v[13] = rot8_256(v[13]);
    v[14] = rot8_256(v[14]);
    v[15] = rot8_256(v[15]);
    v[8]  = addv256(v[8], v[12]);
    v[9]  = addv256(v[9], v[13]);
    v[10] = addv256(v[10], v[14]);
    v[11] = addv256(v[11], v[15]);
    v[4]  = xorv256(v[4], v[8]);
    v[5]  = xorv256(v[5], v[9]);
    v[6]  = xorv256(v[6], v[10]);
    v[7]  = xorv256(v[7], v[11]);
    v[4]  = rot7_256(v[4]);
    v[5]  = rot7_256(v[5]);
    v[6]  = rot7_256(v[6]);
    v[7]  = rot7_256(v[7]);

    v[0]  = addv256(v[0], m[BLAKE3_MSG_SCHEDULE[r][8]]);
    v[1]  = addv256(v[1], m[BLAKE3_MSG_SCHEDULE[r][10]]);
    v[2]  = addv256(v[2], m[BLAKE3_MSG_SCHEDULE[r][12]]);
    v[3]  = addv256(v[3], m[BLAKE3_MSG_SCHEDULE[r][14]]);
    v[0]  = addv256(v[0], v[5]);
    v[1]  = addv256(v[1], v[6]);
    v[2]  = addv256(v[2], v[7]);
    v[3]  = addv256(v[3], v[4]);
    v[15] = xorv256(v[15], v[0]);
    v[12] = xorv256(v[12], v[1]);
    v[13] = xorv256(v[13], v[2]);
    v[14] = xorv256(v[14], v[3]);
    v[15] = rot16_256(v[15]);
    v[12] = rot16_256(v[12]);
    v[13] = rot16_256(v[13]);
    v[14] = rot16_256(v[14]);
    v[10] = addv256(v[10], v[15]);
    v[11] = addv256(v[11], v[12]);
    v[8]  = addv256(v[8], v[13]);
    v[9]  = addv256(v[9], v[14]);
    v[5]  = xorv256(v[5], v[10]);
    v[6]  = xorv256(v[6], v[11]);
    v[7]  = xorv256(v[7], v[8]);
    v[4]  = xorv256(v[4], v[9]);
    v[5]  = rot12_256(v[5]);
    v[6]  = rot12_256(v[6]);
    v[7]  = rot12_256(v[7]);
    v[4]  = rot12_256(v[4]);
    v[0]  = addv256(v[0], m[BLAKE3_MSG_SCHEDULE[r][9]]);
    v[1]  = addv256(v[1], m[BLAKE3_MSG_SCHEDULE[r][11]]);
    v[2]  = addv256(v[2], m[BLAKE3_MSG_SCHEDULE[r][13]]);
    v[3]  = addv256(v[3], m[BLAKE3_MSG_SCHEDULE[r][15]]);
    v[0]  = addv256(v[0], v[5]);
    v[1]  = addv256(v[1], v[6]);
    v[2]  = addv256(v[2], v[7]);
    v[3]  = addv256(v[3], v[4]);
    v[15] = xorv256(v[15], v[0]);
    v[12] = xorv256(v[12], v[1]);
    v[13] = xorv256(v[13], v[2]);
    v[14] = xorv256(v[14], v[3]);
    v[15] = rot8_256(v[15]);
    v[12] = rot8_256(v[12]);
    v[13] = rot8_256(v[13]);
    v[14] = rot8_256(v[14]);
    v[10] = addv256(v[10], v[15]);
    v[11] = addv256(v[11], v[12]);
    v[8]  = addv256(v[8], v[13]);
    v[9]  = addv256(v[9], v[14]);
    v[5]  = xorv256(v[5], v[10]);
    v[6]  = xorv256(v[6], v[11]);
    v[7]  = xorv256(v[7], v[8]);
    v[4]  = xorv256(v[4], v[9]);
    v[5]  = rot7_256(v[5]);
    v[6]  = rot7_256(v[6]);
    v[7]  = rot7_256(v[7]);
    v[4]  = rot7_256(v[4]);
}

// Hash 8 complete 1KB chunks in parallel using AVX2
void BLAKE3_Hash8_AVX2(const byte *const *inputs, const word32 key[8],
                       word64 counter, byte flags, byte *out)
{
    __m256i h_vecs[8];
    __m256i counter_low_vec, counter_high_vec;

    // Initialize state vectors (transposed across 8 chunks)
    for (size_t i = 0; i < 8; i++) {
        h_vecs[i] = set1_256(key[i]);
    }

    // Counter values for each chunk
    counter_low_vec = set8((word32)counter, (word32)(counter + 1),
                           (word32)(counter + 2), (word32)(counter + 3),
                           (word32)(counter + 4), (word32)(counter + 5),
                           (word32)(counter + 6), (word32)(counter + 7));
    counter_high_vec = set8((word32)(counter >> 32), (word32)((counter + 1) >> 32),
                            (word32)((counter + 2) >> 32), (word32)((counter + 3) >> 32),
                            (word32)((counter + 4) >> 32), (word32)((counter + 5) >> 32),
                            (word32)((counter + 6) >> 32), (word32)((counter + 7) >> 32));

    // Process 16 blocks per chunk
    for (size_t block = 0; block < 16; block++) {
        __m256i m_vecs[16];
        transpose_msg_vecs8(inputs, block * BLAKE3_BLOCK_LEN, m_vecs);

        // Determine block flags
        byte block_flags = flags;
        if (block == 0) {
            block_flags |= BLAKE3_CHUNK_START;
        }
        if (block == 15) {
            block_flags |= BLAKE3_CHUNK_END;
        }

        // Set up state
        __m256i v[16];
        v[0] = h_vecs[0];
        v[1] = h_vecs[1];
        v[2] = h_vecs[2];
        v[3] = h_vecs[3];
        v[4] = h_vecs[4];
        v[5] = h_vecs[5];
        v[6] = h_vecs[6];
        v[7] = h_vecs[7];
        v[8] = set1_256(BLAKE3_IV[0]);
        v[9] = set1_256(BLAKE3_IV[1]);
        v[10] = set1_256(BLAKE3_IV[2]);
        v[11] = set1_256(BLAKE3_IV[3]);
        v[12] = counter_low_vec;
        v[13] = counter_high_vec;
        v[14] = set1_256(BLAKE3_BLOCK_LEN);
        v[15] = set1_256(block_flags);

        // 7 rounds
        round_fn8(v, m_vecs, 0);
        round_fn8(v, m_vecs, 1);
        round_fn8(v, m_vecs, 2);
        round_fn8(v, m_vecs, 3);
        round_fn8(v, m_vecs, 4);
        round_fn8(v, m_vecs, 5);
        round_fn8(v, m_vecs, 6);

        // Update chaining values: h = v[:8] ^ v[8:]
        h_vecs[0] = xorv256(v[0], v[8]);
        h_vecs[1] = xorv256(v[1], v[9]);
        h_vecs[2] = xorv256(v[2], v[10]);
        h_vecs[3] = xorv256(v[3], v[11]);
        h_vecs[4] = xorv256(v[4], v[12]);
        h_vecs[5] = xorv256(v[5], v[13]);
        h_vecs[6] = xorv256(v[6], v[14]);
        h_vecs[7] = xorv256(v[7], v[15]);
    }

    // Transpose back and store outputs
    transpose_vecs256(&h_vecs[0], &h_vecs[1], &h_vecs[2], &h_vecs[3],
                      &h_vecs[4], &h_vecs[5], &h_vecs[6], &h_vecs[7]);

    // Store the 8 CVs (each CV is 32 bytes = 8 x 4-byte words)
    STOREU256(&out[0],   h_vecs[0]);
    STOREU256(&out[32],  h_vecs[1]);
    STOREU256(&out[64],  h_vecs[2]);
    STOREU256(&out[96],  h_vecs[3]);
    STOREU256(&out[128], h_vecs[4]);
    STOREU256(&out[160], h_vecs[5]);
    STOREU256(&out[192], h_vecs[6]);
    STOREU256(&out[224], h_vecs[7]);
}

// Hash whole groups of 8 chunks using 8-way parallel AVX2 processing.
// Returns the number of chunks hashed; blake3.cpp passes exactly 8.
size_t BLAKE3_HashMany_AVX2(const byte *input, size_t input_len,
                            const word32 key[8], word64 counter,
                            byte flags, byte *out)
{
    size_t chunks_processed = 0;
    const size_t num_chunks = input_len / BLAKE3_CHUNK_LEN;
    CRYPTOPP_ASSERT(input_len % (8 * BLAKE3_CHUNK_LEN) == 0);

    // Process 8 chunks at a time
    while (chunks_processed + 8 <= num_chunks) {
        const byte *inputs[8] = {
            input + chunks_processed * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 1) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 2) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 3) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 4) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 5) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 6) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 7) * BLAKE3_CHUNK_LEN
        };

        BLAKE3_Hash8_AVX2(inputs, key, counter + chunks_processed, flags,
                          out + chunks_processed * 32);
        chunks_processed += 8;
    }

    return chunks_processed;
}

#endif  // CRYPTOPP_AVX2_AVAILABLE

NAMESPACE_END
