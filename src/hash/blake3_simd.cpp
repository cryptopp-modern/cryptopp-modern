// blake3_simd.cpp - written and placed in the public domain by
//                   Colin Brown.
//
//    This source file uses intrinsics to gain access to SSE4.1 and
//    ARM NEON instructions. A separate source file is needed because
//    additional CXXFLAGS are required to enable the appropriate
//    instruction sets in some build configurations.
//
//    SSE4.1 implementation based on the BLAKE3 team's reference at
//    https://github.com/BLAKE3-team/BLAKE3 (public domain).

#include <cryptopp/pch.h>
#include <cryptopp/config.h>
#include <cryptopp/misc.h>
#include <cryptopp/blake3.h>

// Uncomment for benchmarking C++ against SSE4.1 or NEON.
// Do so in both blake3.cpp and blake3_simd.cpp.
// #undef CRYPTOPP_SSE41_AVAILABLE
// #undef CRYPTOPP_ARM_NEON_AVAILABLE

#if (CRYPTOPP_SSE41_AVAILABLE)
# include <emmintrin.h>
# include <tmmintrin.h>
# include <smmintrin.h>
#endif

#if (CRYPTOPP_AVX2_AVAILABLE)
# include <immintrin.h>
#endif

#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

#if (CRYPTOPP_ARM_ACLE_HEADER)
# include <stdint.h>
# include <arm_acle.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char BLAKE3_SIMD_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

// BLAKE3 IV - same as SHA-256 (aligned in blake3.cpp)
extern const word32 BLAKE3_IV[8];

// Message schedule for BLAKE3 - 7 rounds
extern const byte BLAKE3_MSG_SCHEDULE[7][16];

// BLAKE3 constants
static const size_t BLAKE3_BLOCK_LEN = 64;
static const size_t BLAKE3_CHUNK_LEN = 1024;
static const byte BLAKE3_CHUNK_START = 1;
static const byte BLAKE3_CHUNK_END = 2;

#if CRYPTOPP_SSE41_AVAILABLE

// SSE4.1 helper macros and functions
#define LOADU(p)    _mm_loadu_si128((const __m128i *)(const void*)(p))
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(void*)(p), r)

inline __m128i addv(__m128i a, __m128i b) { return _mm_add_epi32(a, b); }
inline __m128i xorv(__m128i a, __m128i b) { return _mm_xor_si128(a, b); }
inline __m128i set1(word32 x) { return _mm_set1_epi32((int)x); }

inline __m128i set4(word32 a, word32 b, word32 c, word32 d) {
    return _mm_setr_epi32((int)a, (int)b, (int)c, (int)d);
}

// Rotation by 16 bits using byte shuffle (SSE4.1)
inline __m128i rot16(__m128i x) {
    return _mm_shuffle_epi8(x,
        _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
}

// Rotation by 12 bits using shift and OR
inline __m128i rot12(__m128i x) {
    return xorv(_mm_srli_epi32(x, 12), _mm_slli_epi32(x, 20));
}

// Rotation by 8 bits using byte shuffle (SSE4.1)
inline __m128i rot8(__m128i x) {
    return _mm_shuffle_epi8(x,
        _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1));
}

// Rotation by 7 bits using shift and OR
inline __m128i rot7(__m128i x) {
    return xorv(_mm_srli_epi32(x, 7), _mm_slli_epi32(x, 25));
}

// First half of G function (add message, mix, rotate 16, mix, rotate 12)
inline void g1(__m128i *row0, __m128i *row1, __m128i *row2, __m128i *row3,
               __m128i m) {
    *row0 = addv(addv(*row0, m), *row1);
    *row3 = xorv(*row3, *row0);
    *row3 = rot16(*row3);
    *row2 = addv(*row2, *row3);
    *row1 = xorv(*row1, *row2);
    *row1 = rot12(*row1);
}

// Second half of G function (add message, mix, rotate 8, mix, rotate 7)
inline void g2(__m128i *row0, __m128i *row1, __m128i *row2, __m128i *row3,
               __m128i m) {
    *row0 = addv(addv(*row0, m), *row1);
    *row3 = xorv(*row3, *row0);
    *row3 = rot8(*row3);
    *row2 = addv(*row2, *row3);
    *row1 = xorv(*row1, *row2);
    *row1 = rot7(*row1);
}

// Diagonalize the state matrix for diagonal mixing
inline void diagonalize(__m128i *row0, __m128i *row2, __m128i *row3) {
    *row0 = _mm_shuffle_epi32(*row0, _MM_SHUFFLE(2, 1, 0, 3));
    *row3 = _mm_shuffle_epi32(*row3, _MM_SHUFFLE(1, 0, 3, 2));
    *row2 = _mm_shuffle_epi32(*row2, _MM_SHUFFLE(0, 3, 2, 1));
}

// Undiagonalize the state matrix back to column form
inline void undiagonalize(__m128i *row0, __m128i *row2, __m128i *row3) {
    *row0 = _mm_shuffle_epi32(*row0, _MM_SHUFFLE(0, 3, 2, 1));
    *row3 = _mm_shuffle_epi32(*row3, _MM_SHUFFLE(1, 0, 3, 2));
    *row2 = _mm_shuffle_epi32(*row2, _MM_SHUFFLE(2, 1, 0, 3));
}

// Shuffle helper for message word selection
#define _mm_shuffle_ps2(a, b, c) \
    (_mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), (c))))

// Core compression - prepares state and runs 7 rounds
inline void compress_pre(__m128i rows[4], const word32 cv[8],
                         const byte block[64], byte block_len,
                         word64 counter, byte flags)
{
    rows[0] = LOADU(&cv[0]);
    rows[1] = LOADU(&cv[4]);
    rows[2] = set4(BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3]);
    rows[3] = set4((word32)counter, (word32)(counter >> 32),
                   (word32)block_len, (word32)flags);

    __m128i m0 = LOADU(&block[0]);
    __m128i m1 = LOADU(&block[16]);
    __m128i m2 = LOADU(&block[32]);
    __m128i m3 = LOADU(&block[48]);

    __m128i t0, t1, t2, t3, tt;

    // Round 1
    t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(2, 0, 2, 0));
    g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
    t1 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 3, 1));
    g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
    diagonalize(&rows[0], &rows[2], &rows[3]);
    t2 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(2, 0, 2, 0));
    t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 0, 3));
    g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
    t3 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 1, 3, 1));
    t3 = _mm_shuffle_epi32(t3, _MM_SHUFFLE(2, 1, 0, 3));
    g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
    undiagonalize(&rows[0], &rows[2], &rows[3]);
    m0 = t0;
    m1 = t1;
    m2 = t2;
    m3 = t3;

    // Rounds 2-7
    for (int round = 0; round < 6; round++) {
        t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
        t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
        g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
        tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
        t1 = _mm_blend_epi16(tt, t1, 0xCC);
        g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = _mm_unpacklo_epi64(m3, m1);
        tt = _mm_blend_epi16(t2, m2, 0xC0);
        t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
        g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = _mm_unpackhi_epi32(m1, m3);
        tt = _mm_unpacklo_epi32(m2, t3);
        t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
        g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;
    }
}

void BLAKE3_Compress_SSE41(word32 cv[8], const byte block[64],
                           byte block_len, word64 counter, byte flags)
{
    __m128i rows[4];
    compress_pre(rows, cv, block, block_len, counter, flags);
    STOREU(&cv[0], xorv(rows[0], rows[2]));
    STOREU(&cv[4], xorv(rows[1], rows[3]));
}

void BLAKE3_Compress_XOF_SSE41(const word32 cv[8], const byte block[64],
                               byte block_len, word64 counter, byte flags,
                               byte out[64])
{
    __m128i rows[4];
    compress_pre(rows, cv, block, block_len, counter, flags);
    STOREU(&out[0], xorv(rows[0], rows[2]));
    STOREU(&out[16], xorv(rows[1], rows[3]));
    STOREU(&out[32], xorv(rows[2], LOADU(&cv[0])));
    STOREU(&out[48], xorv(rows[3], LOADU(&cv[4])));
}

// ============================================================================
// 4-way parallel chunk hashing (SSE4.1)
// ============================================================================
// This processes 4 independent chunks simultaneously, with each SIMD lane
// handling one chunk. The key insight is that BLAKE3 chunks are independent
// until they're combined in the tree, so we can hash them in parallel.

// Transpose from 4x4 matrix of 32-bit words
inline void transpose_vecs(__m128i *a, __m128i *b, __m128i *c, __m128i *d)
{
    __m128i t0 = _mm_unpacklo_epi32(*a, *b);
    __m128i t1 = _mm_unpackhi_epi32(*a, *b);
    __m128i t2 = _mm_unpacklo_epi32(*c, *d);
    __m128i t3 = _mm_unpackhi_epi32(*c, *d);
    *a = _mm_unpacklo_epi64(t0, t2);
    *b = _mm_unpackhi_epi64(t0, t2);
    *c = _mm_unpacklo_epi64(t1, t3);
    *d = _mm_unpackhi_epi64(t1, t3);
}

// Load and transpose message words from 4 blocks into 16 transposed vectors
inline void transpose_msg_vecs4(const byte *const *inputs, size_t block_offset,
                                __m128i out[16])
{
    out[0]  = LOADU(&inputs[0][block_offset + 0 * sizeof(__m128i)]);
    out[1]  = LOADU(&inputs[1][block_offset + 0 * sizeof(__m128i)]);
    out[2]  = LOADU(&inputs[2][block_offset + 0 * sizeof(__m128i)]);
    out[3]  = LOADU(&inputs[3][block_offset + 0 * sizeof(__m128i)]);
    out[4]  = LOADU(&inputs[0][block_offset + 1 * sizeof(__m128i)]);
    out[5]  = LOADU(&inputs[1][block_offset + 1 * sizeof(__m128i)]);
    out[6]  = LOADU(&inputs[2][block_offset + 1 * sizeof(__m128i)]);
    out[7]  = LOADU(&inputs[3][block_offset + 1 * sizeof(__m128i)]);
    out[8]  = LOADU(&inputs[0][block_offset + 2 * sizeof(__m128i)]);
    out[9]  = LOADU(&inputs[1][block_offset + 2 * sizeof(__m128i)]);
    out[10] = LOADU(&inputs[2][block_offset + 2 * sizeof(__m128i)]);
    out[11] = LOADU(&inputs[3][block_offset + 2 * sizeof(__m128i)]);
    out[12] = LOADU(&inputs[0][block_offset + 3 * sizeof(__m128i)]);
    out[13] = LOADU(&inputs[1][block_offset + 3 * sizeof(__m128i)]);
    out[14] = LOADU(&inputs[2][block_offset + 3 * sizeof(__m128i)]);
    out[15] = LOADU(&inputs[3][block_offset + 3 * sizeof(__m128i)]);

    // Transpose each group of 4 vectors
    transpose_vecs(&out[0], &out[1], &out[2], &out[3]);
    transpose_vecs(&out[4], &out[5], &out[6], &out[7]);
    transpose_vecs(&out[8], &out[9], &out[10], &out[11]);
    transpose_vecs(&out[12], &out[13], &out[14], &out[15]);
}

// Perform one round of BLAKE3 compression on 4 parallel states
inline void round_fn4(__m128i v[16], __m128i m[16], size_t r)
{
    __m128i t0, t1;
    v[0]  = addv(v[0], m[BLAKE3_MSG_SCHEDULE[r][0]]);
    v[1]  = addv(v[1], m[BLAKE3_MSG_SCHEDULE[r][2]]);
    v[2]  = addv(v[2], m[BLAKE3_MSG_SCHEDULE[r][4]]);
    v[3]  = addv(v[3], m[BLAKE3_MSG_SCHEDULE[r][6]]);
    v[0]  = addv(v[0], v[4]);
    v[1]  = addv(v[1], v[5]);
    v[2]  = addv(v[2], v[6]);
    v[3]  = addv(v[3], v[7]);
    v[12] = xorv(v[12], v[0]);
    v[13] = xorv(v[13], v[1]);
    v[14] = xorv(v[14], v[2]);
    v[15] = xorv(v[15], v[3]);
    v[12] = rot16(v[12]);
    v[13] = rot16(v[13]);
    v[14] = rot16(v[14]);
    v[15] = rot16(v[15]);
    v[8]  = addv(v[8], v[12]);
    v[9]  = addv(v[9], v[13]);
    v[10] = addv(v[10], v[14]);
    v[11] = addv(v[11], v[15]);
    v[4]  = xorv(v[4], v[8]);
    v[5]  = xorv(v[5], v[9]);
    v[6]  = xorv(v[6], v[10]);
    v[7]  = xorv(v[7], v[11]);
    v[4]  = rot12(v[4]);
    v[5]  = rot12(v[5]);
    v[6]  = rot12(v[6]);
    v[7]  = rot12(v[7]);
    v[0]  = addv(v[0], m[BLAKE3_MSG_SCHEDULE[r][1]]);
    v[1]  = addv(v[1], m[BLAKE3_MSG_SCHEDULE[r][3]]);
    v[2]  = addv(v[2], m[BLAKE3_MSG_SCHEDULE[r][5]]);
    v[3]  = addv(v[3], m[BLAKE3_MSG_SCHEDULE[r][7]]);
    v[0]  = addv(v[0], v[4]);
    v[1]  = addv(v[1], v[5]);
    v[2]  = addv(v[2], v[6]);
    v[3]  = addv(v[3], v[7]);
    v[12] = xorv(v[12], v[0]);
    v[13] = xorv(v[13], v[1]);
    v[14] = xorv(v[14], v[2]);
    v[15] = xorv(v[15], v[3]);
    v[12] = rot8(v[12]);
    v[13] = rot8(v[13]);
    v[14] = rot8(v[14]);
    v[15] = rot8(v[15]);
    v[8]  = addv(v[8], v[12]);
    v[9]  = addv(v[9], v[13]);
    v[10] = addv(v[10], v[14]);
    v[11] = addv(v[11], v[15]);
    v[4]  = xorv(v[4], v[8]);
    v[5]  = xorv(v[5], v[9]);
    v[6]  = xorv(v[6], v[10]);
    v[7]  = xorv(v[7], v[11]);
    v[4]  = rot7(v[4]);
    v[5]  = rot7(v[5]);
    v[6]  = rot7(v[6]);
    v[7]  = rot7(v[7]);

    v[0]  = addv(v[0], m[BLAKE3_MSG_SCHEDULE[r][8]]);
    v[1]  = addv(v[1], m[BLAKE3_MSG_SCHEDULE[r][10]]);
    v[2]  = addv(v[2], m[BLAKE3_MSG_SCHEDULE[r][12]]);
    v[3]  = addv(v[3], m[BLAKE3_MSG_SCHEDULE[r][14]]);
    v[0]  = addv(v[0], v[5]);
    v[1]  = addv(v[1], v[6]);
    v[2]  = addv(v[2], v[7]);
    v[3]  = addv(v[3], v[4]);
    v[15] = xorv(v[15], v[0]);
    v[12] = xorv(v[12], v[1]);
    v[13] = xorv(v[13], v[2]);
    v[14] = xorv(v[14], v[3]);
    v[15] = rot16(v[15]);
    v[12] = rot16(v[12]);
    v[13] = rot16(v[13]);
    v[14] = rot16(v[14]);
    v[10] = addv(v[10], v[15]);
    v[11] = addv(v[11], v[12]);
    v[8]  = addv(v[8], v[13]);
    v[9]  = addv(v[9], v[14]);
    v[5]  = xorv(v[5], v[10]);
    v[6]  = xorv(v[6], v[11]);
    v[7]  = xorv(v[7], v[8]);
    v[4]  = xorv(v[4], v[9]);
    v[5]  = rot12(v[5]);
    v[6]  = rot12(v[6]);
    v[7]  = rot12(v[7]);
    v[4]  = rot12(v[4]);
    v[0]  = addv(v[0], m[BLAKE3_MSG_SCHEDULE[r][9]]);
    v[1]  = addv(v[1], m[BLAKE3_MSG_SCHEDULE[r][11]]);
    v[2]  = addv(v[2], m[BLAKE3_MSG_SCHEDULE[r][13]]);
    v[3]  = addv(v[3], m[BLAKE3_MSG_SCHEDULE[r][15]]);
    v[0]  = addv(v[0], v[5]);
    v[1]  = addv(v[1], v[6]);
    v[2]  = addv(v[2], v[7]);
    v[3]  = addv(v[3], v[4]);
    v[15] = xorv(v[15], v[0]);
    v[12] = xorv(v[12], v[1]);
    v[13] = xorv(v[13], v[2]);
    v[14] = xorv(v[14], v[3]);
    v[15] = rot8(v[15]);
    v[12] = rot8(v[12]);
    v[13] = rot8(v[13]);
    v[14] = rot8(v[14]);
    v[10] = addv(v[10], v[15]);
    v[11] = addv(v[11], v[12]);
    v[8]  = addv(v[8], v[13]);
    v[9]  = addv(v[9], v[14]);
    v[5]  = xorv(v[5], v[10]);
    v[6]  = xorv(v[6], v[11]);
    v[7]  = xorv(v[7], v[8]);
    v[4]  = xorv(v[4], v[9]);
    v[5]  = rot7(v[5]);
    v[6]  = rot7(v[6]);
    v[7]  = rot7(v[7]);
    v[4]  = rot7(v[4]);
}

// Hash 4 complete 1KB chunks in parallel
// inputs: array of 4 pointers to 1024-byte chunks
// key: the key/IV to use (8 words)
// counter: starting chunk counter (will be incremented for each chunk)
// flags: BLAKE3 flags
// out: output buffer for 4 x 32-byte chaining values (128 bytes total)
void BLAKE3_Hash4_SSE41(const byte *const *inputs, const word32 key[8],
                        word64 counter, byte flags, byte *out)
{
    CRYPTOPP_ALIGN_DATA(16) __m128i h_vecs[8];
    CRYPTOPP_ALIGN_DATA(16) __m128i counter_low_vec, counter_high_vec;

    // Initialize state vectors (transposed across 4 chunks)
    // Each lane holds the corresponding word from a different chunk
    for (size_t i = 0; i < 8; i++) {
        h_vecs[i] = set1(key[i]);
    }

    // Counter values for each chunk
    counter_low_vec = set4((word32)counter, (word32)(counter + 1),
                           (word32)(counter + 2), (word32)(counter + 3));
    counter_high_vec = set4((word32)(counter >> 32), (word32)((counter + 1) >> 32),
                            (word32)((counter + 2) >> 32), (word32)((counter + 3) >> 32));

    // Process 16 blocks per chunk
    for (size_t block = 0; block < 16; block++) {
        CRYPTOPP_ALIGN_DATA(16) __m128i m_vecs[16];
        transpose_msg_vecs4(inputs, block * BLAKE3_BLOCK_LEN, m_vecs);

        // Determine block flags
        byte block_flags = flags;
        if (block == 0) {
            block_flags |= BLAKE3_CHUNK_START;
        }
        if (block == 15) {
            block_flags |= BLAKE3_CHUNK_END;
        }

        // Set up state
        CRYPTOPP_ALIGN_DATA(16) __m128i v[16];
        v[0] = h_vecs[0];
        v[1] = h_vecs[1];
        v[2] = h_vecs[2];
        v[3] = h_vecs[3];
        v[4] = h_vecs[4];
        v[5] = h_vecs[5];
        v[6] = h_vecs[6];
        v[7] = h_vecs[7];
        v[8] = set1(BLAKE3_IV[0]);
        v[9] = set1(BLAKE3_IV[1]);
        v[10] = set1(BLAKE3_IV[2]);
        v[11] = set1(BLAKE3_IV[3]);
        v[12] = counter_low_vec;
        v[13] = counter_high_vec;
        v[14] = set1(BLAKE3_BLOCK_LEN);
        v[15] = set1(block_flags);

        // 7 rounds
        round_fn4(v, m_vecs, 0);
        round_fn4(v, m_vecs, 1);
        round_fn4(v, m_vecs, 2);
        round_fn4(v, m_vecs, 3);
        round_fn4(v, m_vecs, 4);
        round_fn4(v, m_vecs, 5);
        round_fn4(v, m_vecs, 6);

        // Update chaining values: h = v[:8] ^ v[8:]
        h_vecs[0] = xorv(v[0], v[8]);
        h_vecs[1] = xorv(v[1], v[9]);
        h_vecs[2] = xorv(v[2], v[10]);
        h_vecs[3] = xorv(v[3], v[11]);
        h_vecs[4] = xorv(v[4], v[12]);
        h_vecs[5] = xorv(v[5], v[13]);
        h_vecs[6] = xorv(v[6], v[14]);
        h_vecs[7] = xorv(v[7], v[15]);
    }

    // Transpose back and store outputs
    // h_vecs[i] contains word i from each of the 4 chunks
    // We need to output 4 contiguous 32-byte CVs
    transpose_vecs(&h_vecs[0], &h_vecs[1], &h_vecs[2], &h_vecs[3]);
    transpose_vecs(&h_vecs[4], &h_vecs[5], &h_vecs[6], &h_vecs[7]);

    // Store the 4 CVs
    STOREU(&out[0],  h_vecs[0]);
    STOREU(&out[16], h_vecs[4]);
    STOREU(&out[32], h_vecs[1]);
    STOREU(&out[48], h_vecs[5]);
    STOREU(&out[64], h_vecs[2]);
    STOREU(&out[80], h_vecs[6]);
    STOREU(&out[96], h_vecs[3]);
    STOREU(&out[112], h_vecs[7]);
}

// Hash multiple chunks using 4-way parallel processing
// Returns the number of chunks processed
size_t BLAKE3_HashMany_SSE41(const byte *input, size_t input_len,
                             const word32 key[8], word64 counter,
                             byte flags, byte *out)
{
    size_t chunks_processed = 0;
    const size_t num_chunks = input_len / BLAKE3_CHUNK_LEN;

    // Process 4 chunks at a time using SIMD
    while (chunks_processed + 4 <= num_chunks) {
        const byte *inputs[4] = {
            input + chunks_processed * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 1) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 2) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 3) * BLAKE3_CHUNK_LEN
        };

        BLAKE3_Hash4_SSE41(inputs, key, counter + chunks_processed, flags,
                           out + chunks_processed * 32);
        chunks_processed += 4;
    }

    // Process remaining chunks one at a time (fallback)
    while (chunks_processed < num_chunks) {
        const byte *chunk_input = input + chunks_processed * BLAKE3_CHUNK_LEN;
        word32 cv[8];
        std::memcpy(cv, key, 32);

        // Process all 16 blocks in the chunk
        for (size_t block = 0; block < 16; block++) {
            byte block_flags = flags;
            if (block == 0) block_flags |= BLAKE3_CHUNK_START;
            if (block == 15) block_flags |= BLAKE3_CHUNK_END;

            BLAKE3_Compress_SSE41(cv, chunk_input + block * BLAKE3_BLOCK_LEN,
                                  BLAKE3_BLOCK_LEN, counter + chunks_processed,
                                  block_flags);
        }

        std::memcpy(out + chunks_processed * 32, cv, 32);
        chunks_processed++;
    }

    return chunks_processed;
}

#endif  // CRYPTOPP_SSE41_AVAILABLE

// ============================================================================
// AVX2 Implementation - 8-way parallel chunk hashing
// ============================================================================

#if CRYPTOPP_AVX2_AVAILABLE

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

// Hash multiple chunks using 8-way parallel AVX2 processing
size_t BLAKE3_HashMany_AVX2(const byte *input, size_t input_len,
                            const word32 key[8], word64 counter,
                            byte flags, byte *out)
{
    size_t chunks_processed = 0;
    const size_t num_chunks = input_len / BLAKE3_CHUNK_LEN;

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

    // Process remaining 4 chunks with SSE4.1 if available
    while (chunks_processed + 4 <= num_chunks) {
        const byte *inputs[4] = {
            input + chunks_processed * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 1) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 2) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 3) * BLAKE3_CHUNK_LEN
        };

        BLAKE3_Hash4_SSE41(inputs, key, counter + chunks_processed, flags,
                           out + chunks_processed * 32);
        chunks_processed += 4;
    }

    // Process remaining chunks one at a time
    while (chunks_processed < num_chunks) {
        const byte *chunk_input = input + chunks_processed * BLAKE3_CHUNK_LEN;
        word32 cv[8];
        std::memcpy(cv, key, 32);

        for (size_t block = 0; block < 16; block++) {
            byte block_flags = flags;
            if (block == 0) block_flags |= BLAKE3_CHUNK_START;
            if (block == 15) block_flags |= BLAKE3_CHUNK_END;

            BLAKE3_Compress_SSE41(cv, chunk_input + block * BLAKE3_BLOCK_LEN,
                                  BLAKE3_BLOCK_LEN, counter + chunks_processed,
                                  block_flags);
        }

        std::memcpy(out + chunks_processed * 32, cv, 32);
        chunks_processed++;
    }

    return chunks_processed;
}

#endif  // CRYPTOPP_AVX2_AVAILABLE

#if CRYPTOPP_ARM_NEON_AVAILABLE

// ARM NEON helper functions
inline uint32x4_t addv_neon(uint32x4_t a, uint32x4_t b) {
    return vaddq_u32(a, b);
}

inline uint32x4_t xorv_neon(uint32x4_t a, uint32x4_t b) {
    return veorq_u32(a, b);
}

inline uint32x4_t set1_neon(word32 x) {
    return vdupq_n_u32(x);
}

// Rotation by 16 bits
inline uint32x4_t rot16_neon(uint32x4_t x) {
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
}

// Rotation by 12 bits
inline uint32x4_t rot12_neon(uint32x4_t x) {
    return veorq_u32(vshrq_n_u32(x, 12), vshlq_n_u32(x, 20));
}

// Rotation by 8 bits
inline uint32x4_t rot8_neon(uint32x4_t x) {
    return vreinterpretq_u32_u8(vqtbl1q_u8(
        vreinterpretq_u8_u32(x),
        (uint8x16_t){1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12}));
}

// Rotation by 7 bits
inline uint32x4_t rot7_neon(uint32x4_t x) {
    return veorq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 25));
}

// G function first half for NEON
inline void g1_neon(uint32x4_t *row0, uint32x4_t *row1, uint32x4_t *row2,
                    uint32x4_t *row3, uint32x4_t m) {
    *row0 = addv_neon(addv_neon(*row0, m), *row1);
    *row3 = xorv_neon(*row3, *row0);
    *row3 = rot16_neon(*row3);
    *row2 = addv_neon(*row2, *row3);
    *row1 = xorv_neon(*row1, *row2);
    *row1 = rot12_neon(*row1);
}

// G function second half for NEON
inline void g2_neon(uint32x4_t *row0, uint32x4_t *row1, uint32x4_t *row2,
                    uint32x4_t *row3, uint32x4_t m) {
    *row0 = addv_neon(addv_neon(*row0, m), *row1);
    *row3 = xorv_neon(*row3, *row0);
    *row3 = rot8_neon(*row3);
    *row2 = addv_neon(*row2, *row3);
    *row1 = xorv_neon(*row1, *row2);
    *row1 = rot7_neon(*row1);
}

// Diagonalize for NEON
inline void diagonalize_neon(uint32x4_t *row0, uint32x4_t *row2, uint32x4_t *row3) {
    *row0 = vextq_u32(*row0, *row0, 3);
    *row3 = vextq_u32(*row3, *row3, 2);
    *row2 = vextq_u32(*row2, *row2, 1);
}

// Undiagonalize for NEON
inline void undiagonalize_neon(uint32x4_t *row0, uint32x4_t *row2, uint32x4_t *row3) {
    *row0 = vextq_u32(*row0, *row0, 1);
    *row3 = vextq_u32(*row3, *row3, 2);
    *row2 = vextq_u32(*row2, *row2, 3);
}

void BLAKE3_Compress_NEON(word32 cv[8], const byte block[64],
                          byte block_len, word64 counter, byte flags)
{
    uint32x4_t rows[4];

    // Load chaining value
    rows[0] = vld1q_u32(&cv[0]);
    rows[1] = vld1q_u32(&cv[4]);

    // Set up rows 2 and 3
    uint32_t row2_vals[4] = {BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3]};
    uint32_t row3_vals[4] = {(uint32_t)counter, (uint32_t)(counter >> 32),
                             (uint32_t)block_len, (uint32_t)flags};
    rows[2] = vld1q_u32(row2_vals);
    rows[3] = vld1q_u32(row3_vals);

    // Load message block
    uint32x4_t m[4];
    m[0] = vreinterpretq_u32_u8(vld1q_u8(&block[0]));
    m[1] = vreinterpretq_u32_u8(vld1q_u8(&block[16]));
    m[2] = vreinterpretq_u32_u8(vld1q_u8(&block[32]));
    m[3] = vreinterpretq_u32_u8(vld1q_u8(&block[48]));

    // 7 rounds of mixing
    for (size_t round = 0; round < 7; round++) {
        // Load message words according to schedule
        uint32_t msg_words[16];
        for (int i = 0; i < 16; i++) {
            size_t idx = BLAKE3_MSG_SCHEDULE[round][i];
            msg_words[i] = vgetq_lane_u32(m[idx / 4], idx % 4);
        }

        // Column mixing
        uint32x4_t mx, my;
        uint32_t mx_vals[4] = {msg_words[0], msg_words[2], msg_words[4], msg_words[6]};
        uint32_t my_vals[4] = {msg_words[1], msg_words[3], msg_words[5], msg_words[7]};
        mx = vld1q_u32(mx_vals);
        my = vld1q_u32(my_vals);
        g1_neon(&rows[0], &rows[1], &rows[2], &rows[3], mx);
        g2_neon(&rows[0], &rows[1], &rows[2], &rows[3], my);

        // Diagonal mixing
        diagonalize_neon(&rows[0], &rows[2], &rows[3]);
        uint32_t dx_vals[4] = {msg_words[8], msg_words[10], msg_words[12], msg_words[14]};
        uint32_t dy_vals[4] = {msg_words[9], msg_words[11], msg_words[13], msg_words[15]};
        mx = vld1q_u32(dx_vals);
        my = vld1q_u32(dy_vals);
        g1_neon(&rows[0], &rows[1], &rows[2], &rows[3], mx);
        g2_neon(&rows[0], &rows[1], &rows[2], &rows[3], my);
        undiagonalize_neon(&rows[0], &rows[2], &rows[3]);
    }

    // Output: XOR state with input CV
    vst1q_u32(&cv[0], xorv_neon(rows[0], rows[2]));
    vst1q_u32(&cv[4], xorv_neon(rows[1], rows[3]));
}

#endif  // CRYPTOPP_ARM_NEON_AVAILABLE

NAMESPACE_END
