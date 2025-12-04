// blake3_avx512.cpp - written and placed in the public domain by
//                     Colin Brown.
//
//    This source file uses intrinsics to gain access to AVX512
//    instructions for 16-way parallel chunk hashing. A separate
//    source file is needed because additional CXXFLAGS are required
//    to enable the appropriate instruction sets.
//
//    AVX512 implementation based on the BLAKE3 team's reference at
//    https://github.com/BLAKE3-team/BLAKE3 (public domain/CC0 1.0).

#include <cryptopp/pch.h>
#include <cryptopp/config.h>
#include <cryptopp/misc.h>
#include <cryptopp/blake3.h>

#if (CRYPTOPP_AVX512F_AVAILABLE) && (CRYPTOPP_AVX512VL_AVAILABLE)
# include <immintrin.h>
#endif

// Squash MS LNK4221 and libtool warnings
extern const char BLAKE3_AVX512_FNAME[] = __FILE__;

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

#if (CRYPTOPP_AVX512F_AVAILABLE) && (CRYPTOPP_AVX512VL_AVAILABLE)

// AVX512 helper macros and functions
#define LOADU512(p)    _mm512_loadu_si512((const __m512i *)(const void*)(p))
#define STOREU512(p,r) _mm512_storeu_si512((__m512i *)(void*)(p), r)

inline __m512i addv512(__m512i a, __m512i b) { return _mm512_add_epi32(a, b); }
inline __m512i xorv512(__m512i a, __m512i b) { return _mm512_xor_si512(a, b); }
inline __m512i set1_512(word32 x) { return _mm512_set1_epi32((int)x); }

inline __m512i set16(word32 a, word32 b, word32 c, word32 d,
                     word32 e, word32 f, word32 g, word32 h,
                     word32 i, word32 j, word32 k, word32 l,
                     word32 m, word32 n, word32 o, word32 p) {
    return _mm512_setr_epi32((int)a, (int)b, (int)c, (int)d,
                              (int)e, (int)f, (int)g, (int)h,
                              (int)i, (int)j, (int)k, (int)l,
                              (int)m, (int)n, (int)o, (int)p);
}

// Rotation by 16 bits using native AVX512 rotate instruction
inline __m512i rot16_512(__m512i x) {
    return _mm512_ror_epi32(x, 16);
}

// Rotation by 12 bits using native AVX512 rotate instruction
inline __m512i rot12_512(__m512i x) {
    return _mm512_ror_epi32(x, 12);
}

// Rotation by 8 bits using native AVX512 rotate instruction
inline __m512i rot8_512(__m512i x) {
    return _mm512_ror_epi32(x, 8);
}

// Rotation by 7 bits using native AVX512 rotate instruction
inline __m512i rot7_512(__m512i x) {
    return _mm512_ror_epi32(x, 7);
}

// Load message words from 16 blocks into 16 transposed vectors
// Each output vector contains the same word position from each of 16 chunks
inline void transpose_msg_vecs16(const byte *const *inputs, size_t block_offset,
                                 __m512i out[16])
{
    // Load word i from all 16 inputs
    for (int word = 0; word < 16; word++) {
        size_t byte_offset = block_offset + word * sizeof(word32);
        out[word] = _mm512_setr_epi32(
            *(const int*)&inputs[0][byte_offset],
            *(const int*)&inputs[1][byte_offset],
            *(const int*)&inputs[2][byte_offset],
            *(const int*)&inputs[3][byte_offset],
            *(const int*)&inputs[4][byte_offset],
            *(const int*)&inputs[5][byte_offset],
            *(const int*)&inputs[6][byte_offset],
            *(const int*)&inputs[7][byte_offset],
            *(const int*)&inputs[8][byte_offset],
            *(const int*)&inputs[9][byte_offset],
            *(const int*)&inputs[10][byte_offset],
            *(const int*)&inputs[11][byte_offset],
            *(const int*)&inputs[12][byte_offset],
            *(const int*)&inputs[13][byte_offset],
            *(const int*)&inputs[14][byte_offset],
            *(const int*)&inputs[15][byte_offset]);
    }
}

// Perform one round of BLAKE3 compression on 16 parallel states
inline void round_fn16(__m512i v[16], __m512i m[16], size_t r)
{
    // Column step - first half
    v[0]  = addv512(v[0], m[BLAKE3_MSG_SCHEDULE[r][0]]);
    v[1]  = addv512(v[1], m[BLAKE3_MSG_SCHEDULE[r][2]]);
    v[2]  = addv512(v[2], m[BLAKE3_MSG_SCHEDULE[r][4]]);
    v[3]  = addv512(v[3], m[BLAKE3_MSG_SCHEDULE[r][6]]);
    v[0]  = addv512(v[0], v[4]);
    v[1]  = addv512(v[1], v[5]);
    v[2]  = addv512(v[2], v[6]);
    v[3]  = addv512(v[3], v[7]);
    v[12] = xorv512(v[12], v[0]);
    v[13] = xorv512(v[13], v[1]);
    v[14] = xorv512(v[14], v[2]);
    v[15] = xorv512(v[15], v[3]);
    v[12] = rot16_512(v[12]);
    v[13] = rot16_512(v[13]);
    v[14] = rot16_512(v[14]);
    v[15] = rot16_512(v[15]);
    v[8]  = addv512(v[8], v[12]);
    v[9]  = addv512(v[9], v[13]);
    v[10] = addv512(v[10], v[14]);
    v[11] = addv512(v[11], v[15]);
    v[4]  = xorv512(v[4], v[8]);
    v[5]  = xorv512(v[5], v[9]);
    v[6]  = xorv512(v[6], v[10]);
    v[7]  = xorv512(v[7], v[11]);
    v[4]  = rot12_512(v[4]);
    v[5]  = rot12_512(v[5]);
    v[6]  = rot12_512(v[6]);
    v[7]  = rot12_512(v[7]);

    // Column step - second half
    v[0]  = addv512(v[0], m[BLAKE3_MSG_SCHEDULE[r][1]]);
    v[1]  = addv512(v[1], m[BLAKE3_MSG_SCHEDULE[r][3]]);
    v[2]  = addv512(v[2], m[BLAKE3_MSG_SCHEDULE[r][5]]);
    v[3]  = addv512(v[3], m[BLAKE3_MSG_SCHEDULE[r][7]]);
    v[0]  = addv512(v[0], v[4]);
    v[1]  = addv512(v[1], v[5]);
    v[2]  = addv512(v[2], v[6]);
    v[3]  = addv512(v[3], v[7]);
    v[12] = xorv512(v[12], v[0]);
    v[13] = xorv512(v[13], v[1]);
    v[14] = xorv512(v[14], v[2]);
    v[15] = xorv512(v[15], v[3]);
    v[12] = rot8_512(v[12]);
    v[13] = rot8_512(v[13]);
    v[14] = rot8_512(v[14]);
    v[15] = rot8_512(v[15]);
    v[8]  = addv512(v[8], v[12]);
    v[9]  = addv512(v[9], v[13]);
    v[10] = addv512(v[10], v[14]);
    v[11] = addv512(v[11], v[15]);
    v[4]  = xorv512(v[4], v[8]);
    v[5]  = xorv512(v[5], v[9]);
    v[6]  = xorv512(v[6], v[10]);
    v[7]  = xorv512(v[7], v[11]);
    v[4]  = rot7_512(v[4]);
    v[5]  = rot7_512(v[5]);
    v[6]  = rot7_512(v[6]);
    v[7]  = rot7_512(v[7]);

    // Diagonal step - first half
    v[0]  = addv512(v[0], m[BLAKE3_MSG_SCHEDULE[r][8]]);
    v[1]  = addv512(v[1], m[BLAKE3_MSG_SCHEDULE[r][10]]);
    v[2]  = addv512(v[2], m[BLAKE3_MSG_SCHEDULE[r][12]]);
    v[3]  = addv512(v[3], m[BLAKE3_MSG_SCHEDULE[r][14]]);
    v[0]  = addv512(v[0], v[5]);
    v[1]  = addv512(v[1], v[6]);
    v[2]  = addv512(v[2], v[7]);
    v[3]  = addv512(v[3], v[4]);
    v[15] = xorv512(v[15], v[0]);
    v[12] = xorv512(v[12], v[1]);
    v[13] = xorv512(v[13], v[2]);
    v[14] = xorv512(v[14], v[3]);
    v[15] = rot16_512(v[15]);
    v[12] = rot16_512(v[12]);
    v[13] = rot16_512(v[13]);
    v[14] = rot16_512(v[14]);
    v[10] = addv512(v[10], v[15]);
    v[11] = addv512(v[11], v[12]);
    v[8]  = addv512(v[8], v[13]);
    v[9]  = addv512(v[9], v[14]);
    v[5]  = xorv512(v[5], v[10]);
    v[6]  = xorv512(v[6], v[11]);
    v[7]  = xorv512(v[7], v[8]);
    v[4]  = xorv512(v[4], v[9]);
    v[5]  = rot12_512(v[5]);
    v[6]  = rot12_512(v[6]);
    v[7]  = rot12_512(v[7]);
    v[4]  = rot12_512(v[4]);

    // Diagonal step - second half
    v[0]  = addv512(v[0], m[BLAKE3_MSG_SCHEDULE[r][9]]);
    v[1]  = addv512(v[1], m[BLAKE3_MSG_SCHEDULE[r][11]]);
    v[2]  = addv512(v[2], m[BLAKE3_MSG_SCHEDULE[r][13]]);
    v[3]  = addv512(v[3], m[BLAKE3_MSG_SCHEDULE[r][15]]);
    v[0]  = addv512(v[0], v[5]);
    v[1]  = addv512(v[1], v[6]);
    v[2]  = addv512(v[2], v[7]);
    v[3]  = addv512(v[3], v[4]);
    v[15] = xorv512(v[15], v[0]);
    v[12] = xorv512(v[12], v[1]);
    v[13] = xorv512(v[13], v[2]);
    v[14] = xorv512(v[14], v[3]);
    v[15] = rot8_512(v[15]);
    v[12] = rot8_512(v[12]);
    v[13] = rot8_512(v[13]);
    v[14] = rot8_512(v[14]);
    v[10] = addv512(v[10], v[15]);
    v[11] = addv512(v[11], v[12]);
    v[8]  = addv512(v[8], v[13]);
    v[9]  = addv512(v[9], v[14]);
    v[5]  = xorv512(v[5], v[10]);
    v[6]  = xorv512(v[6], v[11]);
    v[7]  = xorv512(v[7], v[8]);
    v[4]  = xorv512(v[4], v[9]);
    v[5]  = rot7_512(v[5]);
    v[6]  = rot7_512(v[6]);
    v[7]  = rot7_512(v[7]);
    v[4]  = rot7_512(v[4]);
}

// Transpose 16 state vectors back to 16 CVs
// h_vecs[i] contains word i from each of 16 chunks (transposed form)
// We need to output 16 contiguous 32-byte CVs (untransposed)
inline void transpose_vecs16_out(__m512i h_vecs[8], byte *out)
{
    // Use scatter/gather approach or manual extraction
    // For each chunk, we need to extract its CV from all 8 h_vecs
    alignas(64) word32 temp[8][16];

    // Store transposed data to temp buffer
    _mm512_store_si512((__m512i*)temp[0], h_vecs[0]);
    _mm512_store_si512((__m512i*)temp[1], h_vecs[1]);
    _mm512_store_si512((__m512i*)temp[2], h_vecs[2]);
    _mm512_store_si512((__m512i*)temp[3], h_vecs[3]);
    _mm512_store_si512((__m512i*)temp[4], h_vecs[4]);
    _mm512_store_si512((__m512i*)temp[5], h_vecs[5]);
    _mm512_store_si512((__m512i*)temp[6], h_vecs[6]);
    _mm512_store_si512((__m512i*)temp[7], h_vecs[7]);

    // Untranspose: for chunk c, CV = [temp[0][c], temp[1][c], ..., temp[7][c]]
    for (int c = 0; c < 16; c++) {
        word32 *cv_out = (word32*)(out + c * 32);
        cv_out[0] = temp[0][c];
        cv_out[1] = temp[1][c];
        cv_out[2] = temp[2][c];
        cv_out[3] = temp[3][c];
        cv_out[4] = temp[4][c];
        cv_out[5] = temp[5][c];
        cv_out[6] = temp[6][c];
        cv_out[7] = temp[7][c];
    }
}

// Hash 16 complete 1KB chunks in parallel using AVX512
void BLAKE3_Hash16_AVX512(const byte *const *inputs, const word32 key[8],
                          word64 counter, byte flags, byte *out)
{
    __m512i h_vecs[8];
    __m512i counter_low_vec, counter_high_vec;

    // Initialize state vectors (transposed across 16 chunks)
    for (size_t i = 0; i < 8; i++) {
        h_vecs[i] = set1_512(key[i]);
    }

    // Counter values for each chunk
    counter_low_vec = set16(
        (word32)counter, (word32)(counter + 1),
        (word32)(counter + 2), (word32)(counter + 3),
        (word32)(counter + 4), (word32)(counter + 5),
        (word32)(counter + 6), (word32)(counter + 7),
        (word32)(counter + 8), (word32)(counter + 9),
        (word32)(counter + 10), (word32)(counter + 11),
        (word32)(counter + 12), (word32)(counter + 13),
        (word32)(counter + 14), (word32)(counter + 15));

    counter_high_vec = set16(
        (word32)(counter >> 32), (word32)((counter + 1) >> 32),
        (word32)((counter + 2) >> 32), (word32)((counter + 3) >> 32),
        (word32)((counter + 4) >> 32), (word32)((counter + 5) >> 32),
        (word32)((counter + 6) >> 32), (word32)((counter + 7) >> 32),
        (word32)((counter + 8) >> 32), (word32)((counter + 9) >> 32),
        (word32)((counter + 10) >> 32), (word32)((counter + 11) >> 32),
        (word32)((counter + 12) >> 32), (word32)((counter + 13) >> 32),
        (word32)((counter + 14) >> 32), (word32)((counter + 15) >> 32));

    // Process 16 blocks per chunk
    for (size_t block = 0; block < 16; block++) {
        __m512i m_vecs[16];
        transpose_msg_vecs16(inputs, block * BLAKE3_BLOCK_LEN, m_vecs);

        // Determine block flags
        byte block_flags = flags;
        if (block == 0) {
            block_flags |= BLAKE3_CHUNK_START;
        }
        if (block == 15) {
            block_flags |= BLAKE3_CHUNK_END;
        }

        // Set up state
        __m512i v[16];
        v[0] = h_vecs[0];
        v[1] = h_vecs[1];
        v[2] = h_vecs[2];
        v[3] = h_vecs[3];
        v[4] = h_vecs[4];
        v[5] = h_vecs[5];
        v[6] = h_vecs[6];
        v[7] = h_vecs[7];
        v[8] = set1_512(BLAKE3_IV[0]);
        v[9] = set1_512(BLAKE3_IV[1]);
        v[10] = set1_512(BLAKE3_IV[2]);
        v[11] = set1_512(BLAKE3_IV[3]);
        v[12] = counter_low_vec;
        v[13] = counter_high_vec;
        v[14] = set1_512(BLAKE3_BLOCK_LEN);
        v[15] = set1_512(block_flags);

        // 7 rounds
        round_fn16(v, m_vecs, 0);
        round_fn16(v, m_vecs, 1);
        round_fn16(v, m_vecs, 2);
        round_fn16(v, m_vecs, 3);
        round_fn16(v, m_vecs, 4);
        round_fn16(v, m_vecs, 5);
        round_fn16(v, m_vecs, 6);

        // Update chaining values: h = v[:8] ^ v[8:]
        h_vecs[0] = xorv512(v[0], v[8]);
        h_vecs[1] = xorv512(v[1], v[9]);
        h_vecs[2] = xorv512(v[2], v[10]);
        h_vecs[3] = xorv512(v[3], v[11]);
        h_vecs[4] = xorv512(v[4], v[12]);
        h_vecs[5] = xorv512(v[5], v[13]);
        h_vecs[6] = xorv512(v[6], v[14]);
        h_vecs[7] = xorv512(v[7], v[15]);
    }

    // Transpose back and store outputs
    transpose_vecs16_out(h_vecs, out);
}

// Forward declaration of AVX2 fallback
extern void BLAKE3_Hash8_AVX2(const byte *const *inputs, const word32 key[8],
                              word64 counter, byte flags, byte *out);
extern void BLAKE3_Hash4_SSE41(const byte *const *inputs, const word32 key[8],
                               word64 counter, byte flags, byte *out);
extern void BLAKE3_Compress_SSE41(word32 cv[8], const byte block[64],
                                  byte block_len, word64 counter, byte flags);

// Hash multiple chunks using 16-way parallel AVX512 processing
size_t BLAKE3_HashMany_AVX512(const byte *input, size_t input_len,
                              const word32 key[8], word64 counter,
                              byte flags, byte *out)
{
    size_t chunks_processed = 0;
    const size_t num_chunks = input_len / BLAKE3_CHUNK_LEN;

    // Process 16 chunks at a time using AVX512
    while (chunks_processed + 16 <= num_chunks) {
        const byte *inputs[16] = {
            input + chunks_processed * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 1) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 2) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 3) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 4) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 5) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 6) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 7) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 8) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 9) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 10) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 11) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 12) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 13) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 14) * BLAKE3_CHUNK_LEN,
            input + (chunks_processed + 15) * BLAKE3_CHUNK_LEN
        };

        BLAKE3_Hash16_AVX512(inputs, key, counter + chunks_processed, flags,
                             out + chunks_processed * 32);
        chunks_processed += 16;
    }

#if CRYPTOPP_AVX2_AVAILABLE
    // Process remaining 8 chunks with AVX2
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
#endif

#if CRYPTOPP_SSE41_AVAILABLE
    // Process remaining 4 chunks with SSE4.1
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
#endif

    return chunks_processed;
}

#endif  // CRYPTOPP_AVX512F_AVAILABLE && CRYPTOPP_AVX512VL_AVAILABLE

NAMESPACE_END
