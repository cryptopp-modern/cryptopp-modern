#include <stdint.h>
#if (CRYPTOPP_ARM_NEON_HEADER)
# include <arm_neon.h>
#endif

// Keep sync'd with arm_simd.h
#include <cryptopp/arm_simd.h>

int main(int argc, char* argv[])
{
    // SHA3 intrinsics are merely ARMv8.2 instructions.
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics
    uint64x2_t x={0}, y={1}, z={2};
    x=VEOR3(x,y,z);
    x=VXAR<6>(x,z);
    x=VRAX1(x,z);

    // Use the result. Unused inline assembly is removed when optimizing.
    return (int)(vgetq_lane_u64(x,0) & 1);
}
