#include <stdint.h>

// Example from https://github.com/adilahmad17/Obfuscuro/blob/master/eval/matmul/Enclave.cpp
// TODO We swapped indexes when writing to `res`, to prevent the compiler from inserting
// a `memcpy`. Actually this should be handled by calling a secure version of memcpy, while
// still allowing the compiler to fully optimize away the call.
static unsigned int res[4][4] = {
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0}
};

// Multiplies two 4x4 matrices.
[[clang::obelix]] void multiply(unsigned int r[][4], unsigned int m1[][4], unsigned int m2[][4])
{
    unsigned int i, j, k;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            res[j][i] = 0;
            for (k = 0; k < 4; k++)
                res[j][i] = res[j][i] + m1[i][k]*m2[k][j];
        }
    }

    for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
        r[i][j] = res[j][i];
}

[[clang::noinline]] uint64_t modexp_sq(uint64_t x) {
    return x * x;
}

[[clang::noinline]] uint64_t modexp_sqmul(uint64_t x, uint64_t m) {
    return x * x * m;
}

// Computes b^x mod n through modular exponentiation. Uses subroutines.
[[clang::obelix]] uint64_t modexp(uint64_t b, uint64_t x, uint64_t n)
{
    uint64_t result = 1;

    for(int i = 63; i >= 0; --i)
    {
        if((unsigned int)x & (1u << i))
        {
            result = modexp_sqmul(result, b);
        }
        else
        {
            result = modexp_sq(result);
        }

        result = result % n;
    }

    return result;
}
