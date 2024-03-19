#include "benchmark.h"

void multiply(unsigned int r[][4], unsigned int m1[][4], unsigned int m2[][4]);
[[clang::obelix("extern")]] void OBELIX(multiply)(unsigned int r[][4], unsigned int m1[][4], unsigned int m2[][4]);

int main(void)
{
    unsigned int result[4][4] = {};

    unsigned int mat1[4][4] = {{1, 1, 1, 1},
                    {2, 2, 2, 2},
                    {3, 3, 3, 3},
                    {4, 4, 4, 4}};

    unsigned int mat2[4][4] = {{1, 1, 1, 1},
                    {2, 2, 2, 2},
                    {3, 3, 3, 3},
                    {4, 4, 4, 4}};

    MEASUREMENT_BASELINE_START(100000)
    {
        multiply(result, mat1, mat2); 
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: \n");
    for(int i = 0; i < 4; ++i)
    {
        for(int j = 0; j < 4; ++j)
            fprintf(stderr, "%d ", result[i][j]);
        fprintf(stderr, "\n");
    }

    MEASUREMENT_INSTRUMENTED_START()
    {
        OBELIX(multiply)(result, mat1, mat2);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: \n");
    for(int i = 0; i < 4; ++i)
    {
        for(int j = 0; j < 4; ++j)
            fprintf(stderr, "%d ", result[i][j]);
        fprintf(stderr, "\n");
    }

    return 0;
}
