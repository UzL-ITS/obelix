#include "benchmark.h"

extern uint64_t modexp(uint64_t b, uint64_t x, uint64_t n);
[[clang::obelix("extern")]] extern uint64_t OBELIX(modexp)(uint64_t b, uint64_t x, uint64_t n);

int main(void)
{
    uint64_t result = 0;

    MEASUREMENT_BASELINE_START(1000)
    {
        result = modexp(5, 93, 257);
    }
    MEASUREMENT_BASELINE_END()

    fprintf(stderr, "Result: %lu\n", result);

    MEASUREMENT_INSTRUMENTED_START()
    {
        result = OBELIX(modexp)(5, 93, 257);
    }
    MEASUREMENT_INSTRUMENTED_END()

    fprintf(stderr, "Result: %lu\n", result);

    return 0;
}
