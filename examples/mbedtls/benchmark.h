#pragma once

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <time.h>
#define CLOCK CLOCK_MONOTONIC

#define OBELIX(name) name##__obelix

#define MEASUREMENT_BASELINE_START(ROUNDS) \
    struct timespec timeStart, timeEnd;    \
    int rounds = ROUNDS;                   \
    clock_gettime(CLOCK, &timeStart);      \
    for(int r = 0; r < rounds; ++r)         

#define MEASUREMENT_BASELINE_END()                                                                                            \
    clock_gettime(CLOCK, &timeEnd);                                                                                           \
    int64_t baselineDuration = (timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + (timeEnd.tv_nsec - timeStart.tv_nsec) / 1000;  \
    fprintf(stderr, "Time: %*ld ms -> %*.3f us / round\n", 9, baselineDuration / 1000, 9, baselineDuration / (double)rounds);

#define MEASUREMENT_INSTRUMENTED_START()     \
    fprintf(stderr, "\n-------------------------\n"); \
    clock_gettime(CLOCK, &timeStart);        \
    for(int r = 0; r < rounds; ++r)

#define MEASUREMENT_INSTRUMENTED_END()                                                                                                \
    clock_gettime(CLOCK, &timeEnd);                                                                                                   \
    int64_t instrumentedDuration = (timeEnd.tv_sec - timeStart.tv_sec) * 1000000 + (timeEnd.tv_nsec - timeStart.tv_nsec) / 1000;      \
    fprintf(stderr, "Time: %*ld ms -> %*.3f us / round\n", 9, instrumentedDuration / 1000, 9, instrumentedDuration / (double)rounds); \
    fprintf(stderr, "  ---> Overhead: %4.1f\n", (double)instrumentedDuration / baselineDuration);                                     \
    printf("%d %ld %ld %4.1f\n", rounds, baselineDuration, instrumentedDuration, (double)instrumentedDuration / baselineDuration);

inline void dump_bytes(FILE *f, uint8_t *ptr, int len)
{
    for(int i = 0; i < len; ++i)
        fprintf(f, "%02x ", ptr[i]);
    fprintf(f, "\n");
}