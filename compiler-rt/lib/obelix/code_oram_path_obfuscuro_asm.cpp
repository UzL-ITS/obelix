#include "sanitizer_common/sanitizer_common.h"
#include <stdint.h>

using namespace __sanitizer;

// Moved to other file to prevent GCC from doing broken optimizations

/* implementation of cmov */
uint64_t cmov(uint64_t val1, uint64_t test, uint64_t val2) {
uint64_t result;
__asm__ volatile ( "mov %1, %0;"    // move t_val -> result
                   "test %2, %2;"   // test value of pred?
                   "cmove %3, %0;"  // cmov on the test value?
    : "=&r" (result)
    : "r" (val1), "r" (test), "r" (val2)
    : "cc"
    );
return result;
}

/* implementation of cmov to memcpy */
void cmov_memory(char* addr1, char* addr2, uint64_t size, uint32_t test) {
  if(size%8 != 0)
  {
    Printf("size : %lu\n", size);
  }
  CHECK(size%8 == 0);
  size = size/8;
  __asm__ volatile (
      "mov %0, %%rsi;"            // addr1
      "mov %1, %%rdi;"            // addr2
      "_cmov_memory_repeat_%=:"
      "mov (%%rsi), %%rcx;"
      "mov (%%rdi), %%rdx;"
      "test %2, %2;"              // test value to cmov
      "cmove %%rdx, %%rcx;"       // cmov to copy from addr (2->1)
      "mov %%rcx, (%%rsi);"       // mov the value of addr1 -> mem
      "add $8, %%rsi;"
      "add $8, %%rdi;"
      "dec %3;"
      "jnz _cmov_memory_repeat_%=;"
      :
      : "m" (addr1), "m" (addr2), "r" (test), "r" (size)
      : "rsi", "rdi", "rcx", "rdx", "cc"
      );
}

/* get a random number (32-bit) */
int get_rand32(unsigned int* rand) {
  unsigned char err;
  asm volatile("rdrand %0 ; setc %1"
      : "=&r" (*rand), "=qm" (err));
  return (int) err;
}