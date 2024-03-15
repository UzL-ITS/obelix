#include "sanitizer_common/sanitizer_common.h"

// if(cmpLeft == cmpRight) {
//   result = newVal;
// }
template<typename TCmov, typename TCmp>
void cmov_cmp(TCmov &result, TCmov newVal,
                     TCmp cmpLeft, TCmp cmpRight) {
  __asm__ __volatile__( "cmp %2, %3\n\t"
                        "cmove %0, %1"
      : "+r,r" (result)
      : "rm,rm"(newVal),
        "r,m"(cmpLeft), "irm,ir"(cmpRight)
      : "cc"
      );
}

// if(cmpLeft == cmpRight) {
//   result1 = newVal1;
//   result2 = newVal2;
// }
template<typename TCmov1, typename TCmov2, typename TCmp>
void cmov2_cmp(TCmov1 &result1, TCmov1 newVal1,
                      TCmov2 &result2, TCmov2 newVal2,
                      TCmp cmpLeft, TCmp cmpRight) {
  __asm__ __volatile__( "cmp %4, %5\n\t"
                        "cmove %0, %2\n\t"
                        "cmove %1, %3"
      : "+&r,r" (result1), "+&r,r"(result2)
      : "rm,rm"(newVal1), "rm,rm"(newVal2),
        "r,m"(cmpLeft), "irm,ir"(cmpRight)
      : "cc"
      );
}

// if(cmpLeft == cmpRight) {
//   result1 = result2;
//   result2 = newVal2;
// }
template<typename TCmov, typename TCmp>
void cmov2rw_cmp(TCmov &result1, TCmov &result2, TCmov newVal,
                      TCmp cmpLeft, TCmp cmpRight) {
  __asm__ __volatile__( "cmp %3, %4\n\t"
                        "cmove %0, %1\n\t"
                        "cmove %1, %2"
      : "+&r,r" (result1), "+&r,r"(result2)
      : "rm,rm"(newVal),
        "r,m"(cmpLeft), "irm,ir"(cmpRight)
      : "cc"
      );
}

// if(test) {
//   result = newVal;
// }
template<typename TCmov>
void cmov_test(TCmov &result1, TCmov newVal,
                       int test) {
  __asm__ __volatile__( "test %2, %2\n\t"
                        "cmovnz %0, %1"
      : "+&r,r" (result1)
      : "rm,rm"(newVal),
        "r,r"(test)
      : "cc"
      );
}

// if(test) {
//   result1 = newVal1;
//   result2 = newVal2;
// }
template<typename TCmov1, typename TCmov2>
void cmov2_test(TCmov1 &result1, TCmov1 newVal1,
                       TCmov2 &result2, TCmov2 newVal2,
                       int test) {
  __asm__ __volatile__( "test %4, %4\n\t"
                        "cmovnz %0, %2\n\t"
                        "cmovnz %1, %3"
      : "+&r,r" (result1), "+&r,r"(result2)
      : "rm,rm"(newVal1), "rm,rm"(newVal2),
        "r,r"(test)
      : "cc"
      );
}

// if(test) {
//   result1 = newVal1;
//   result2 = newVal2;
//   result3 = newVal3;
// }
template<typename TCmov1, typename TCmov2, typename TCmov3>
void cmov3_test(TCmov1 &result1, TCmov1 newVal1,
                       TCmov2 &result2, TCmov2 newVal2,
                       TCmov3 &result3, TCmov3 newVal3,
                       int test) {
  __asm__ __volatile__( "test %6, %6\n\t"
                        "cmovnz %0, %3\n\t"
                        "cmovnz %1, %4\n\t"
                        "cmovnz %2, %5"
      : "+&r,r" (result1), "+&r,r"(result2), "+&r,r"(result3)
      : "rm,rm"(newVal1), "rm,rm"(newVal2), "rm,rm"(newVal3),
        "r,r"(test)
      : "cc"
      );
}

// if(cmpLeft <= x && x < cmpRight) {
//   result = 1;
// }
template<typename TCmp>
int check_between(TCmp x, TCmp cmpLeft, TCmp cmpRight)
{
  int result = 0;
  int tmp;
  __asm__ __volatile__( "cmp %2, %3\n\t"
                        "setle %b1\n\t"
                        "cmp %3, %4\n\t"
                        "setl %b0\n\t"
                        "and %k0, %k1"
      : "+r,r" (result), "=&r,r"(tmp)
      : "rm,r"(cmpLeft), "r,rm"(x), "irm,ir"(cmpRight)
      : "cc"
      );
  return result;
}