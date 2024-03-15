#include "sanitizer_common/sanitizer_common.h"
#include <immintrin.h>

// XorShift128+, code adapted from https://en.wikipedia.org/wiki/Xorshift

struct xorshift128p_state {
  __sanitizer::u64 x[2];
};

inline void xorshift128p_init(xorshift128p_state &state)
{
  __sanitizer::u64 val;

  while(!_rdrand64_step(&val)) {}
  state.x[0] = val;

  while(!_rdrand64_step(&val)) {}
  state.x[1] = val;
}

inline __sanitizer::u64 xorshift128p_next(xorshift128p_state &state)
{
  __sanitizer::u64 t = state.x[0];
  const __sanitizer::u64 s = state.x[1];

  state.x[0] = s;
  t ^= t << 23;
  t ^= t >> 18;
  t ^= s ^ (s >> 5);
  state.x[1] = t;

  return t + s;
}