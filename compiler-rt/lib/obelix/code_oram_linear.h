
#include "sanitizer_common/sanitizer_common.h"

// Entry in the function info table.
struct function_info_entry {
  __sanitizer::s32 codeTableOffset;
  __sanitizer::s32 originalCodeOffset;
};

void init_linear_oram_naive();
void init_linear_oram_compressed();