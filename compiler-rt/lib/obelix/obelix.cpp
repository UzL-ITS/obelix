
#include "code_oram_linear.h"
#include "code_oram_path_c.h"
#include "data_oram_linear.h"
#include "constants.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"
#include <sys/mman.h>

using namespace __sanitizer;


// Controller functions.
extern "C" void __obelix_controller_next(void);
extern "C" void __obelix_memory_load(void);
extern "C" void __obelix_memory_store(void);

extern "C"
{
  // Pointers to controller functions.
  // Used for flexible jumping from the code block into the controller.
  // Alignment to 0x100 is necessary for a zeroing-hack at each code block end:
  //     `movzx r15, r14b` sets r15 to 0 if r14b == 0, and only takes 4 bytes.
  [[gnu::aligned(0x100)]] uptr __obelix_controller_functions[] = {
      0, // Placeholder for RIP-adjustment value
      reinterpret_cast<uptr>(__obelix_controller_next),
      reinterpret_cast<uptr>(__obelix_memory_load),
      reinterpret_cast<uptr>(__obelix_memory_store)
  };
}

// Tracks whether the ORAM controller is initialized (only done once per
// execution)
static bool initialized = false;

extern "C"
{
  // Used by the Obelix entry/exit point for saving register state and the return address.
  SANITIZER_INTERFACE_ATTRIBUTE u64 __obelix_save[4] = {
      0, // r13
      0, // r14
      0, // r15
      0 // return address
  };
}

extern "C"
{
  // Pointer to info block of the function that triggered ORAM entry.
  function_info_entry *function_info = nullptr;

  // Pointer to code scratch pad.
  u8 *code_scratch_pad = nullptr;

  // Pointer to data scratch pad.
  u8 *data_scratch_pad = nullptr;
}

extern "C"
{
  // Current code scratch pad address.
  u64 code_scratch_pad_address = 0;

  // Current data scratch pad address.
  u64 data_scratch_pad_address = 0;

  // Offsets for the ciphertext side-channel countermeasure. The offsets are added
  // to the code and data scratch pad pointers.
  u32 code_scratch_pad_offset = 0;
  u32 data_scratch_pad_offset = 0;

  // Addends for the ciphertext side-channel countermeasure. The addends are added
  // to the code and data scratch pad pointer offsets.
  u32 code_scratch_pad_addend = 0;
  u32 data_scratch_pad_addend = 0;
}


extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_init(function_info_entry* functionInfo, bool useRandOram) {

  //Printf("[OBELIX] Enter, function info %lx\n", reinterpret_cast<uptr>(functionInfo));

  if(!initialized) {
    //Printf("[OBELIX] Init\n");

    // Allocate code scratch pad
    code_scratch_pad = reinterpret_cast<u8 *>(internal_mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0));
    code_scratch_pad_address = reinterpret_cast<uptr>(code_scratch_pad);
    //Printf("[OBELIX]  Code scratch pad: %lx\n", reinterpret_cast<uptr>(code_scratch_pad));

    // Always rotate the code scratch pad, as this seems to mitigate
    // self-modifying code issues a bit.
    // We use an uneven addend to reduce the probability that the CPU speculatively
    // prefetches stale instructions. This way, we iterate over all possible scratchpad
    // position before it repeats.
    // Round code block size to power of 2 to prevent accidental overflows.
    int codeBlockSizePow2 = 64;
    while(codeBlockSizePow2 < code_block_size)
      codeBlockSizePow2 *= 2;
    code_scratch_pad_addend = 9 * codeBlockSizePow2;

    data_scratch_pad = reinterpret_cast<u8 *>(internal_mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    data_scratch_pad_address =reinterpret_cast<uptr>(data_scratch_pad);

    preinit_linear_data_oram();

    initialized = true;
  }

  function_info = functionInfo;

  if(useRandOram) {
    data_scratch_pad_addend = 32;
  }
  else {
    data_scratch_pad_addend = 0;
  }

  // Initialize code ORAM
  //init_path_oram_c();
  init_linear_oram_naive();
  //init_linear_oram_compressed();

  // Initialize data ORAM
  init_linear_data_oram(useRandOram);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_debug_output(u64 value) {
  Printf("[OBELIX] Debug: %llx\n", value);
}

// Dump the entire internal state.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_dump() {

  Printf("[OBELIX] Dumping state...\n");

  // Pointers
  Printf("[OBELIX]  Code scratch pad: %lx\n", reinterpret_cast<uptr>(code_scratch_pad));
  Printf("[OBELIX]  Data scratch pad: %lx\n", reinterpret_cast<uptr>(data_scratch_pad));

  // Function info
  Printf("[OBELIX]  Function info / code block tables (relative offsets, hex):\n");
  function_info_entry *functionInfoPtr = function_info;
  while(functionInfoPtr->codeTableOffset != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->codeTableOffset);
    uptr origPtr = reinterpret_cast<uptr>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->originalCodeOffset);

    Printf("[OBELIX]   +%x (-> %lx, orig %lx)\n", functionInfoPtr->codeTableOffset, reinterpret_cast<uptr>(codeBlockTablePtr), origPtr);

    while(*codeBlockTablePtr != 0)
    {
      Printf("[OBELIX]     +%x (-> %lx)\n", *codeBlockTablePtr, reinterpret_cast<uptr>(codeBlockTablePtr) + *codeBlockTablePtr);

      ++codeBlockTablePtr;
    }

    ++functionInfoPtr;
  }

  dump_linear_data_oram();

  Printf("[OBELIX] Dumping state done.\n");
}

// Output an error message that the called function is not a valid ORAM entrypoint.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_invalid_entrypoint() {
  Printf("[OBELIX] This function is not a valid ORAM entrypoint. "
         "Only functions explicitly marked with the [[clang::obelix]] attribute "
         "may be called directly.\n");
  internal__exit(-1);
}

// Dumps the saved register state.
extern "C" u8 __obelix_stack;
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_dump_regstate() {
  constexpr int OBELIX_STACK_SIZE = 0x1000;
  struct regstate {
    u64 rsi;
    u64 rdi;
    u64 rcx;
    u64 rdx;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 flags;
    u64 rax;
    u64 rsp;
  };

  regstate *regs = reinterpret_cast<regstate *>(reinterpret_cast<uptr>(&__obelix_stack) + OBELIX_STACK_SIZE - sizeof(regstate));

  Printf("[OBELIX] Regstate at %lx:\n", reinterpret_cast<uptr>(regs));
  Printf("[OBELIX]   rax = %llx\n", regs->rax);
  Printf("[OBELIX]   rcx = %llx\n", regs->rcx);
  Printf("[OBELIX]   rdx = %llx\n", regs->rdx);
  Printf("[OBELIX]   rsi = %llx\n", regs->rsi);
  Printf("[OBELIX]   rdi = %llx\n", regs->rdi);
  Printf("[OBELIX]   r8 = %llx\n", regs->r8);
  Printf("[OBELIX]   r9 = %llx\n", regs->r9);
  Printf("[OBELIX]   r10 = %llx\n", regs->r10);
  Printf("[OBELIX]   r11 = %llx\n", regs->r11);
  Printf("[OBELIX]   rsp = %llx\n", regs->rsp);
  Printf("[OBELIX]   flags = %llx\n", regs->flags);
}