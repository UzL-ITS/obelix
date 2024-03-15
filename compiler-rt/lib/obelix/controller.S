#include "../builtins/assembly.h"
#ifdef __x86_64__
.intel_syntax noprefix

.set CODE_SCRATCH_PAD_OFFSET_MASK, (0x1000 - 1)
.set DATA_SCRATCH_PAD_OFFSET_MASK, (0x1000 - 1)
.set ADJUSTMENT_NEEDED_ADDEND, 0x100000

// The size of each code block as stored in the .text section.
.set CODE_BLOCK_SIZE_TEXT, 256

#include "controller_stack.S"
#include "debug_macros.S"

.bss
// Holds the fallthrough address to the subsequent block.
__obelix_block_fallthrough: .skip 8

.text
.balign 8
DEFINE_COMPILERRT_FUNCTION(__obelix_controller_enter)

    // r15 contains the address of the function info block
    // Resolve to code block table
    movsx r14, dword ptr [r15]
    add r14, r15
    add r14, 4 // Skip block count
    mov r15, r14

    // We prepare state as expected by __obelix_controller_next
    // - r15: address of first block
    // - Dummy fallthrough

    // Get address of entry block
    movsx r14, dword ptr [r15]
    add r15, r14

    // Compute dummy fallthrough address (not used on startup)
    lea r14, [r15+CODE_BLOCK_SIZE_TEXT]
    mov [rip+__obelix_block_fallthrough], r14

    jmp __obelix_controller_next

END_COMPILERRT_FUNCTION(__obelix_controller_enter)

// Code ORAM controller and dispatcher.
// Entry:
// - r15: Target address (based on scratchpad address)
//        - 0 means "leave ORAM mode"
//        - 1 means "fallthrough to subsequent block"
// Exit:
// - (r13) Scratchpad address
// - r14: Address of __obelix_controller_functions
.balign 8
DEFINE_COMPILERRT_FUNCTION(__obelix_controller_next)

    // Save state and align stack
    save_regs
    sub rsp, 8

    //call __obelix_dump_regstate

    // Exit ORAM mode?
    cmp r15, 1
    je __obelix_controller_next.leave_oram

    // Fallthrough address?
    mov r14, [rip+__obelix_block_fallthrough]
    test r15, r15
    cmove r15, r14

    // Increment code scratch pad addend
    mov r13, [rip+code_scratch_pad]
    mov r14d, [rip+code_scratch_pad_offset]
    add r14d, [rip+code_scratch_pad_addend]
    and r14d, CODE_SCRATCH_PAD_OFFSET_MASK
    add r13, r14
    mov [rip+code_scratch_pad_offset], r14d
    mov [rip+code_scratch_pad_address], r13
    prefetchw [r13]
    prefetchw [r13+64]

    // We assume that r15 is properly aligned. This assumption should be safe,
    // as we ensure that all MBBs are aligned to 128 bytes, and that calls only
    // point to functions also marked as protected.

    // Do oblivious code fetch
    mov rdi, r15
    //call code_oram_linear_naive_query
    call code_oram_linear_naive_query_c
    //call code_oram_linear_compressed_query_c
    //call code_oram_path_c_query

    // The fetched address may have changed (remapped function pointer calls)
    mov r15, rax

    /*
    // Execute code at original location, not in scratch pad
    mov r13, r15
    mov [rip+code_scratch_pad_address], r13
    //*/

    // Compute fallthrough address to avoid separate lea in blocks
    lea r14, [r15+CODE_BLOCK_SIZE_TEXT]
    mov [rip+__obelix_block_fallthrough], r14

    // Compute distance between code scratchpad and block
    // (needed for adjusting code scratchpad-relative addresses to absolute ones)
    mov r13, [rip+code_scratch_pad_address]
    sub r15, r13  // block - scrbase
    mov [rip+__obelix_controller_functions+0x0], r15

    // r13 now holds the address of the code scratchpad

    // Execute a number of dependent dummy instructions to stall the processor
    // until the code store has completed. This way, we avoid a very costly
    // self-modifying code machine clear.
    mov rax, [rip+code_scratch_pad_address]
    mov r9d, 27272727
    .rept 4
    sub rdx, rdx
    idiv r9
    .endr
    add r13, rax

    //call __obelix_dump_regstate

    // Restore state
    add rsp, 8
    restore_regs

    // Enter next block
    lea r14, [rip+__obelix_controller_functions]
    jmp r13

__obelix_controller_next.leave_oram:

    // Finalize data ORAM
    call data_oram_linear_fini

    // Finalize code ORAM
    //call code_oram_path_c_fini

    // Restore state
    add rsp, 8
    restore_regs

    // Leave ORAM
    // Leaving controller, restore reserved registers
    mov r13, [rip+__obelix_save+0x00]
    mov r14, [rip+__obelix_save+0x08]
    mov r15, [rip+__obelix_save+0x10]

    jmp [rip+__obelix_save+0x18]

END_COMPILERRT_FUNCTION(__obelix_controller_next)


// Data ORAM load controller.
// Entry:
// - r13: Address to return to in code scratchpad
// - r15: Address to access
// Exit:
// - (r13): Scratchpad return address
// - r14: Address of __obelix_controller_functions
// - r15: Address to access, remapped to data scratchpad
.balign 8
DEFINE_COMPILERRT_FUNCTION(__obelix_memory_load)

    // Save state and align stack
    save_regs
    sub rsp, 8

    // Check return address
    // If it points outside the code scratchpad (which is not a valid return location),
    // we have added a constant that indicates that the pointer is RIP-relative and
    // needs adjustment.
    //
    //   int adjustAddend = 0;  // rcx
    //   if(retAddr > scrbase + ADJUSTMENT_NEEDED_ADDEND) {
    //     adjustAddend = __obelix_controller_functions[0]; // r14
    //   }
    //   address += adjustAddend; // r15
    //
    //   int updateRetAddr = 0; // rcx
    //   if(retAddr > scrbase + ADJUSTMENT_NEEDED_ADDEND) {
    //     updateRetAddr = ADJUSTMENT_NEEDED_ADDEND; // r14
    //   }
    //   retAddr -= updateRetAddr; // r13
    mov r11, [rip+code_scratch_pad_address]
    add r11, ADJUSTMENT_NEEDED_ADDEND // scrbase + ADJUSTMENT_NEEDED_ADDEND
    mov r14, [rip+__obelix_controller_functions] // Read adjustment value
    xor ecx, ecx // Final adjustment addend
    cmp r11, r13 // Will be negative if the return address is behind scrbase+ADJUSTMENT_NEEDED_ADDEND
    cmovb rcx, r14 // If negative, load adjustment value, else keep 0
    add r15, rcx // Update address to access
    mov r14, ADJUSTMENT_NEEDED_ADDEND
    xor ecx, ecx
    cmp r11, r13 // Will be negative if the return address is behind scrbase+ADJUSTMENT_NEEDED_ADDEND
    cmovb rcx, r14 // If negative, load adjustment value, else keep 0
    sub r13, rcx

    // - r13 holds the adjusted return address
    // - r15 holds the target address

    // Compute 16-byte aligned base address of data
    mov rdi, ~0xf
    and rdi, r15

    // Compute offset of requested data in data scratchpad
    // The requested address may not be 16-byte aligned, so we need to add this
    // offset to the final rewritten address.
    sub r15, rdi

    // - rdi holds the 16-byte aligned data address
    // - r15 holds the offset of the requested data in the data scratchpad

    // Increment data scratch pad offset
    mov rsi, [rip+data_scratch_pad_address]
    mov r14d, [rip+data_scratch_pad_offset]
    add r14d, [rip+data_scratch_pad_addend]
    and r14d, DATA_SCRATCH_PAD_OFFSET_MASK
    mov [rip+data_scratch_pad_offset], r14d
    add r14, [rip+data_scratch_pad]
    mov [rip+data_scratch_pad_address], r14

    // - rsi holds the old data scratchpad address
    // - r14 holds the new data scratchpad address

    // Fetch data from ORAM
    // rdi: 16-byte aligned address
    // rsi: oldDataScratchPadAddress
    xor edx, edx // isStore
    call data_oram_linear_query

    // Absolute address of data residing in the data scratchpad
    add r15, r14

    // Restore state
    add rsp, 8
    restore_regs

    // Re-enter block
    lea r14, [rip+__obelix_controller_functions]
    jmp r13

END_COMPILERRT_FUNCTION(__obelix_memory_load)

// Data ORAM store controller.
// Entry:
// - r13: Address to return to in code scratchpad
// - r15: Address to access
// Exit:
// - (r13): Scratchpad return address
// - r14: Address of __obelix_controller_functions
// - r15: Address to access, remapped to data scratchpad
.balign 8
DEFINE_COMPILERRT_FUNCTION(__obelix_memory_store)

    // Save state and align stack
    save_regs
    sub rsp, 8

    // Check return address
    // If it points outside the code scratchpad (which is not a valid return location),
    // we have added a constant that indicates that the pointer is RIP-relative and
    // needs adjustment.
    //
    //   int adjustAddend = 0;  // rcx
    //   if(retAddr > scrbase + ADJUSTMENT_NEEDED_ADDEND) {
    //     adjustAddend = __obelix_controller_functions[0]; // r14
    //   }
    //   address += adjustAddend; // r15
    //
    //   int updateRetAddr = 0; // rcx
    //   if(retAddr > scrbase + ADJUSTMENT_NEEDED_ADDEND) {
    //     updateRetAddr = ADJUSTMENT_NEEDED_ADDEND; // r14
    //   }
    //   retAddr -= updateRetAddr; // r13
    mov r11, [rip+code_scratch_pad_address]
    add r11, ADJUSTMENT_NEEDED_ADDEND // scrbase + ADJUSTMENT_NEEDED_ADDEND
    mov r14, [rip+__obelix_controller_functions] // Read adjustment value
    xor ecx, ecx // Final adjustment addend
    cmp r11, r13 // Will be negative if the return address is behind scrbase+ADJUSTMENT_NEEDED_ADDEND
    cmovb rcx, r14 // If negative, load adjustment value, else keep 0
    add r15, rcx // Update address to access
    mov r14, ADJUSTMENT_NEEDED_ADDEND
    xor ecx, ecx
    cmp r11, r13 // Will be negative if the return address is behind scrbase+ADJUSTMENT_NEEDED_ADDEND
    cmovb rcx, r14 // If negative, load adjustment value, else keep 0
    sub r13, rcx

    // - r13 holds the adjusted return address
    // - r15 holds the target address

    // Compute 16-byte aligned base address of data
    mov rdi, ~0xf
    and rdi, r15

    // Compute offset of requested data in data scratchpad
    // The requested address may not be 16-byte aligned, so we need to add this
    // offset to the final rewritten address.
    sub r15, rdi

    // - rdi holds the 16-byte aligned data address
    // - r15 holds the offset of the requested data in the data scratchpad

    // Increment data scratch pad offset
    mov rsi, [rip+data_scratch_pad_address]
    mov r14d, [rip+data_scratch_pad_offset]
    add r14d, [rip+data_scratch_pad_addend]
    and r14d, DATA_SCRATCH_PAD_OFFSET_MASK
    mov [rip+data_scratch_pad_offset], r14d
    add r14, [rip+data_scratch_pad]
    mov [rip+data_scratch_pad_address], r14

    // - rsi holds the old data scratchpad address
    // - r14 holds the new data scratchpad address

    // Fetch data from ORAM
    // rdi: 16-byte aligned address
    // rsi: oldDataScratchPadAddress
    mov edx, 1 // isStore
    call data_oram_linear_query

    // Absolute address of data residing in the data scratchpad
    add r15, r14

    // Restore state
    add rsp, 8
    restore_regs

    // Re-enter block
    lea r14, [rip+__obelix_controller_functions]
    jmp r13

END_COMPILERRT_FUNCTION(__obelix_memory_store)

#endif // __x86_64__
