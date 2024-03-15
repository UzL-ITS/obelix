#include "../builtins/assembly.h"
#ifdef __x86_64__
.intel_syntax noprefix

.extern code_scratch_pad_address
.extern function_info

#include "debug_macros.S"


// Parameters:
// - rdi: Address of code block to fetch.
DEFINE_COMPILERRT_PRIVATE_FUNCTION(code_oram_linear_naive_query)

    // Do oblivious code fetch
    // We iterate the function info, and then each respective code block table
    vmovq xmm7, rdi // Comparison register
    vpbroadcastq ymm7, xmm7
    mov rdx, [rip+function_info]

code_oram_linear_naive_query.loop_function_info:
    movsx rcx, dword ptr [rdx]
    test rcx, rcx
    je code_oram_linear_naive_query.store_code_block

    add rcx, rdx

    // Skip block count
    add rcx, 4

    xor eax, eax
.p2align 4
code_oram_linear_naive_query.test_code_block:
    movsx r8, dword ptr [rcx]
    test r8, r8
    je code_oram_linear_naive_query.next_table

    // Compute actual code block address
    add r8, rcx

#if defined(__AVX512F__) && defined(__AVX512VL__)
    // Generate mask
    vpbroadcastq ymm10, r8
    vpcmpeqq k1, ymm10, ymm7

    // Conditionally read code into register
    vmovdqa64 ymm12 {k1}, [r8+0x00]
    vmovdqa64 ymm13 {k1}, [r8+0x20]
    vmovdqa64 ymm14 {k1}, [r8+0x40]
    vmovdqa64 ymm15 {k1}, [r8+0x60]
#else
    // Compute actual code block address and generate mask
    vmovq xmm10, r8
    vpbroadcastq ymm10, xmm10
    vpcmpeqq ymm10, ymm10, ymm7

    // Conditionally read code into register
    vpblendvb ymm12, ymm12, [r8+0x00], ymm10
    vpblendvb ymm13, ymm13, [r8+0x20], ymm10
    vpblendvb ymm14, ymm14, [r8+0x40], ymm10
    vpblendvb ymm15, ymm15, [r8+0x60], ymm10
#endif

    add rcx, 4
    jmp code_oram_linear_naive_query.test_code_block

code_oram_linear_naive_query.next_table:

    add rdx, 4
    jmp code_oram_linear_naive_query.loop_function_info

code_oram_linear_naive_query.store_code_block:

    // Write block
    mov rcx, [rip+code_scratch_pad_address]
    vmovdqa [rcx+0x00], ymm12
    vmovdqa [rcx+0x20], ymm13
    vmovdqa [rcx+0x40], ymm14
    vmovdqa [rcx+0x60], ymm15

    ret

END_COMPILERRT_FUNCTION(code_oram_linear_naive_query)

#endif