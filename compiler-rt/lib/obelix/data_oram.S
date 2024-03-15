#include "../builtins/assembly.h"
#ifdef __x86_64__
.intel_syntax noprefix

#include "debug_macros.S"

.extern data_oram_size
.extern data_oram_capacity
.extern data_oram
.extern data_rand_oram_size
.extern data_rand_oram_capacity
.extern data_rand_oram
.extern data_rand_oram_counters
.extern data_rand_oram_counters_increment

.extern data_oram_store_buffer_pointers
.extern data_oram_store_buffer_data
.extern data_oram_last_store_address

// Function macro for reading an entry (regPtr) from the data ORAM into XMM registers,
// while performing a write back in parallel, if the doWriteBack parameter is set.
// If it doesn't find the entry, the entry is added (lazy insertion).
// The insertion is _unsorted_, so do not use this for initialization.
// Macro arguments:
// - funcName: Name of the generated runtime function
// - useRandOram: Controls use of the randomized ORAM (ciphertext side-channel protection)
// - doWriteBack: If 1, a write back is performed
// Function parameters:
// - rdi: Pointer to retrieve. Must be 16-byte aligned.
// - rsi: First address to write back to (ignored if doWriteBack == 0).
// - rdx: Second address to write back to (ignored if doWriteBack == 0).
// - xmm0: First entry to write back (ignored if doWriteBack == 0).
// - xmm1: Second entry to write back (ignored if doWriteBack == 0).
// Returns:
// - xmm8: First part of the retrieved entry.
// - xmm9: Second part of the retrieved entry.
.macro data_oram_fetch funcName:req useRandOram:req doWriteBack:req
.balign 8
DEFINE_COMPILERRT_FUNCTION(\funcName)

    // Assign names to frequently used registers to improve readability

    // Parameters
    .equ regPtr, rdi
    .equ xmmWbData1, xmm0
    .equ xmmWbData2, xmm1

    // Returns
    .equ xmmResult1, xmm8
    .equ xmmResult2, xmm9

    // Temporaries
    .equ regFound, rsi

    .equ xmmWbPtr1, xmm10
    .equ xmmWbPtr2, xmm11

    .equ xmmConst16, xmm2 // For randomized ORAM
    .equ xmmOffset1, xmm2 // For non-randomized ORAM
    .equ xmmOffset2, xmm3 // For non-randomized ORAM

    .equ xmmCurPtr, xmm4
    .equ xmmMask, xmm5
    .equ xmmCurVal, xmm6
    .equ xmmRandCtr, xmm7
    .equ xmmPtr1, xmm14
    .equ xmmPtr2, xmm15

    // Available general-purpose: rdx, rcx, r8, r9, r10, r11

    .if \doWriteBack
        // Load write back addresses into vector registers
        vmovq xmmWbPtr1, rsi
        vmovq xmmWbPtr2, rdx
        vpbroadcastq xmmWbPtr1, xmmWbPtr1
        vpbroadcastq xmmWbPtr2, xmmWbPtr2

        .if \useRandOram
            vmovdqa xmmRandCtr, [rip+data_rand_oram_counters]
            vpaddq xmmRandCtr, xmmRandCtr, [rip+data_rand_oram_counters_increment]
            vmovdqa [rip+data_rand_oram_counters], xmmRandCtr
        .endif
    .endif

    // Init register for status tracking
    xor regFound, regFound

    // Init comparison register
    vpxor xmmPtr1, xmmPtr1, xmmPtr1

    // Dummy access
    mov edx, 1 // any non-0 value for the status tracker
    test regPtr, regPtr
    cmove regFound, rdx

    // We never actually access dummy memory, as we obliviously traverse the
    // whole ORAM anyway

    //.if \useRandOram

        // xmmConst16 contains 16 | 16
        mov edx, 16
        vmovq xmmConst16, rdx
        vpbroadcastq xmmConst16, xmmConst16
    //.else

        // Compute distance of first and second entry part from cache line boundary
        // 12..     -> begin 0, +1/+3
        // .12.     -> begin 1, +1/+3
        // ..12     -> begin 2, +1/+3
        // 2..1     -> begin 0, +3/+1
        // This way, we avoid clearly unneccessary accesses and masks/blends per
        // cache line, at no security risk.
        // TODO implement optimization. Only worth the effort for data spanning
        //      multiple cache lines, else potential padding eats all the speedup


    //.endif

    // Init comparison registers
    vmovq xmmPtr1, regPtr
    vpbroadcastq xmmPtr1, xmmPtr1
    vpaddq xmmPtr2, xmmPtr1, xmmConst16

    // Iterate through ORAM
    mov r8, [rip+data_oram]
\funcName\().data_oram_fetch.test_entry:

    // Get current entry pointer
    mov r9, [r8+0x0]
    test r9, r9
    je \funcName\().data_oram_fetch.check_store_buffer

    // Check whether pointer >= startAddress...
    mov rcx, ~0
    cmp regPtr, r9
    cmovae rcx, regPtr // if yes, rcx <- pointer, else rcx <- 111..111
    // ...and whether rcx <= endAddress
    cmp rcx, [r8+0x8]
    cmovb regFound, regPtr // any non-0 value for the status tracker

    // Init pointer vector register
    vmovq xmmCurPtr, r9
    vpbroadcastq xmmCurPtr, xmmCurPtr

    .if \useRandOram

        // Compute actual pointers in the randomized ORAM
        mov r9, [r8+0x10]
        mov r10, [r8+0x18]

        \funcName\().data_oram_fetch.test_pointer:

            // Done?
            cmp r9, r10
            je \funcName\().data_oram_fetch.test_entry_next

            // Read value, skip counters
            vmovdqa xmmCurVal, [r9]
            vpunpckhqdq xmmCurVal, xmmCurVal, [r9+16]

            // Test pointer and conditionally read data into register
            vpcmpeqq xmmMask, xmmCurPtr, xmmPtr1
            vpblendvb xmmResult1, xmmResult1, xmmCurVal, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmPtr2
            vpblendvb xmmResult2, xmmResult2, xmmCurVal, xmmMask

            .if \doWriteBack
                // Write back
                vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr1
                vpblendvb xmmCurVal, xmmCurVal, xmmWbData1, xmmMask
                vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr2
                vpblendvb xmmCurVal, xmmCurVal, xmmWbData2, xmmMask

                // Write with counter
                vpunpcklqdq xmmMask, xmmRandCtr, xmmCurVal
                vmovdqa [r9], xmmMask
                vpunpckhqdq xmmMask, xmmRandCtr, xmmCurVal
                vmovdqa [r9+16], xmmMask
            .endif

            vpaddq xmmCurPtr, xmmCurPtr, xmmConst16
            add r9, 32
            jmp \funcName\().data_oram_fetch.test_pointer
    .else

        // Get end pointer of current entry
        mov r10, [r8+0x8]

        \funcName\().data_oram_fetch.test_pointer:

            // Done?
            cmp r9, r10
            je \funcName\().data_oram_fetch.test_entry_next

            // Read value
            vmovdqa xmmCurVal, [r9]

            // Test pointer and conditionally read data into register
            vpcmpeqq xmmMask, xmmCurPtr, xmmPtr1
            vpblendvb xmmResult1, xmmResult1, xmmCurVal, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmPtr2
            vpblendvb xmmResult2, xmmResult2, xmmCurVal, xmmMask

            .if \doWriteBack
                // Write back
                vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr1
                vpblendvb xmmCurVal, xmmCurVal, xmmWbData1, xmmMask
                vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr2
                vpblendvb xmmCurVal, xmmCurVal, xmmWbData2, xmmMask
                vmovdqa [r9], xmmCurVal
            .endif

            vpaddq xmmCurPtr, xmmCurPtr, xmmConst16
            add r9, 16
            jmp \funcName\().data_oram_fetch.test_pointer
    .endif

\funcName\().data_oram_fetch.test_entry_next:

    add r8, 32
    jmp \funcName\().data_oram_fetch.test_entry


\funcName\().data_oram_fetch.check_store_buffer:

    // Try to find entry in the store buffer
    // We don't need to update the found status here, as the store buffer can
    // only contain data that is also present in the ORAM.

    vpbroadcastq xmmCurPtr, [rip+data_oram_store_buffer_pointers+0]
    vmovdqa xmmCurVal, [rip+data_oram_store_buffer_data+0]
    vpcmpeqq xmmMask, xmmCurPtr, xmmPtr1
    vpblendvb xmmResult1, xmmResult1, xmmCurVal, xmmMask
    vpcmpeqq xmmMask, xmmCurPtr, xmmPtr2
    vpblendvb xmmResult2, xmmResult2, xmmCurVal, xmmMask

    vpbroadcastq xmmCurPtr, [rip+data_oram_store_buffer_pointers+8]
    vmovdqa xmmCurVal, [rip+data_oram_store_buffer_data+16]
    vpcmpeqq xmmMask, xmmCurPtr, xmmPtr1
    vpblendvb xmmResult1, xmmResult1, xmmCurVal, xmmMask
    vpcmpeqq xmmMask, xmmCurPtr, xmmPtr2
    vpblendvb xmmResult2, xmmResult2, xmmCurVal, xmmMask

\funcName\().data_oram_fetch.check_success:

    // Did we find the entry?
    test regFound, regFound
    jne \funcName\().data_oram_fetch.done

    // We need to insert a new entry
    // Do we need to resize the pointer array?
    mov rdx, [rip+data_oram_size]
    cmp rdx, [rip+data_oram_capacity]
    jb \funcName\().data_oram_fetch.insert_entry

    // Resizing is not implemented at the moment. We initialize the ORAM to be big enough for most cases.
    // Also lazy insertion should be a last resort, and is not designed for adding lots of entries.
    hlt

\funcName\().data_oram_fetch.insert_entry:

    // Write back is not necessary here, as that value has been retrieved from the ORAM earlier.

    mov r8, [rip+data_oram]

    lea r10, [regPtr+16] // End pointer
    mov [r8+rdx], regPtr
    mov [r8+rdx+8], r10

    add rdx, 32
    mov [rip+data_oram_size], rdx

    // Ensure that next element is 0, marking the end
    // This way we avoid memset'ing the entire array on ORAM entry
    mov qword ptr [r8+rdx], 0

    // Debug output
    debug_output regPtr
    debug_output r10

    vmovdqa xmmResult1, [regPtr]
    vmovdqa xmmResult2, [regPtr+16]

\funcName\().data_oram_fetch.done:

    ret

END_COMPILERRT_FUNCTION(\funcName)
.endm

data_oram_fetch data_oram_linear_fetch 0 0
data_oram_fetch data_oram_linear_fetch_write_back 0 1
data_oram_fetch data_oram_linear_rand_fetch 1 0
data_oram_fetch data_oram_linear_rand_fetch_write_back 1 1


// Function macro for writing back into the data ORAM from XMM registers, and then writing
// back the ORAM contents into their original locations.
// - funcName: Name of the generated runtime function
// - useRandOram: Controls use of the randomized ORAM (ciphertext side-channel protection).
// Function parameters:
// - rdi: First address to write back to (ignored if doWriteBack == 0).
// - rsi: Second address to write back to (ignored if doWriteBack == 0).
// - rdx: Third address to write back to (ignored if doWriteBack == 0).
// - rcx: Fourth address to write back to (ignored if doWriteBack == 0).
// - xmm0: First entry to write back (ignored if doWriteBack == 0).
// - xmm1: Second entry to write back (ignored if doWriteBack == 0).
// - xmm2: Third entry to write back (ignored if doWriteBack == 0).
// - xmm3: Fourth entry to write back (ignored if doWriteBack == 0).
.macro data_oram_write_back funcName:req useRandOram:req
.balign 8
DEFINE_COMPILERRT_FUNCTION(\funcName)

    // Assign names to registers to improve readability

    // Parameters
    .equ xmmWbData1, xmm0
    .equ xmmWbData2, xmm1
    .equ xmmWbData3, xmm2
    .equ xmmWbData4, xmm3

    // Temporaries
    .equ xmmWbPtr1, xmm10
    .equ xmmWbPtr2, xmm11
    .equ xmmWbPtr3, xmm12
    .equ xmmWbPtr4, xmm13

    .equ xmmConst16, xmm4
    .equ xmmCurPtr, xmm5
    .equ xmmMask, xmm6
    .equ xmmCurVal, xmm7
    .equ xmmPtr1, xmm8
    .equ xmmPtr2, xmm9

    // Load write back addresses into vector registers
    vmovq xmmWbPtr1, rdi
    vmovq xmmWbPtr2, rsi
    vmovq xmmWbPtr3, rdx
    vmovq xmmWbPtr4, rcx
    vpbroadcastq xmmWbPtr1, xmmWbPtr1
    vpbroadcastq xmmWbPtr2, xmmWbPtr2
    vpbroadcastq xmmWbPtr3, xmmWbPtr3
    vpbroadcastq xmmWbPtr4, xmmWbPtr4

    // Available general-purpose: rdi, rsi, rdx, rcx, r8, r9, r10, r11

    // xmmConst16 contains 16 | 16
    mov edx, 16
    vmovq xmmConst16, rdx
    vpbroadcastq xmmConst16, xmmConst16

    // Iterate through ORAM
    mov r8, [rip+data_oram]
\funcName\().data_oram_write_back.test_entry:

    // Get current entry pointer
    mov rsi, [r8]
    test rsi, rsi
    je \funcName\().data_oram_write_back.done

    // Init pointer vector register
    vmovq xmmCurPtr, rsi
    vpbroadcastq xmmCurPtr, xmmCurPtr

    .if \useRandOram

        // Compute actual pointers in the randomized ORAM
        mov r9, [r8+0x10]
        mov r10, [r8+0x18]

        \funcName\().data_oram_write_back.test_pointer:

            // Done?
            cmp r9, r10
            je \funcName\().data_oram_write_back.test_entry_next

            // Read value, skip counters
            vmovdqa xmmCurVal, [r9]
            vpunpckhqdq xmmCurVal, xmmCurVal, [r9+16]

            // Write back
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr1
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData1, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr2
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData2, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr3
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData3, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr4
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData4, xmmMask

            // Write into original location, without counter
            vmovdqa [rsi], xmmCurVal

            vpaddq xmmCurPtr, xmmCurPtr, xmmConst16
            add r9, 32
            add rsi, 16
            jmp \funcName\().data_oram_write_back.test_pointer
    .else

        // Get end pointer of current entry
        mov r10, [r8+0x8]

        \funcName\().data_oram_write_back.test_pointer:

            // Done?
            cmp rsi, r10
            je \funcName\().data_oram_write_back.test_entry_next

            // Read value
            vmovdqa xmmCurVal, [rsi]

            // Write back
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr1
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData1, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr2
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData2, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr3
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData3, xmmMask
            vpcmpeqq xmmMask, xmmCurPtr, xmmWbPtr4
            vpblendvb xmmCurVal, xmmCurVal, xmmWbData4, xmmMask
            vmovdqa [rsi], xmmCurVal

            vpaddq xmmCurPtr, xmmCurPtr, xmmConst16
            add rsi, 16
            jmp \funcName\().data_oram_write_back.test_pointer
    .endif

\funcName\().data_oram_write_back.test_entry_next:

    add r8, 32
    jmp \funcName\().data_oram_write_back.test_entry

\funcName\().data_oram_write_back.done:

    ret

END_COMPILERRT_FUNCTION(\funcName)
.endm

data_oram_write_back data_oram_linear_write_back 0
data_oram_write_back data_oram_linear_rand_write_back 1

#endif