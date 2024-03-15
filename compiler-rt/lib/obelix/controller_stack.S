.bss

// Controller stack. Used for storing state between code blocks.
.balign 0x1000
.set OBELIX_STACK_SIZE, 0x1000
.globl __obelix_stack
__obelix_stack: .skip OBELIX_STACK_SIZE

.text

// Macro for storing the volatile register state in the controller stack on
// controller entry.
// After this macro, RSP is NOT 16-byte aligned, but 8-byte aligned.
.macro save_regs
    mov [rip+__obelix_stack+OBELIX_STACK_SIZE-0x8], rsp
    lea rsp, [rip+__obelix_stack+OBELIX_STACK_SIZE-0x8]
    push rax

    // FLAGS
    lahf
    push rax

    push r11
    push r10
    push r9
    push r8
    push rdx
    push rcx
    push rdi
    push rsi
.endm

// Macro for restoring the volatile register state at controller exit.
// After this macro, the controller stack is empty.
.macro restore_regs
    pop rsi
    pop rdi
    pop rcx
    pop rdx
    pop r8
    pop r9
    pop r10
    pop r11

    // FLAGS
    pop rax
    sahf

    pop rax
    pop rsp
.endm