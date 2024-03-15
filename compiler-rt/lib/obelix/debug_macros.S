
.extern __obelix_debug_output

// Utility function.
// Outputs the value of reg.
.macro debug_output reg:req
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rdx
    push rcx
    push rbx
    push rax
    mov rbx, rsp

    // Align to 0x20, ensure space for YMM0
    sub rsp, 0x40
    and rsp, -0x20

    vmovdqa [rsp-0x00], ymm0
    vmovdqa [rsp-0x20], ymm1
    vmovdqa [rsp-0x40], ymm2
    vmovdqa [rsp-0x60], ymm3
    vmovdqa [rsp-0x80], ymm4
    vmovdqa [rsp-0xa0], ymm5
    vmovdqa [rsp-0xc0], ymm6
    vmovdqa [rsp-0xe0], ymm7
    vmovdqa [rsp-0x100], ymm8
    vmovdqa [rsp-0x120], ymm9
    vmovdqa [rsp-0x140], ymm10
    vmovdqa [rsp-0x160], ymm11
    vmovdqa [rsp-0x180], ymm12
    vmovdqa [rsp-0x1a0], ymm13
    vmovdqa [rsp-0x1c0], ymm14
    vmovdqa [rsp-0x1e0], ymm15
    sub rsp, 0x200

    mov rdi, \reg
    call __obelix_debug_output

    add rsp, 0x200
    vmovdqa ymm15, [rsp-0x1e0]
    vmovdqa ymm14, [rsp-0x1c0]
    vmovdqa ymm13, [rsp-0x1a0]
    vmovdqa ymm12, [rsp-0x180]
    vmovdqa ymm11, [rsp-0x160]
    vmovdqa ymm10, [rsp-0x140]
    vmovdqa ymm9, [rsp-0x120]
    vmovdqa ymm8, [rsp-0x100]
    vmovdqa ymm7, [rsp-0xe0]
    vmovdqa ymm6, [rsp-0xc0]
    vmovdqa ymm5, [rsp-0xa0]
    vmovdqa ymm4, [rsp-0x80]
    vmovdqa ymm3, [rsp-0x60]
    vmovdqa ymm2, [rsp-0x40]
    vmovdqa ymm1, [rsp-0x20]
    vmovdqa ymm0, [rsp-0x00]

    mov rsp, rbx
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
.endm