.text
.globl mbdi_x64_enter
mbdi_x64_enter:
    # Save the engine's flags and Windows x64 nonvolatile GPRs.
    pushfq
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    # RCX = GateFrame pointer, RDX = cache entry address.
    mov rax, rcx
    mov [rax + 136], rsp
    mov [rax + 144], rdx

    # Load guest CF, PF, AF, ZF, SF, OF.
    pushfq
    pop r10
    #~0x8d5=CF, PF, AF, ZF, SF, OF
    and r10, ~0x8d5
    mov r11, [rax + 128]
    and r11, 0x8d5
    or r10, r11
    push r10
    popfq

    mov rcx, [rax + 8]
    mov rdx, [rax + 16]
    mov rbx, [rax + 24]
    mov rbp, [rax + 40]
    mov rsi, [rax + 48]
    mov rdi, [rax + 56]
    mov r8,  [rax + 64]
    mov r9,  [rax + 72]
    mov r10, [rax + 80]
    mov r11, [rax + 88]
    mov r12, [rax + 96]
    mov r13, [rax + 104]
    mov r14, [rax + 112]
    mov r15, [rax + 120]
    mov rsp, [rax + 32]

    # The cache entry shim loads guest RAX and falls through into the body.
    jmp qword ptr [rax + 144]

.globl mbdi_x64_leave
mbdi_x64_leave:
    # The cache exit shim has already saved guest RAX.
    # RAX now points to GateFrame.
    mov [rax + 8], rcx
    mov [rax + 16], rdx
    mov [rax + 24], rbx
    mov [rax + 32], rsp
    mov [rax + 40], rbp
    mov [rax + 48], rsi
    mov [rax + 56], rdi
    mov [rax + 64], r8
    mov [rax + 72], r9
    mov [rax + 80], r10
    mov [rax + 88], r11
    mov [rax + 96], r12
    mov [rax + 104], r13
    mov [rax + 112], r14
    mov [rax + 120], r15

    # Capture guest flags on the engine's stack.
    mov rsp, [rax + 136]
    pushfq
    pop qword ptr [rax + 128]

    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    popfq
    ret