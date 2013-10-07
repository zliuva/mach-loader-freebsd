	.data
hello_str:
    .ascii  "Hello, World!\n"

    .text
    .globl start

start:
    movq    $2, %rdi
    leaq    hello_str(%rip), %rsi
    movq    $14, %rdx
    movq    $0x2000004, %rax
    syscall

    xorq    %rdi, %rdi
    movq    $0x2000001, %rax
    syscall

