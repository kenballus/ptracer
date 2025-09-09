.intel_syntax noprefix

.global _start
_start:
    push rbp
    mov rbp, rsp
    mov rax, 60
    mov rdi, 0
    syscall
