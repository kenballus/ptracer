.intel_syntax noprefix
.global _start

_start:
    push 20                  
    sub rsp, 8              
    mov rax, 0x48454c4c4f
    mov qword ptr [rsp], rax
    mov byte ptr [rsp], 'H'  

    call main

    mov rdi, 0         
    mov rax, 60              
    syscall

main:
    ret
