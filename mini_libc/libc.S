.intel_syntax noprefix

.global syscall
syscall:
    mov eax, edi // syscall numbers are 32-bit!!
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 8]
    syscall
    ret

.global _start
_start:
    mov rdi, qword ptr [rsp] // grab argc
    lea rsi, [rsp + 8]       // grab argv
    lea rdx, [rsp + 8 /* skip argc */ + rdi * 8 /* skip argv */ + 8 /* skip NULL */] // grab envp
    and rsp, -16             // align the stack for a call
    call main

    mov edi, eax             // plop returned value from main into rdi
    jmp _exit
