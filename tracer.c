#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <unistd.h> // for fork, pid_t
#include <stdlib.h> // for exit, EXIT_FAILURE, NULL
#include <sys/user.h> // for struct user_regs_struct
#include <stdio.h> // for puts, printf
#include <sys/wait.h> // for waitpid, WSTOPSIG
#include <signal.h> // for SIG*
#include <stdint.h> // for uint*_t

#include <capstone/capstone.h>

void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
}

long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr, void *data) {
    if (ptrace(op, pid, addr, data) == -1) {
        die("ptrace failed!");
    }
}

void print_regs(struct user_regs_struct regs) {
    printf("rax: %llu\n", regs.rax);
    printf("rbx: %llu\n", regs.rbx);
    printf("rcx: %llu\n", regs.rcx);
    printf("rdx: %llu\n", regs.rdx);
    printf("rdi: %llu\n", regs.rdi);
    printf("rsi: %llu\n", regs.rsi);
    printf("r8:  %llu\n", regs.r8);
    printf("r9:  %llu\n", regs.r9);
    printf("r10: %llu\n", regs.r10);
    printf("r11: %llu\n", regs.r11);
    printf("r12: %llu\n", regs.r12);
    printf("r13: %llu\n", regs.r13);
    printf("r14: %llu\n", regs.r14);
    printf("r15: %llu\n", regs.r15);
    printf("rip: %p\n", regs.rip);
    printf("rbp: %p\n", regs.rbp);
    printf("rsp: %p\n", regs.rsp);
}

int waitpid_or_die(pid_t pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid) {
        die("waitpid failed!");
    }
    return wstatus;
}

void check_signal(int signal, int expected_signal) {
    if (signal != expected_signal) {
        die("child stopped for unexpected reason");
    }
}

void wait_and_expect_signal(pid_t pid, int signal) {
    check_signal(WSTOPSIG(waitpid_or_die(pid)), signal);
}

csh cs_open_or_die(void) {
    csh cs_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
        die("cs_open failed!");
    }
    return cs_handle;
}

uint64_t disas_rip(pid_t pid) {
    csh cs_handle = cs_open_or_die();
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    char s[sizeof(uint64_t)];
    *(uint64_t *)s = ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);

    cs_insn *instructions;
    size_t count = cs_disasm(cs_handle, s, sizeof(s), regs.rip, 0, &instructions);
    if (count <= 0) {
        die("cs_disasm failed!");
    }
    printf("-> %s %s\n", instructions[0].mnemonic, instructions[0].op_str);
    cs_free(instructions, count);
    cs_close(&cs_handle);
}

int main(int argc, char **argv) {
    pid_t child_pid = fork();
    if (child_pid == -1) {
        die("fork failed!");
    }
    if (!child_pid) { // child
        ptrace_or_die(PTRACE_TRACEME, -1, NULL, NULL);
        execve(argv[1], argv + 1, NULL);
        die("execve failed!");
    }
    wait_and_expect_signal(child_pid, SIGTRAP);

    while (1) {
        struct user_regs_struct regs = {};
        ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
        print_regs(regs);
        disas_rip(child_pid);

        getchar();
        ptrace_or_die(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
        int const wstatus = waitpid_or_die(child_pid);
        if (WIFEXITED(wstatus)) {
            break;
        }
        check_signal(WSTOPSIG(wstatus), SIGTRAP);
    }
    puts("Child exited.");
}
