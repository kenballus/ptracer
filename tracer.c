#include <signal.h>     // for SIG*
#include <stdint.h>     // for uint*_t
#include <stdio.h>      // for puts, printf
#include <stdlib.h>     // for exit, EXIT_FAILURE, NULL
#include <string.h>     // for memcpy
#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <sys/user.h>   // for struct user_regs_struct
#include <sys/wait.h>   // for waitpid, WSTOPSIG
#include <unistd.h>     // for fork, pid_t
#include <limits.h>     // for CHAR_BIT

#include <capstone/capstone.h>

#define BOX_TOP "╔══════════════════════════════╗"
#define BOX_SIDE "║"
#define BOX_DIVIDER "╠══════════════════════════════╣"
#define BOX_BOTTOM "╚══════════════════════════════╝"
#define CLEAR_SCREEN "\x1b[1;1H\x1b[2J"

void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
}

long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr,
                   void *data) {
    long const result = ptrace(op, pid, addr, data);
    if (result == -1) {
        die("ptrace failed!");
    }
    return result;
}

void print_regs(struct user_regs_struct regs) {
    puts(BOX_TOP);
    printf(BOX_SIDE "    rax: 0x%016llx   " BOX_SIDE "\n", regs.rax);
    printf(BOX_SIDE "    rbx: 0x%016llx   " BOX_SIDE "\n", regs.rbx);
    printf(BOX_SIDE "    rcx: 0x%016llx   " BOX_SIDE "\n", regs.rcx);
    printf(BOX_SIDE "    rdx: 0x%016llx   " BOX_SIDE "\n", regs.rdx);
    printf(BOX_SIDE "    rdi: 0x%016llx   " BOX_SIDE "\n", regs.rdi);
    printf(BOX_SIDE "    rsi: 0x%016llx   " BOX_SIDE "\n", regs.rsi);
    printf(BOX_SIDE "    r8:  0x%016llx   " BOX_SIDE "\n", regs.r8);
    printf(BOX_SIDE "    r9:  0x%016llx   " BOX_SIDE "\n", regs.r9);
    printf(BOX_SIDE "    r10: 0x%016llx   " BOX_SIDE "\n", regs.r10);
    printf(BOX_SIDE "    r11: 0x%016llx   " BOX_SIDE "\n", regs.r11);
    printf(BOX_SIDE "    r12: 0x%016llx   " BOX_SIDE "\n", regs.r12);
    printf(BOX_SIDE "    r13: 0x%016llx   " BOX_SIDE "\n", regs.r13);
    printf(BOX_SIDE "    r14: 0x%016llx   " BOX_SIDE "\n", regs.r14);
    printf(BOX_SIDE "    r15: 0x%016llx   " BOX_SIDE "\n", regs.r15);
    printf(BOX_SIDE "    rip: 0x%016llx   " BOX_SIDE "\n", regs.rip);
    printf(BOX_SIDE "    rbp: 0x%016llx   " BOX_SIDE "\n", regs.rbp);
    printf(BOX_SIDE "    rsp: 0x%016llx   " BOX_SIDE "\n", regs.rsp);
    puts(BOX_BOTTOM);
    puts("");
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

uint64_t read_word(pid_t const pid, uintptr_t const addr) {
    return ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
}

bool contains_zero_byte(uint64_t n) {
    for (size_t i = 0; i < sizeof(n); i++) {
        if (((n >> (i * CHAR_BIT)) & 0xff) == 0) {
            return true;
        }
    }
    return false;
}

char *read_string(pid_t const pid, uintptr_t const addr) {
    size_t words_read = 0;
    uint64_t *buf = malloc(words_read * sizeof(*buf));
    if (!buf) {
        die("Allocation failed!");
    }
    while (1) {
        buf = realloc(buf, (words_read + 1) * sizeof(*buf));
        if (!buf) {
            die("Allocation failed!");
        }
        buf[words_read] = read_word(pid, addr + (words_read * sizeof(*buf)));
        if (contains_zero_byte(buf[words_read])) {
            break;
        }
        words_read++;
    }
    return (char *)buf;
}

void disas_rip(pid_t pid) {
    csh cs_handle = cs_open_or_die();
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    uint64_t instruction_buffer[2];

    instruction_buffer[0] = read_word(pid, regs.rip);
    instruction_buffer[1] = read_word(pid, regs.rip + 8);

    cs_insn *instructions;
    size_t count =
        cs_disasm(cs_handle, (uint8_t *)instruction_buffer,
                  sizeof(instruction_buffer), regs.rip, 0, &instructions);
    if (count <= 0) {
        die("cs_disasm failed!");
    }
    printf("rip → %s %s\n", instructions[0].mnemonic, instructions[0].op_str);
    cs_free(instructions, count);
    cs_close(&cs_handle);
}

void parse_stack(uintptr_t initial_rsp, uintptr_t end_rsp, pid_t pid) {
    puts(BOX_TOP);

    uint64_t argc = read_word(pid, initial_rsp);

    for (uint64_t i = 0; i < argc; i++) {
        uint64_t const stack_value = read_word(pid, initial_rsp + (argc - i) * 8);
        char *s = read_string(pid, stack_value);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE " (argv[%" PRIu64 "]) → \"%s\"\n", stack_value, argc - i - 1, s);
        free(s);
        puts(BOX_DIVIDER);
    }

    printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE " (argc)\n", argc);

    uintptr_t current_slot = initial_rsp - 8;
    while (current_slot >= end_rsp) {
        puts(BOX_DIVIDER);
        uint64_t stack_value = read_word(pid, current_slot);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE "\n", stack_value);
        current_slot -= 8;
    }
    printf(BOX_BOTTOM " ← rsp\n");
}

void info_regs(struct user_regs_struct regs) {
    print_regs(regs);
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        die("Usage: ./ptracer program_to_exec *[arg]");
    }

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

    struct user_regs_struct initial_regs = {};
    ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &initial_regs);

    uintptr_t initial_rsp = initial_regs.rsp;

    while (1) {
        printf("%s", CLEAR_SCREEN);

        struct user_regs_struct regs = {};
        ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
        info_regs(regs);
        disas_rip(child_pid);
        puts("");
        parse_stack(initial_rsp, regs.rsp, child_pid);
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
