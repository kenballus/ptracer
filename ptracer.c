#define _GNU_SOURCE
#include <elf.h>    // for Elf64_Shdr, Elf64_Section
#include <fcntl.h>  // for open, O_RDONLY
#include <gelf.h>   // for GElf_Sym, gelf_getsym
#include <libelf.h> // for elf_version, elf_begin, elf_getscn, elf_nextscn, Elf, Elf_Scn, elf64_getshdr, Elf_Data, elf_getdata
#include <limits.h> // for CHAR_BIT
#include <signal.h> // for SIG*
#include <stdint.h> // for uint*_t
#include <stdio.h>  // for puts, printf, getline, fflush, stdout
#include <stdlib.h> // for exit, EXIT_FAILURE, NULL
#include <string.h> // for memcpy, strcmp
#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <sys/user.h>   // for struct user_regs_struct
#include <sys/wait.h>   // for waitpid, WSTOPSIG
#include <unistd.h>     // for fork, pid_t

#include <capstone/capstone.h>

char const BOX_TOP[] = "╔══════════════════════════════╗";
#define BOX_SIDE "║"
char const BOX_DIVIDER[] = "╠══════════════════════════════╣";
#define BOX_BOTTOM "╚══════════════════════════════╝"
char const CLEAR_SCREEN[] = "\x1b[1;1H\x1b[2J";

static void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
}

static long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr,
                          void *data) {
    long const result = ptrace(op, pid, addr, data);
    if (result == -1) {
        die("ptrace failed!");
    }
    return result;
}

static void print_regs(struct user_regs_struct regs) {
    puts(BOX_TOP);
    printf(BOX_SIDE "    rax: 0x%016llx   " BOX_SIDE "\n", regs.rax);
    printf(BOX_SIDE "    rbx: 0x%016llx   " BOX_SIDE "\n", regs.rbx);
    printf(BOX_SIDE "    rcx: 0x%016llx   " BOX_SIDE "\n", regs.rcx);
    printf(BOX_SIDE "    rdx: 0x%016llx   " BOX_SIDE "\n", regs.rdx);
    printf(BOX_SIDE "    rdi: 0x%016llx   " BOX_SIDE "\n", regs.rdi);
    printf(BOX_SIDE "    rsi: 0x%016llx   " BOX_SIDE "\n", regs.rsi);
    printf(BOX_SIDE "     r8: 0x%016llx   " BOX_SIDE "\n", regs.r8);
    printf(BOX_SIDE "     r9: 0x%016llx   " BOX_SIDE "\n", regs.r9);
    printf(BOX_SIDE "    r10: 0x%016llx   " BOX_SIDE "\n", regs.r10);
    printf(BOX_SIDE "    r11: 0x%016llx   " BOX_SIDE "\n", regs.r11);
    printf(BOX_SIDE "    r12: 0x%016llx   " BOX_SIDE "\n", regs.r12);
    printf(BOX_SIDE "    r13: 0x%016llx   " BOX_SIDE "\n", regs.r13);
    printf(BOX_SIDE "    r14: 0x%016llx   " BOX_SIDE "\n", regs.r14);
    printf(BOX_SIDE "    r15: 0x%016llx   " BOX_SIDE "\n", regs.r15);
    printf(BOX_SIDE "    rip: 0x%016llx   " BOX_SIDE "\n", regs.rip);
    printf(BOX_SIDE "    rbp: 0x%016llx   " BOX_SIDE "\n", regs.rbp);
    printf(BOX_SIDE "    rsp: 0x%016llx   " BOX_SIDE "\n", regs.rsp);
    printf(BOX_SIDE " eflags: 0x%016llx   " BOX_SIDE, regs.eflags);
    if (regs.eflags & 0x1) {
        printf(" (CF)");
    }
    if (regs.eflags & 0x4) {
        printf(" (PF)");
    }
    if (regs.eflags & 0x10) {
        printf(" (AF)");
    }
    if (regs.eflags & 0x40) {
        printf(" (ZF)");
    }
    if (regs.eflags & 0x80) {
        printf(" (SF)");
    }
    if (regs.eflags & 0x100) {
        printf(" (TF)");
    }
    if (regs.eflags & 0x200) {
        printf(" (IF)");
    }
    if (regs.eflags & 0x400) {
        printf(" (DF)");
    }
    if (regs.eflags & 0x800) {
        printf(" (OF)");
    }
    if (regs.eflags & 0x3000) {
        printf(" (IOPL)");
    }
    if (regs.eflags & 0x4000) {
        printf(" (NT)");
    }
    if (regs.eflags & 0x10000) {
        printf(" (RF)");
    }
    if (regs.eflags & 0x20000) {
        printf(" (VM)");
    }
    if (regs.eflags & 0x40000) {
        printf(" (AC)");
    }
    if (regs.eflags & 0x80000) {
        printf(" (VIF)");
    }
    if (regs.eflags & 0x100000) {
        printf(" (VIP)");
    }
    if (regs.eflags & 0x200000) {
        printf(" (ID)");
    }

    puts("");
    puts(BOX_BOTTOM);
    puts("");
}

static int waitpid_or_die(pid_t pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid) {
        die("waitpid failed!");
    }
    return wstatus;
}

static bool single_step_until_sigtrap_or_exit(pid_t const pid) {
    int wstatus;
    do {
        ptrace_or_die(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wstatus = waitpid_or_die(pid);
        if (WIFEXITED(wstatus)) {
            printf("Child exited with status %d.\n", WEXITSTATUS(wstatus));
            return true;
        }
    } while (WSTOPSIG(wstatus) != SIGTRAP);
    return false;
}

static csh cs_open_or_die(void) {
    csh cs_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
        die("cs_open failed!");
    }
    return cs_handle;
}

static uint64_t read_word(pid_t const pid, uintptr_t const addr) {
    return ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
}

static bool contains_zero_byte(uint64_t n) {
    for (size_t i = 0; i < sizeof(n); i++) {
        if (((n >> (i * CHAR_BIT)) & 0xff) == 0) {
            return true;
        }
    }
    return false;
}

static char *read_string(pid_t const pid, uintptr_t const addr) {
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

static void disas_rip(pid_t pid) {
    csh cs_handle = cs_open_or_die();
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    // an x86_64 instruction is at most 15 bytes long
    uint64_t instruction_buffer[2];

    instruction_buffer[0] = read_word(pid, regs.rip);
    instruction_buffer[1] = read_word(pid, regs.rip + 8);

    cs_insn *instructions;
    size_t count =
        cs_disasm(cs_handle, (uint8_t *)instruction_buffer,
                  sizeof(instruction_buffer), regs.rip, 0, &instructions);
    if (count <= 0) {
        printf("rip → ???\n");
    } else {
        printf("rip → %s %s\n", instructions[0].mnemonic, instructions[0].op_str);
        cs_free(instructions, count);
    }
    cs_close(&cs_handle);
}

static void parse_stack(uintptr_t initial_rsp, struct user_regs_struct const regs, pid_t pid) {
    // The initial state of the stack looks like this:
    // |-----------------|
    // | NULL            |
    // |-----------------|
    // | ...more envp... |
    // |-----------------|
    // | envp[0]         |
    // |-----------------|
    // | NULL            |
    // |-----------------|
    // | ...more argv... |
    // |-----------------|
    // | argv[0]         |
    // |-----------------|
    // | argc            |
    // |-----------------| <-- rsp

    puts(BOX_TOP);

    uint64_t argc = read_word(pid, initial_rsp);

    uintptr_t envp_start = initial_rsp + 8 /* for argc */ +
                           argc * 8 /* for argv */ +
                           8 /* for NULL on the end of argv */;

    size_t envc = 0;
    while (read_word(pid, envp_start + envc * 8)) {
        envc++;
    }

    printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE "\n",
           read_word(pid, envp_start - 8));
    puts(BOX_DIVIDER);

    for (size_t i = 0; i < envc; i++) {
        uintptr_t const stack_value = read_word(pid, envp_start + i * 8);
        char *const s = read_string(pid, stack_value);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE
                        " (envp[%" PRIu64 "]) → \"%s\"\n",
               stack_value, envc - i - 1, s);
        free(s);
        puts(BOX_DIVIDER);
    }

    printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE "\n",
           read_word(pid, initial_rsp + (argc + 1) * 8));
    puts(BOX_DIVIDER);

    for (uint64_t i = 0; i < argc; i++) {
        uintptr_t const stack_value =
            read_word(pid, initial_rsp + (argc - i) * 8);
        char *const s = read_string(pid, stack_value);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE
                        " (argv[%" PRIu64 "]) → \"%s\"\n",
               stack_value, argc - i - 1, s);
        free(s);
        puts(BOX_DIVIDER);
    }

    printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE " (argc)\n", argc);

    uintptr_t current_slot = initial_rsp - 8;
    while (current_slot >= regs.rsp) {
        puts(BOX_DIVIDER);
        uint64_t const stack_value = read_word(pid, current_slot);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE "\n",
               stack_value);
        current_slot -= 8;
    }
    printf(BOX_BOTTOM " ← rsp\n");
}

static void info_regs(struct user_regs_struct regs) {
    print_regs(regs);
}

static void get_symbol_offset(int const target_fd, uintptr_t addr) {
    Elf *const elf = elf_begin(target_fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        die("elf_begin failed");
    }

    GElf_Sym result_symbol;
    Elf64_Section result_strtab_index;
    bool have_found_a_symbol = false;
    Elf_Scn *section = elf_getscn(elf, 0);
    while (section != NULL) {
        Elf64_Shdr const *const section_header = elf64_getshdr(section);
        if (section_header->sh_type == SHT_SYMTAB) {
            Elf_Data *const data = elf_getdata(section, NULL);
            for (size_t i = 0;
                 i < section_header->sh_size / section_header->sh_entsize;
                 i++) {
                GElf_Sym symbol;
                if (gelf_getsym(data, i, &symbol) == NULL) {
                    die("gelf_getsym failed");
                }
                if (!have_found_a_symbol ||
                    (addr - result_symbol.st_value > addr - symbol.st_value)) {
                    result_symbol = symbol;
                    have_found_a_symbol = true;
                    result_strtab_index = section_header->sh_link;
                }
            }
        }

        section = elf_nextscn(elf, section);
    }

    if (have_found_a_symbol) {
        char const *const result_symbol_name =
            elf_strptr(elf, result_strtab_index, result_symbol.st_name);
        if (result_symbol_name == NULL) {
            die("elf_strptr failed");
        }
        size_t const result_offset = addr - result_symbol.st_value;
        printf("      (%s+%zu)\n", result_symbol_name, result_offset);
    }

    if (elf_end(elf) != 0) {
        die("elf refcount is too high");
    }
}

int main(int argc, char *const *argv, char *const *const envp) {
    if (argc <= 1) {
        die("Usage: ./ptracer [--pass-envp] program_to_exec *[arg]");
    }
    bool const pass_envp = strcmp(argv[1], "--pass-envp") == 0;
    if (pass_envp) {
        argv++;
    }
    char const *const target_path = argv[1];

    if (elf_version(EV_CURRENT) == EV_NONE) {
        die("couldn't initialize libelf");
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        die("fork failed!");
    }
    if (!child_pid) { // child
        ptrace_or_die(PTRACE_TRACEME, -1, NULL, NULL);
        execve(target_path, argv + 1, pass_envp ? envp : NULL);
        die("execve failed!");
    }

    if (WSTOPSIG(waitpid_or_die(child_pid)) != SIGTRAP) {
        die("child stopped for unexpected reason");
    }

    struct user_regs_struct initial_regs = {};
    ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &initial_regs);

    uintptr_t initial_rsp = initial_regs.rsp;

    int const target_fd = open(target_path, O_RDONLY);
    if (target_fd < 0) {
        die("couldn't open target");
    }

    while (1) {
        printf("%s", CLEAR_SCREEN);

        struct user_regs_struct regs = {};
        ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
        info_regs(regs);
        disas_rip(child_pid);
        get_symbol_offset(target_fd, regs.rip);
        puts("");
        parse_stack(initial_rsp, regs, child_pid);

        printf("ptracer> ");
        fflush(stdout);

        char *line = NULL;
        size_t n = 0;
        ssize_t const getline_rc = getline(&line, &n, stdin);
        if (getline_rc == -1) {
            free(line);
            break;
        }
        if (line[getline_rc - 1] == '\n') {
            line[getline_rc - 1] = '\0';
        }

        if (strcmp(line, "") == 0 || strcmp(line, "step") == 0) {
            if (single_step_until_sigtrap_or_exit(child_pid)) {
                free(line);
                break;
            }
        } // TODO: more commands!

        free(line);
    }
    close(target_fd);
}
