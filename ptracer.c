#define _GNU_SOURCE
#include <elf.h>    // for Elf64_Shdr, Elf64_Section
#include <fcntl.h>  // for open, O_RDONLY
#include <gelf.h>   // for GElf_Sym, gelf_getsym
#include <libelf.h> // for elf_version, elf_begin, elf_getscn, elf_nextscn, Elf, Elf_Scn, elf64_getshdr, Elf_Data, elf_getdata
#include <limits.h> // for CHAR_BIT
#include <signal.h> // for SIG*
#include <stdint.h> // for uint*_t
#include <stdio.h>  // for puts, printf, getline, fflush, stdout
#include <stdlib.h> // for exit, EXIT_FAILURE
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

static void die(char const *const s) {
    puts(s);
    exit(EXIT_FAILURE);
}

static long ptrace_or_die(enum __ptrace_request const op, pid_t const pid, void *const addr,
                          void *const data) {
    long const result = ptrace(op, pid, addr, data);
    if (result == -1) {
        die("ptrace failed!");
    }
    return result;
}

static void print_regs(struct user_regs_struct const regs) {
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

static int waitpid_or_die(pid_t const pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid) {
        die("waitpid failed!");
    }
    return wstatus;
}

static bool single_step_until_sigtrap_or_exit(pid_t const pid) {
    int wstatus;
    do {
        ptrace_or_die(PTRACE_SINGLESTEP, pid, nullptr, (void *)0);
        wstatus = waitpid_or_die(pid);
        if (WIFEXITED(wstatus)) {
            printf("Child exited with status %d.\n", WEXITSTATUS(wstatus));
            return true;
        }
    } while (WSTOPSIG(wstatus) != SIGTRAP);
    return false;
}

static uint64_t read_word(pid_t const pid, uintptr_t const addr) {
    return ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)addr, nullptr);
}

static uint8_t read_byte(pid_t const pid, uintptr_t const addr) {
    return read_word(pid, addr);
}

static void write_word(pid_t const pid, uintptr_t const addr, uint64_t const data) {
    ptrace_or_die(PTRACE_POKEDATA, pid, (void *)addr, (void *)data);
}

static void write_byte(pid_t const pid, uintptr_t const addr, uint8_t const data) {
    write_word(pid, addr, (read_word(pid, addr) & ~0xffull) | data);
}

struct breakpoint {
    uintptr_t addr;
    uint8_t original_byte;
    struct breakpoint *next;
};

static void hide_breakpoints(pid_t const pid, struct breakpoint const *const breakpoints) {
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, nullptr, &regs);

    bool have_rewound_rip = false;
    for (struct breakpoint const *curr = breakpoints; curr != NULL; curr = curr->next) {
        if (!have_rewound_rip && curr->addr == regs.rip - 1) {
            regs.rip--;
            ptrace_or_die(PTRACE_SETREGS, pid, nullptr, &regs);
            have_rewound_rip = true;
        }
        write_byte(pid, curr->addr, curr->original_byte);
    }
}

static void show_breakpoints(pid_t const pid, struct breakpoint const *const breakpoints) {
    for (struct breakpoint const *curr = breakpoints; curr != NULL; curr = curr->next) {
        write_byte(pid, curr->addr, 0xcc);
    }
}

static bool continue_until_sigtrap_or_exit(pid_t const pid, struct breakpoint const *const breakpoints) {
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, nullptr, &regs);

    if (read_byte(pid, regs.rip) == 0xcc) { // this is wrong probably?
        hide_breakpoints(pid, breakpoints);
        if (single_step_until_sigtrap_or_exit(pid)) {
            return true;
        }
        show_breakpoints(pid, breakpoints);
    }

    int wstatus;
    do {
        ptrace_or_die(PTRACE_CONT, pid, nullptr, (void *)0);
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

static bool contains_zero_byte(uint64_t const n) {
    for (size_t i = 0; i < sizeof(n); i++) {
        if (((n >> (i * CHAR_BIT)) & 0xff) == 0) {
            return true;
        }
    }
    return false;
}

static void *malloc_or_die(size_t const n) {
    void *const result = malloc(n);
    if (!result) {
        die("Allocation failed!");
    }
    return result;
}

static char *read_string(pid_t const pid, uintptr_t const addr) {
    size_t words_read = 0;
    uint64_t *buf = malloc_or_die(words_read * sizeof(*buf));
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

static void disas_rip(pid_t const pid, uint8_t count) {
    csh cs_handle = cs_open_or_die();
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, nullptr, &regs);

    size_t const insn_buffer_size = count * sizeof(uint64_t) * 2; // each instruction is at most 2 words
    uint64_t *const instruction_buffer = malloc_or_die(insn_buffer_size);
    if (!instruction_buffer) {
        die("Allocation of instruction buffer failed.");
    }

    for (size_t i = 0; i < count * 2 /* each insn is at most 2 words */; i++) {
        instruction_buffer[i] = read_word(pid, regs.rip + i * 8);
    }

    cs_insn *instructions;
    size_t insn_count =
        cs_disasm(cs_handle, (uint8_t *)instruction_buffer,
                  insn_buffer_size, regs.rip, 0, &instructions);
    if (insn_count <= 0) {
        printf("rip → ???\n");
    } else {
        for (size_t i = 0; i < (insn_count < count ? insn_count : count); i++) {
            printf("%s%s %s\n", i == 0 ? "rip → " : "      ", instructions[i].mnemonic, instructions[i].op_str);
        }
        cs_free(instructions, insn_count);
    }
    cs_close(&cs_handle);
    free(instruction_buffer);
}

static void parse_stack(uintptr_t initial_rsp, struct user_regs_struct const regs, pid_t pid) {
    // The initial state of the stack looks like this:
    // |-----------------|
    // | nullptr         |
    // |-----------------|
    // | ...more envp... |
    // |-----------------|
    // | envp[0]         |
    // |-----------------|
    // | nullptr         |
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
                           8 /* for nullptr on the end of argv */;

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

static Elf *open_elf_or_die(int const target_fd) {
    Elf *const result = elf_begin(target_fd, ELF_C_READ, nullptr);
    if (!result) {
        die("elf_begin failed");
    }
    return result;
}

static uintptr_t look_up_symbol(int const target_fd, char const *const sym) {
    Elf *const elf = open_elf_or_die(target_fd);

    uintptr_t result = 0;
    for (Elf_Scn *section = elf_getscn(elf, 0); section; section = elf_nextscn(elf, section)) {
        Elf64_Shdr const *const section_header = elf64_getshdr(section);
        if (section_header->sh_type == SHT_SYMTAB) {
            Elf_Data *const data = elf_getdata(section, nullptr);
            for (size_t i = 0;
                 i < section_header->sh_size / section_header->sh_entsize;
                 i++) {
                GElf_Sym symbol;
                if (!gelf_getsym(data, i, &symbol)) {
                    die("gelf_getsym failed");
                }
                char const *const symbol_name = elf_strptr(elf, section_header->sh_link, symbol.st_name);
                if (!symbol_name) {
                    die("elf_strptr failed");
                }
                if (strcmp(symbol_name, sym) == 0) {
                    result = symbol.st_value;
                    goto done;
                }
            }
        }
    }

done:
    if (elf_end(elf) != 0) {
        die("elf refcount is too high");
    }
    return result;
}

static void display_symbol(int const target_fd, uintptr_t addr) {
    Elf *const elf = open_elf_or_die(target_fd);

    GElf_Sym result_symbol;
    Elf64_Section result_strtab_index;
    bool have_found_a_symbol = false;
    Elf_Scn *section = elf_getscn(elf, 0);
    while (section) {
        Elf64_Shdr const *const section_header = elf64_getshdr(section);
        if (section_header->sh_type == SHT_SYMTAB) {
            Elf_Data *const data = elf_getdata(section, nullptr);
            for (size_t i = 0;
                 i < section_header->sh_size / section_header->sh_entsize;
                 i++) {
                GElf_Sym symbol;
                if (!gelf_getsym(data, i, &symbol)) {
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
        if (!result_symbol_name) {
            die("elf_strptr failed");
        }
        size_t const result_offset = addr - result_symbol.st_value;
        printf("(%s+%zu)\n", result_symbol_name, result_offset);
    }

    if (elf_end(elf) != 0) {
        die("elf refcount is too high");
    }
}

void print_breakpoints(struct breakpoint const *const breakpoints) {
    printf("Breakpoints:");
    for (struct breakpoint const *curr = breakpoints; curr; curr = curr->next) {
        printf(" %p\n", (void *)curr->addr);
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

    pid_t const child_pid = fork();
    if (child_pid == -1) {
        die("fork failed!");
    }
    if (!child_pid) { // child
        ptrace_or_die(PTRACE_TRACEME, -1, nullptr, nullptr);
        execve(target_path, argv + 1, pass_envp ? envp : nullptr);
        die("execve failed!");
    }

    if (WSTOPSIG(waitpid_or_die(child_pid)) != SIGTRAP) {
        die("child stopped for unexpected reason");
    }

    struct user_regs_struct initial_regs = {};
    ptrace_or_die(PTRACE_GETREGS, child_pid, nullptr, &initial_regs);

    uintptr_t initial_rsp = initial_regs.rsp;

    int const target_fd = open(target_path, O_RDONLY);
    if (target_fd < 0) {
        die("couldn't open target");
    }

    struct breakpoint *breakpoints = nullptr;

    while (1) {
        printf("%s", CLEAR_SCREEN);

        struct user_regs_struct regs = {};
        ptrace_or_die(PTRACE_GETREGS, child_pid, nullptr, &regs);
        info_regs(regs);
        display_symbol(target_fd, regs.rip);
        disas_rip(child_pid, 5);
        puts("");
        parse_stack(initial_rsp, regs, child_pid);
        if (breakpoints) {
            print_breakpoints(breakpoints);
        }

        printf("ptracer> ");
        fflush(stdout);

        char *line = nullptr;
        size_t n = 0;
        ssize_t const getline_rc = getline(&line, &n, stdin);
        if (getline_rc == -1) {
            free(line);
            break;
        }
        if (line[getline_rc - 1] == '\n') {
            line[getline_rc - 1] = '\0';
        }

        if (strcmp(line, "") == 0 || strcmp(line, "s") == 0 || strcmp(line, "step") == 0) {
            if (single_step_until_sigtrap_or_exit(child_pid)) {
                free(line);
                break;
            }
        } else if (strncmp(line, "b ", 2) == 0 || strncmp(line, "break ", 6) == 0) {
            char const *operand = strchr(line, ' ');
            while (*operand == ' ') {
                operand++;
            }
            char *end;
            uintptr_t addr = strtoull(operand, &end, 0);
            if (*end != '\0') {
                // leftover junk at the end of the line.
                // probably this isn't an integer.
                // try parsing it as a symbol
                addr = look_up_symbol(target_fd, operand);
                if (!addr) {
                    // Couldn't find the symbol. Just keep going.
                    goto repl_done;
                }
            }

            struct breakpoint const new_breakpoint = {
                .addr = addr,
                .next = nullptr,
                .original_byte = read_byte(child_pid, addr),
            };

            if (!breakpoints) {
                breakpoints = malloc_or_die(sizeof(struct breakpoint));
                *breakpoints = new_breakpoint;
            } else {
                struct breakpoint *curr = breakpoints;
                while (curr->next) {
                    curr = curr->next;
                }
                curr->next = malloc_or_die(sizeof(struct breakpoint));
                *curr->next = new_breakpoint;
            }
        } else if (strcmp(line, "b") == 0 || strcmp(line, "break") == 0) {
            puts("this command needs an argument.");
        } else if ((strcmp(line, "c") == 0) || (strcmp(line, "continue") == 0)) {
            show_breakpoints(child_pid, breakpoints);
            if (continue_until_sigtrap_or_exit(child_pid, breakpoints)) {
                free(line);
                break;
            }
            hide_breakpoints(child_pid, breakpoints);
        }
        // TODO: more commands!

repl_done:
        free(line);
    }

    while (breakpoints) {
        struct breakpoint *next = breakpoints->next;
        free(breakpoints);
        breakpoints = next;
    }

    close(target_fd);
}
