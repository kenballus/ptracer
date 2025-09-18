#include <signal.h>     // for SIG*
#include <stdint.h>     // for uint*_t
#include <stdio.h>      // for puts, printf
#include <stdlib.h>     // for exit, EXIT_FAILURE, NULL
#include <string.h>     // for memcpy
#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <sys/user.h>   // for struct user_regs_struct
#include <sys/wait.h>   // for waitpid, WSTOPSIG
#include <unistd.h>     // for fork, pid_t

#include <capstone/capstone.h>

#define VRT "\xe2\x95\x91"  // ║
#define HRZ2 "\xe2\x95\x90" // ═
#define HRZ1 "\xe2\x94\x80" // ─
#define TUP "\xe2\x95\xa9"  // ╩
#define TDWN "\xe2\x95\xa4" // ╤
#define INTR "\xe2\x95\xab" // ╫
#define TL "\xe2\x95\x94"   // ╔
#define TR "\xe2\x95\x97"   // ╗
#define BL "\xe2\x95\x9a"   // ╚
#define BR "\xe2\x95\x9d"   // ╝
//
#define AR "\xe2\x86\x92" // →
#define DV "\xe2\x95\x8d" // ╍

#define INSN_MAX_BYTES 16
uint8_t s[INSN_MAX_BYTES];

void die(char *s) {
  puts(s);
  exit(EXIT_FAILURE);
}

long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr,
                   void *data) {
  if (ptrace(op, pid, addr, data) == -1) {
    die("ptrace failed!");
  }
}

void print_regs(struct user_regs_struct regs) {
  puts("+--------Register Info---------+");
  printf("| rax: 0x%016llx      |\n", regs.rax);
  printf("| rbx: 0x%016llx      |\n", regs.rbx);
  printf("| rcx: 0x%016llx      |\n", regs.rcx);
  printf("| rdx: 0x%016llx      |\n", regs.rdx);
  printf("| rdi: 0x%016llx      |\n", regs.rdi);
  printf("| rsi: 0x%016llx      |\n", regs.rsi);
  printf("| r8:  %llu                       |\n", regs.r8);
  printf("| r9:  %llu                       |\n", regs.r9);
  printf("| r10: %llu                       |\n", regs.r10);
  printf("| r11: %llu                       |\n", regs.r11);
  printf("| r12: %llu                       |\n", regs.r12);
  printf("| r13: %llu                       |\n", regs.r13);
  printf("| r14: %llu                       |\n", regs.r14);
  printf("| r15: %llu                       |\n", regs.r15);
  printf("| rip: 0x%016llx      |\n", regs.rip);
  printf("| rbp: 0x%016llx      |\n", regs.rbp);
  printf("| rsp: 0x%016llx      |\n", regs.rsp);
  puts("+------------------------------+");
  printf("\n");
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

  for (int i = 0; i < 2; i++) {
    uint64_t data =
        ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)(regs.rip + i * 8), NULL);
    memcpy(s + i * 8, &data, 8);
  }

  cs_insn *instructions;
  size_t count =
      cs_disasm(cs_handle, s, sizeof(s) - 1, regs.rip, 0, &instructions);
  if (count <= 0) {
    die("cs_disasm failed!");
  }
  printf("-> %s %s\n", instructions[0].mnemonic, instructions[0].op_str);
  cs_free(instructions, count);
  cs_close(&cs_handle);
}

void place_top() {
  printf("%s", TL);
  for (int i = 0; i < 30; i++) {
    printf("%s", HRZ2);
  }
  printf("%s \n", TR);
}

void place_byte_box(void *ref_rsp, void *start_rsp, void *current_rsp,
                    pid_t pid, unsigned long long stack_data) {
  if (ref_rsp == start_rsp) {
    place_top();
  }
  printf("%s", VRT);
  for (int i = 0; i < 30; i++) {
    if (i < 6) {
      printf(" ");
    } else if (i == 7) {
      printf("0x%016lx", stack_data);
    } else if (i > 7 && i < 14) {
      printf(" ");
    } else if (i == 17) {
      printf("%s\n", VRT);
    }
  }

  if (ref_rsp == current_rsp) {
    printf("%s", BL);
    for (int i = 0; i < 30; i++) {
      printf("%s", HRZ2);
    }
    if (ref_rsp == start_rsp) {
      printf("%s %s rsp [ %p ]** \n", BR, AR, ref_rsp);
    } else {
      printf("%s %s rsp [ %p ] \n", BR, AR, ref_rsp);
    }
  } else {
    printf("%s", VRT);
    for (int i = 0; i < 30; i++) {
      printf("-");
    }
    if (ref_rsp == start_rsp) {
      printf("%s %s     [ %p ]** \n", VRT, AR, ref_rsp);
    } else {
      printf("%s %s     [ %p ] \n", VRT, AR, ref_rsp);
    }
  }
}

void parse_stack(void *start_rsp, void *current_rsp, pid_t pid) {

  void *ref_ptr = start_rsp;
  unsigned long long stack_value;
  printf("Program Start **\n");
  while (ref_ptr >= current_rsp) {
    stack_value = ptrace(PTRACE_PEEKDATA, pid, ref_ptr, NULL);
    place_byte_box(ref_ptr, start_rsp, current_rsp, pid, stack_value);
    ref_ptr = ref_ptr - 8;
  }
}

void info_regs(struct user_regs_struct regs) { print_regs(regs); }

int main(int argc, char **argv) {
  printf("\e[1;1H\e[2J"); // clear screen

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

  struct user_regs_struct regs = {};
  unsigned long long topof_stack;
  ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);

  topof_stack = regs.rsp;
  void *pointer = (void *)regs.rsp;

  info_regs(regs);

  parse_stack((void *)topof_stack, pointer, child_pid);
  disas_rip(child_pid);
  getchar();

  while (1) {

    printf("\e[1;1H\e[2J");

    ptrace_or_die(PTRACE_SINGLESTEP, child_pid, NULL, NULL);

    int const wstatus = waitpid_or_die(child_pid);
    if (WIFEXITED(wstatus)) {
      break;
    }
    ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
    pointer = (void *)regs.rsp;

    info_regs(regs);

    parse_stack((void *)topof_stack, pointer, child_pid);
    disas_rip(child_pid);

    getchar();

    check_signal(WSTOPSIG(wstatus), SIGTRAP);
  }
  puts("Child exited.");
}
