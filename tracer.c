#include <ctype.h>      // for isprint
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

struct Stack {
  int byte[4096];
  int len;
};

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
  puts("+-****** Register Info *********");
  printf("| rax: %llu\n", regs.rax);
  printf("| rbx: %llu\n", regs.rbx);
  printf("| rcx: %llu\n", regs.rcx);
  printf("| rdx: %llu\n", regs.rdx);
  printf("| rdi: %llu\n", regs.rdi);
  printf("| rsi: %llu\n", regs.rsi);
  printf("| r8:  %llu\n", regs.r8);
  printf("| r9:  %llu\n", regs.r9);
  printf("| r10: %llu\n", regs.r10);
  printf("| r11: %llu\n", regs.r11);
  printf("| r12: %llu\n", regs.r12);
  printf("| r13: %llu\n", regs.r13);
  printf("| r14: %llu\n", regs.r14);
  printf("| r15: %llu\n", regs.r15);
  printf("| rip: %p\n", regs.rip);
  printf("| rbp: %p\n", regs.rbp);
  printf("| rsp: %p\n", regs.rsp);
  puts("+-****************************");
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

void place_top(unsigned long long topof_stack,
               unsigned long long base_pointer) {
  printf("%s", TL);
  for (int i = 0; i < 30; i++) {
    printf("%s", HRZ2);
  }
  printf("%s \n", TR);
}

void place_bottom(unsigned long long topof_stack,
                  unsigned long long base_pointer) {

  printf("%s", BL);
  for (int i = 0; i < 30; i++) {
    printf("%s", DV);
  }
  printf("%s %s rsp [ %p ], rbp [ %p ]\n", BR, AR, topof_stack, base_pointer);
}

void place_byte_box(void *start_rsp, void *current_rsp, pid_t pid,
                    struct Stack *s1) {

  unsigned long long stack_value;
  int remainder;
  int quotient;
  int diff = (int)(start_rsp - current_rsp);

  if (diff <= 8) {
    printf("%p\n", start_rsp - 8);

    stack_value = ptrace(PTRACE_PEEKDATA, pid, start_rsp - 8, NULL);

    for (int i = 0; i < 8; i++) {
      unsigned char byte = (stack_value >> (8 * i)) & 0xFF;
      printf("0x%02x '%c'", byte, isprint(byte) ? byte : '.');
    }
  } else {
    remainder = diff % 8;
    printf("remainder: %d \n", remainder);
    if (remainder == 0) {
      quotient = diff / 8;
      for (int i = 0; i < quotient; i++) {
        stack_value = ptrace(PTRACE_PEEKDATA, pid, current_rsp, NULL);
        for (int i = 0; i < 8; i++) {
          unsigned char byte = (stack_value >> (8 * i)) & 0xFF;
          printf("0x%02x '%c' ", byte, isprint(byte) ? byte : '.');
        }
      }
    } else {
      quotient = (diff / 8);
      // printf("quotient: %d \n", quotient);
      void *ptr = current_rsp;
      int i = 0;
      s1->len = 0;
      for (; i < quotient; i++) {
        // printf("%d\n", i);
        // printf("%p\n", ptr - (8 * i));

        stack_value = ptrace(PTRACE_PEEKDATA, pid, ptr, NULL);
        for (int i = 0; i < 8; i++) {
          unsigned char byte = (stack_value >> (8 * i)) & 0xFF;
          // pritf("0x%02x '%c' ", byte, isprint(byte) ? byte : '.');
          s1->byte[i] = byte;
          s1->len++;
          // printf("\nstruct test: %x \n", s1.byte[i]);
        }
        ptr = ptr + 8;
      }
      stack_value = ptrace(PTRACE_PEEKDATA, pid, ptr - 8, NULL);
      printf("stack_value: 0x%016lx \n", stack_value);
      for (; i < diff; i++) {
        unsigned char byte = (stack_value >> (8 * remainder)) & 0xFF;
        // s1.byte[i] = byte;
        // s1.len++;
        // printf("\nstruct test: %x \n", s1.byte[i]);
      }

      for (int i = 0; i < s1->len; i++) {
        printf("\nstruct test: %x \n", s1->byte[i]);
      }
    }
  }
}

void place_bars() {

  printf("%s", VRT);
  for (int i = 0; i < 30; i++) {
    printf(" ");
  }
  printf("%s\n", VRT);
}

void start_stack(unsigned long long topof_stack,
                 unsigned long long base_pointer) {

  puts("Program Start");
  place_top(topof_stack, base_pointer);
  place_bars();
  place_bottom(topof_stack, base_pointer);
}

void info_regs(struct user_regs_struct regs) { print_regs(regs); }

int main(int argc, char **argv) {
  printf("\e[1;1H\e[2J");

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
  int flag = 0;
  unsigned long long stack_value;

  struct Stack s1;
  // Struct Stack *ptr = &s1;
  s1.len = 0;

  struct user_regs_struct regs = {};
  unsigned long long topof_stack;
  int stack_increaseBy = 0;
  ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
  info_regs(regs);
  disas_rip(child_pid);
  void *pointer = (void *)regs.rsp;
  topof_stack = regs.rsp;
  start_stack(topof_stack, regs.rbp);
  stack_value = ptrace(PTRACE_PEEKDATA, child_pid, pointer, NULL);
  printf("value on stack at rsp[%016p]: 0x%016lx\n", pointer, stack_value);
  for (int i = 0; i < 8; i++) {
    unsigned char byte = (stack_value >> (8 * i)) & 0xFF;
    printf("Byte %d: 0x%02x '%c' \n", i, byte, isprint(byte) ? byte : '.');
  }
  getchar();

  while (1) {

    printf("\e[1;1H\e[2J");

    ptrace_or_die(PTRACE_SINGLESTEP, child_pid, NULL, NULL);

    int const wstatus = waitpid_or_die(child_pid);
    if (WIFEXITED(wstatus)) {
      break;
    }
    ptrace_or_die(PTRACE_GETREGS, child_pid, NULL, &regs);
    info_regs(regs);
    disas_rip(child_pid);
    pointer = (void *)regs.rsp;
    stack_value = ptrace(PTRACE_PEEKDATA, child_pid, pointer, NULL);
    printf("start rsp: %p \n", topof_stack);
    printf("value on stack at rsp[%016p]: 0x%016lx\n", pointer, stack_value);
    int stack_increaseBy = (int)((void *)topof_stack - pointer);
    printf("stack_increasedBy: %d \n", stack_increaseBy);
    int diff = stack_increaseBy - s1.len;
    printf("stack diff: %d\n", diff);
    for (int i = 0; i < 8; i++) {
      unsigned char byte = (stack_value >> (8 * i)) & 0xFF;
      printf("%x\n", stack_value >> (8 * i));
      printf("Byte %d: 0x%02x '%c'\n", i, byte, isprint(byte) ? byte : '.');
      s1.byte[s1.len] = byte;
      s1.len++;
    }
    for (int i = 0; i < 8; i++) {
      printf("struct test: 0x%x\n", s1.byte[i]);
    }

    // place_byte_box((void *)topof_stack, pointer, child_pid, &s1);
    getchar();

    check_signal(WSTOPSIG(wstatus), SIGTRAP);
  }
  puts("Child exited.");
}
