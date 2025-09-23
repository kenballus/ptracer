# ptracer

A stack viewer for x86\_64 Linux.

## Getting Started

1. Run `make`. This will build both `tracer` and `target`, a simple assembly program for basic testing.
2. Run `./tracer ./target hello ptracer`. You should see something like this:
```
╔══════════════════════════════╗
║    rax: 0x0000000000000000   ║
║    rbx: 0x0000000000000000   ║
║    rcx: 0x0000000000000000   ║
║    rdx: 0x0000000000000000   ║
║    rdi: 0x0000000000000000   ║
║    rsi: 0x0000000000000000   ║
║    r8:  0x0000000000000000   ║
║    r9:  0x0000000000000000   ║
║    r10: 0x0000000000000000   ║
║    r11: 0x0000000000000000   ║
║    r12: 0x0000000000000000   ║
║    r13: 0x0000000000000000   ║
║    r14: 0x0000000000000000   ║
║    r15: 0x0000000000000000   ║
║    rip: 0x0000000000401000   ║
║    rbp: 0x0000000000000000   ║
║    rsp: 0x00007ffd5a463f40   ║
╚══════════════════════════════╝

rip → push 0x14

╔══════════════════════════════╗
║      0x00007ffd5a465fe7      ║ (argv[2]) → "ptracer"
╠══════════════════════════════╣
║      0x00007ffd5a465fe1      ║ (argv[1]) → "hello"
╠══════════════════════════════╣
║      0x00007ffd5a465fd8      ║ (argv[0]) → "./target"
╠══════════════════════════════╣
║      0x0000000000000003      ║ (argc)
╚══════════════════════════════╝ ← rsp
```
This indicates that the traced program (`./target`, with arguments `hello` and `ptracer`) is running and paused just before executing its first instruction, `push 0x14`.

3. Press enter to single-step. You should now see something like this:
```
╔══════════════════════════════╗
║    rax: 0x0000000000000000   ║
║    rbx: 0x0000000000000000   ║
║    rcx: 0x0000000000000000   ║
║    rdx: 0x0000000000000000   ║
║    rdi: 0x0000000000000000   ║
║    rsi: 0x0000000000000000   ║
║    r8:  0x0000000000000000   ║
║    r9:  0x0000000000000000   ║
║    r10: 0x0000000000000000   ║
║    r11: 0x0000000000000000   ║
║    r12: 0x0000000000000000   ║
║    r13: 0x0000000000000000   ║
║    r14: 0x0000000000000000   ║
║    r15: 0x0000000000000000   ║
║    rip: 0x0000000000401002   ║
║    rbp: 0x0000000000000000   ║
║    rsp: 0x00007ffd5a463f38   ║
╚══════════════════════════════╝

rip → push 0x1e

╔══════════════════════════════╗
║      0x00007ffd5a465fe7      ║ (argv[2]) → "ptracer"
╠══════════════════════════════╣
║      0x00007ffd5a465fe1      ║ (argv[1]) → "hello"
╠══════════════════════════════╣
║      0x00007ffd5a465fd8      ║ (argv[0]) → "./target"
╠══════════════════════════════╣
║      0x0000000000000003      ║ (argc)
╠══════════════════════════════╣
║      0x0000000000000014      ║
╚══════════════════════════════╝ ← rsp
```
Note that `rsp` has decreased by 8, and `0x0000000000000014` has shown up in the stack view, demonstrating the effect of the `push`.

4. Continue stepping through the program, observing the effects of each instruction on the stack and registers.
