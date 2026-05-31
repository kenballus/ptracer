#define _GNU_SOURCE
#include <fcntl.h>       // for mode_t, open, O_*
#include <limits.h>      // for PAGE_SIZE
#include <stdarg.h>      // for va_list, va_start, va_arg, va_end
#include <stddef.h>      // for size_t, unreachable, NULL
#include <stdint.h>      // for SIZE_MAX, intptr_t, uintptr_t
#include <stdio.h>       // for EOF, puts
#include <stdlib.h>      // for malloc, free
#include <string.h>      // for strlen, strcpy, strcat
#include <sys/mman.h>    // for mmap, MAP_*, PROT_*
#include <sys/syscall.h> // for SYS_*
#include <sys/types.h>   // for ssize_t, off_t
#include <unistd.h>      // for syscall, STDOUT_FILENO, write, _exit

int open(char const *const path, int flags, ...) {
    if (flags & (O_TMPFILE | O_CREAT)) {
        va_list va;
        va_start(va, flags);
        mode_t mode = va_arg(va, mode_t);
        va_end(va);
        return syscall((uintptr_t)path, flags, mode);
    }
    return syscall((uintptr_t)path, flags);
}

ssize_t write(int const fd, void const *const buf, size_t const count) {
    return syscall(SYS_write, fd, buf, count);
}

char *strcpy(char *dst, char const *src) {
    while (*src) {
        *dst = *src;
        src++;
        dst++;
    }
    *dst = *src;
    return dst;
}

char *strcat(char *const dst, char const *const src) {
    return strcpy(dst + strlen(dst), src);
}

size_t strlen(char const *s) {
    size_t result = 0;
    while (*s) {
        result++;
        s++;
    }
    return result;
}

void *mmap(void *const addr, size_t const len, int const prot, int const flags,
           int const fd, off_t const off) {
    return (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}

int munmap(void *const addr, size_t const len) {
    return syscall(SYS_munmap, addr, len);
}

void *malloc(size_t n) {
    if (n > SIZE_MAX - (sizeof(size_t))) {
        return NULL;
    }
    n += sizeof(size_t);
    void *const result = mmap(NULL, n, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if ((intptr_t)result < 0) {
        return NULL;
    }
    *(size_t *)result = n;
    return (char *)result + sizeof(size_t);
}

void free(void *const p) {
    if (!p) {
        return;
    }
    munmap(p, *(size_t *)p);
}

[[noreturn]] void _exit(int const status) {
    syscall(SYS_exit, status);
    unreachable();
}

int puts(char const *s) {
    size_t len = strlen(s);
    while (*s) {
        ssize_t const write_rc = write(STDOUT_FILENO, s, len);
        if (write_rc < 0) {
            return EOF;
        } else {
            len -= write_rc;
            s += write_rc;
        }
    }
    static char const nl = '\n';
    while (1) {
        ssize_t const write_rc = write(STDOUT_FILENO, &nl, sizeof(nl));
        if (write_rc < 0) {
            return EOF;
        } else if (write_rc > 0) {
            break;
        }
    }
    return 0;
}
