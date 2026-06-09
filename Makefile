CC ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Wshadow -g -std=c23 -fsanitize=address,undefined

TARGET_CFLAGS := -O0 -Wall -Wextra -Wpedantic -Wvla -Wshadow -g -static -nostdlib -std=c23 -fno-stack-protector

.PHONY: all clean fmt

all: ptracer examples/echo/echo examples/env/env

ptracer: ptracer.c
	$(CC) $(CFLAGS) -lcapstone -lelf $^ -o $@

examples/echo/echo: examples/echo/echo.c mini_libc/libc.S mini_libc/libc.c
	$(CC) $(TARGET_CFLAGS) $^ -o $@

examples/env/env: examples/env/env.c mini_libc/libc.S mini_libc/libc.c
	$(CC) $(TARGET_CFLAGS) $^ -o $@

clean:
	rm -f ptracer examples/echo/echo example/env/env

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i **/*.c **/*.h
