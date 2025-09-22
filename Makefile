CC ?= gcc
CFLAGS ?= -O0 -fsanitize=address,undefined -Wall -Wextra -Wpedantic -Wvla -Wshadow -g

.PHONY: all clean fmt

all: tracer target

tracer: tracer.c
	$(CC) $(CFLAGS) -lcapstone $^ -o $@

target: target.s
	$(CC) -static -nostdlib $^ -o $@

clean:
	rm -f tracer target

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c
