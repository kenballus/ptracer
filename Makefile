CC ?= gcc
CFLAGS ?= -O0

.PHONY: all

all: tracer target

tracer: tracer.c
	$(CC) $(CFLAGS) -lcapstone $^ -o $@

target: target.s
	$(CC) -static -nostdlib $^ -o $@

clean:
	rm tracer target
