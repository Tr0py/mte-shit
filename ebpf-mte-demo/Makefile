CC=~/clang-11
CFLAGS= -g -target aarch64-linux-gnu -march=armv8+memtag -static

all: ebpf

ebpf: sbpf.c
	 $(CC) $(CFLAGS) $? -o $@ 

run:
	~/qemu-aarch64 ebpf

clean:
	rm ebpf
