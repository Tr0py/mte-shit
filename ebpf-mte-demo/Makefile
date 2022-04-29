CC=~/clang-11
CFLAGS= -g -target aarch64-linux-gnu -march=armv8+memtag -static

all: ebpf sbpf

ebpf: sbpf.c
	 $(CC) $(CFLAGS) $? -o $@ 

sbpf: sbpf.c
	 $(CC) $(CFLAGS) $? -o $@  -DSBPF_LDST

run-ebpf:
	~/qemu-aarch64 ebpf

run-sbpf:
	~/qemu-aarch64 sbpf

clean:
	rm mte
