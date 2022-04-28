CC=~/clang-11
CFLAGS= -g -target aarch64-linux-gnu -march=armv8+memtag -static

mte: mte.c
	 $(CC) $(CFLAGS) $? -o $@ 

run:
	~/qemu-aarch64 ./mte

clean:
	rm mte
