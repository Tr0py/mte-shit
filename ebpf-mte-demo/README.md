# EBPF MTE and IR Instrumentation Exp


## Run

```
make 
make run
```

## Expected Results

Crash on Test 3.

Demo: 
```
$ make
~/clang-11 -g -target aarch64-linux-gnu -march=armv8+memtag -static sbpf.c -o ebpf
$ make run
~/qemu-aarch64 ebpf
======================
Initialzing ...
======================
ebpf data on:      	0x5500802000
tagged ebpf data on:	0xf00005500802000
normal data on:    	0x5500802100
======================
eBPF accessing ebpf data on 0xf00005500802000...
======================
Test 0: EBPF accessing tagged ebpf data, without IR instrumentation...
The data on 0xf00005500802000 is 0x12
Test 1: EBPF accessing tagged ebpf data, with IR instrumentation...
[TAG Enforced]	actual load addr	0xf00005500802000
The data on 0xf00005500802000 is 0x12
======================
eBPF accessing *normal* data on 0x5500802100...
======================
Test 2: EBPF accessing non-tagged normal data, without IR instrumentation...
The secret on 0x5500802100 is 0x34
Test 3: EBPF accessing non-tagged normal data, with IR instrumentation...
[TAG Enforced]	actual load addr	0xf00005500802100
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
Makefile:10: recipe for target 'run' failed
make: *** [run] Error 139
```
