CC := clang
CFLAGS := -target bpf -Wall
DFLAGS := -O2 -g

SRC := $(wildcard *.c)
XDP_OBJ := $(patsubst %.c, %.o, $(SRC))

all: $(XDP_OBJ)

%.o : %.c
	$(CC) $(CFLAGS) $(DFLAGS) -c $<

clean:
	rm $(XDP_OBJ) || true

#
# Reference
# ------------------------------------
# clang -S \
#     -target bpf \
#     -D __BPF_TRACING__ \
#     -I../libbpf/src//build/usr/include/ -I../headers/ \
#     -Wall \
#     -Wno-unused-value \
#     -Wno-pointer-sign \
#     -Wno-compare-distinct-pointer-types \
#     -Werror \
#     -O2 -emit-llvm -c -g -o xdp_prog_kern_03.ll xdp_prog_kern_03.c
# llc -march=bpf -filetype=obj -o xdp_prog_kern_03.o xdp_prog_kern_03.ll
#
# Kernel build
# clang  -nostdinc -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi \
#            -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi \
#            -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h \
#       -fno-stack-protector -g \
#       -I$HOME/Desktop/linux-next/samples/bpf -I./tools/testing/selftests/bpf/ \
#       -I$HOME/Desktop/linux-next/samples/bpf/libbpf/include \
#       -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
#       -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
#       -Wno-gnu-variable-sized-type-not-at-end \
#       -Wno-address-of-packed-member -Wno-tautological-compare \
#       -Wno-unknown-warning-option  \
#       -fno-asynchronous-unwind-tables \
#       -I./samples/bpf/ -include asm_goto_workaround.h \
#       -O2 -emit-llvm -Xclang -disable-llvm-passes -c $HOME/Desktop/linux-next/samples/bpf/lwt_len_hist_kern.c -o - | \
#       opt -O2 -mtriple=bpf-pc-linux | llvm-dis | \
#       llc -march=bpf  -filetype=obj -o $HOME/Desktop/linux-next/samples/bpf/lwt_len_hist_kern.o
#
