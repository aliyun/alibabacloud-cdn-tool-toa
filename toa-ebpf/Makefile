CLANG ?= clang
ARCH := $(shell uname -m)

EXEC = toa
BPF_KERN_SRC = $(EXEC)-kern.c
BPF_KERN_DEP = toa.h
BPF_OBJECT = $(EXEC)-kern.o


.PHONY: all
all: $(BPF_OBJECT)

.PHONY: clean
clean:
	rm -rf *.ll *.o

$(BPF_OBJECT): $(BPF_KERN_SRC) $(BPF_KERN_DEP)
	$(CLANG) -S -target bpf -D__$(ARCH)__ \
		     -Wno-compare-distinct-pointer-types \
		     -O2 -emit-llvm -c -g -o $(EXEC).kern.ll $(BPF_KERN_SRC)
	llc -march=bpf -filetype=obj -o $@ $(EXEC).kern.ll