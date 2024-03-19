LLVM_DIR = $(realpath ../../obelix-build/bin)
CC = $(LLVM_DIR)/clang
LLD = $(LLVM_DIR)/ld.lld

OPTFLAGS = -O2
LDFLAGS = -fno-semantic-interposition -fuse-ld=$(LLD)

bin/libobelixeval-10.so: libobelixeval.c
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=10 -mllvm -fobelix-stage=1
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=10 -mllvm -fobelix-stage=2
bin/libobelixeval-20.so: libobelixeval.c
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=20 -mllvm -fobelix-stage=1
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=20 -mllvm -fobelix-stage=2
bin/libobelixeval-30.so: libobelixeval.c
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=30 -mllvm -fobelix-stage=1
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=30 -mllvm -fobelix-stage=2
bin/libobelixeval-40.so: libobelixeval.c
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=40 -mllvm -fobelix-stage=1
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=40 -mllvm -fobelix-stage=2
bin/libobelixeval-50.so: libobelixeval.c
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=50 -mllvm -fobelix-stage=1
	$(CC) $< -fPIC -shared $(LDFLAGS) -o $@ -std=c2x $(OPTFLAGS) -fsanitize=obelix -mllvm -fobelix-level=50 -mllvm -fobelix-stage=2

bin/%-10: %.c benchmark.h bin/libobelixeval-10.so
	$(CC) $< -o $@ -std=c2x -O2 -L$(PWD)/bin -lobelixeval-10 -fsanitize=obelix -mllvm -fobelix-stage=1
bin/%-20: %.c benchmark.h bin/libobelixeval-20.so
	$(CC) $< -o $@ -std=c2x -O2 -L$(PWD)/bin -lobelixeval-20 -fsanitize=obelix -mllvm -fobelix-stage=1
bin/%-30: %.c benchmark.h bin/libobelixeval-30.so
	$(CC) $< -o $@ -std=c2x -O2 -L$(PWD)/bin -lobelixeval-30 -fsanitize=obelix -mllvm -fobelix-stage=1
bin/%-40: %.c benchmark.h bin/libobelixeval-40.so
	$(CC) $< -o $@ -std=c2x -O2 -L$(PWD)/bin -lobelixeval-40 -fsanitize=obelix -mllvm -fobelix-stage=1
bin/%-50: %.c benchmark.h bin/libobelixeval-50.so
	$(CC) $< -o $@ -std=c2x -O2 -L$(PWD)/bin -lobelixeval-50 -fsanitize=obelix -mllvm -fobelix-stage=1

library: makedirs bin/libobelixeval-10.so bin/libobelixeval-20.so bin/libobelixeval-30.so bin/libobelixeval-40.so bin/libobelixeval-50.so
matmul: makedirs bin/matmul-10 bin/matmul-20 bin/matmul-30 bin/matmul-40 bin/matmul-50
modexp: makedirs bin/modexp-10 bin/modexp-20 bin/modexp-30 bin/modexp-40 bin/modexp-50

all: library matmul modexp

makedirs:
	mkdir -p bin

clean:
	rm -f bin/*

.PHONY: library matmul modexp
.PHONY: all
.PHONY: makedirs clean