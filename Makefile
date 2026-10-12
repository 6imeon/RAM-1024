# Portable build: macOS, Linux, the BSDs, Windows (MinGW / MSYS2 / Cygwin).
# MSVC users: see CMakeLists.txt.  `make check` runs the C conformance
# test only (no Python needed); `make test` also runs the Python suite.
CC ?= cc
CFLAGS ?= -O3
# Required flags live here so `make CFLAGS=...` cannot drop them.
REQ := -Wall -Wextra -std=c99 -fPIC
PYTHON ?= python3

ifeq ($(OS),Windows_NT)
  SYS := Windows
else
  SYS := $(shell uname -s)
endif

ifeq ($(SYS),Darwin)
  SO := dylib
  GPU_OBJ := build/ram_gpu.o
  GPU_LIBS := -framework Metal -framework Foundation
else ifeq ($(SYS),Windows)
  SO := dll
  REQ := $(filter-out -fPIC,$(REQ)) -DRAM_BUILD_DLL
  EXE := .exe
else
  SO := so
  THREAD_LIBS := -lpthread
endif

LIB := build/libram.$(SO)
LABLIB := build/libramlab.$(SO)
GEN := csrc/ram_constants.h csrc/ram_permute_gen.h
CORE_DEPS := csrc/ram1024.c csrc/ram1024.h $(GEN)

all: $(LIB) build/ram_test$(EXE) build/ramsum$(EXE)
lab: $(LABLIB)

build/ram1024.o: $(CORE_DEPS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(REQ) -c -o $@ csrc/ram1024.c

build/ram_gpu.o: csrc/ram_gpu.m csrc/ram1024.h csrc/ram_metal_src.h csrc/ram_constants.h
	@mkdir -p build
	$(CC) -O3 -Wall -fPIC -fobjc-arc -c -o $@ csrc/ram_gpu.m

$(LIB): build/ram1024.o $(GPU_OBJ)
	$(CC) -shared -o $@ $^ $(GPU_LIBS) $(THREAD_LIBS)

# Research lab (attack kernels, reduced rounds allowed): GCC/Clang on POSIX.
$(LABLIB): $(CORE_DEPS) csrc/lab.c csrc/perm_lab.c $(GPU_OBJ)
	$(CC) $(CFLAGS) $(REQ) -std=gnu11 -DRAM_RESEARCH -shared -o $@ csrc/ram1024.c csrc/lab.c csrc/perm_lab.c $(GPU_OBJ) $(GPU_LIBS) $(THREAD_LIBS)

build/ram_test$(EXE): csrc/ram_test.c build/ram1024.o
	$(CC) $(CFLAGS) $(REQ) -o $@ csrc/ram_test.c build/ram1024.o $(THREAD_LIBS)

build/ram_test_research$(EXE): csrc/ram_test.c $(CORE_DEPS)
	$(CC) $(CFLAGS) $(REQ) -DRAM_RESEARCH -o $@ csrc/ram_test.c csrc/ram1024.c $(THREAD_LIBS)

build/ramsum$(EXE): csrc/ramsum.c build/ram1024.o
	$(CC) $(CFLAGS) $(REQ) -o $@ csrc/ramsum.c build/ram1024.o $(THREAD_LIBS)

csrc/ram_permute_gen.h: tools/gen_permute.py
	$(PYTHON) tools/gen_permute.py > $@

csrc/ram_metal_src.h: tools/gen_permute.py
	$(PYTHON) tools/gen_permute.py --metal > $@

csrc/ram_constants.h: tools/gen_constants.py
	$(PYTHON) tools/gen_constants.py > $@

tests/kat.txt: tools/gen_kat.py ramhash/ram1024.py
	$(PYTHON) tools/gen_kat.py > $@

tests/kat_pwhash.txt: tools/gen_kat.py ramhash/ram1024.py
	$(PYTHON) tools/gen_kat.py --pw > $@

check: build/ram_test$(EXE) build/ram_test_research$(EXE)
	./build/ram_test$(EXE) tests/kat.txt tests/kat_pwhash.txt
	./build/ram_test_research$(EXE) tests/kat.txt tests/kat_pwhash.txt

test: all lab check
	$(PYTHON) -m unittest discover -s tests -v

# Slow (~15 s, pure Python; the two files are made in parallel): regenerate both KAT files from the reference
# and require them byte-identical to the committed ones.
reference:
	@mkdir -p build
	$(PYTHON) tools/gen_kat.py > build/kat.ref & $(PYTHON) tools/gen_kat.py --pw > build/kat_pwhash.ref; wait
	cmp build/kat.ref tests/kat.txt && cmp build/kat_pwhash.ref tests/kat_pwhash.txt
	@echo "reference reproduces both KAT files"

clean:
	rm -rf build

.PHONY: all lab check test reference clean
