---
title: "glibc all in one"
date: 2025-01-06
lastmod: 2025-01-21T17:09:11+08:00
type: posts
draft: false
summary: "Using [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one) combined with [patchelf](https://github.com/NixOS/patchelf) or the `LD_PRELOAD` environment variable for fast glibc version switching."
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - heap
  - glibc
---

Download glibc-all-in-one:

```bash
git clone https://github.com/matrix1001/glibc-all-in-one
cd glibc-all-in-one
```

Determine the libc version provided by the challenge:

```bash
strings libc.so.6 | grep "GNU C Library"
```

Two methods to obtain a specific glibc version:

## Compile glibc

```bash
apt install build-essential libssl-dev libgdbm-dev libdb-dev libexpat-dev libncurses5-dev libbz2-dev zlib1g-dev gawk bison binutils texinfo

./build 2.27 amd64
```

## Extract from Downloaded Packages

```bash
./download 2.27-3ubuntu1_amd64

ls -alh ./libs/
```

Two methods to make an ELF load a specific libc:

## Using patchelf to Modify the ELF to Load a Specific libc

Download [patchelf](https://github.com/NixOS/patchelf).

```bash
patchelf --add-needed /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6 ./ezheap
patchelf --set-interpreter /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 ./ezheap
```

The original file is modified in-place.

## Using the LD_PRELOAD Environment Variable to Load a Specific libc

Use LD_PRELOAD in your script to load a specific libc without modifying the ELF file directly:

```python
libc_version = '2.27-3ubuntu1.6'
file = './ezheap'
p = process([f"/root/glibc-all-in-one/libs/{libc_version}/ld-linux-x86-64.so.2",
             file], env={"LD_PRELOAD": f"/root/glibc-all-in-one/libs/{libc_version}/libc.so.6"})
```

## Compiling with a Specific Version

Using my modified [glibc-all-in-one](https://github.com/0xlane/glibc-all-in-one), download the specified glibc version:

```bash
./download 2.27-3ubuntu1_amd64
```

Use this `Makefile` to compile (a compatible gcc compiler version is required — versions that are too new will cause errors):

```makefile
# Specify compiler
CXX := g++-9

# Source file
SRC := main.cpp

# Output executable name
TARGET := main

# Custom glibc paths
GLIBC_INCLUDE := /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/.dev/usr/include
GLIBC_LIB := /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64

# Compilation flags
CXXFLAGS := -I$(GLIBC_INCLUDE) -std=c++11 -D__STRICT_ANSI__
LDFLAGS := -L$(GLIBC_LIB) -Wl,-rpath=$(GLIBC_LIB) -Wl,--dynamic-linker=$(GLIBC_LIB)/ld-linux-x86-64.so.2

# Build rule
$(TARGET): $(SRC)
        $(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) -ldl -lpthread -lm -nostartfiles

# Clean generated files
.PHONY: clean
clean:
        rm -f $(TARGET)
```

Or use the g++ command directly:

```bash
g++-9 -I/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/.dev/usr/include -L/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ -Wl,--rpath=/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 -Wl,--dynamic-linker=/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 -nostartfiles -o main main.cpp
```
