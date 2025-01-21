---
title: "glibc all in one"
date: 2025-01-06
lastmod: 2025-01-21T17:09:11+08:00
type: posts
draft: false
summary: "使用 [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one) 结合 [patchelf](https://github.com/NixOS/patchelf) 或 `LD_PRELOAD` 环境变量实现 glibc 多版本快速切换。"
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - heap
  - glibc
---

下载 glibc-all-in-one：

```bash
git clone https://github.com/matrix1001/glibc-all-in-one
cd glibc-all-in-one
```

判断题目给出的 libc 版本：

```bash
strings libc.so.6 | grep "GNU C Library"
```

两种方式获取指定版本的 glibc 库：

## 编译 glibc

```bash
apt install build-essential libssl-dev libgdbm-dev libdb-dev libexpat-dev libncurses5-dev libbz2-dev zlib1g-dev gawk bison binutils texinfo

./build 2.27 amd64
```

## 直接下载安装包提取

```bash
./download 2.27-3ubuntu1_amd64

ls -alh ./libs/
```

两种方式使 elf 加载指定 libc：

## 使用 patchelf 修改 elf 文件加载指定的 libc

下载 [patchelf](https://github.com/NixOS/patchelf)。

```bash
patchelf --add-needed /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6 ./ezheap
patchelf --set-interpreter /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 ./ezheap
```

原文件会被直接修改。

## 使用 LD_PRELOAD 环境变量加载指定的 libc

在脚本中利用 LD_PRELOAD 加载指定的 libc，不直接修改 ELF 文件：

```python
libc_version = '2.27-3ubuntu1.6'
file = './ezheap'
p = process([f"/root/glibc-all-in-one/libs/{libc_version}/ld-linux-x86-64.so.2",
             file], env={"LD_PRELOAD": f"/root/glibc-all-in-one/libs/{libc_version}/libc.so.6"})
```

## 使用指定版本编译

使用我修改后的 [glibc-all-in-one](https://github.com/0xlane/glibc-all-in-one)，下载指定版本的 glibc：

```bash
./download 2.27-3ubuntu1_amd64
```

使用此 `Makefile` 编译 (需要使用对应适配的 gcc 编译器，版本太高会报错)：

```makefile
# 指定编译器
CXX := g++-9

# 源文件
SRC := main.cpp

# 输出可执行文件名称
TARGET := main

# 自定义 glibc 的路径
GLIBC_INCLUDE := /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/.dev/usr/include
GLIBC_LIB := /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64

# 编译选项
CXXFLAGS := -I$(GLIBC_INCLUDE) -std=c++11 -D__STRICT_ANSI__
LDFLAGS := -L$(GLIBC_LIB) -Wl,-rpath=$(GLIBC_LIB) -Wl,--dynamic-linker=$(GLIBC_LIB)/ld-linux-x86-64.so.2

# 目标规则
$(TARGET): $(SRC)
        $(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) -ldl -lpthread -lm -nostartfiles

# 清理生成的文件
.PHONY: clean
clean:
        rm -f $(TARGET)
```

或者 g++ 命令：

```bash
g++-9 -I/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/.dev/usr/include -L/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ -Wl,--rpath=/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 -Wl,--dynamic-linker=/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 -nostartfiles -o main main.cpp
```

