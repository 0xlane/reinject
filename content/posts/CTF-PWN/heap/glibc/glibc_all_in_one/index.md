---
title: "glibc all in one"
date: 2025-01-06
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
patchelf --add-needed /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd6/libc.so.6 ./ezheap
patchelf --set-interpreter /root/glibc-all-in-one/libs/2.27-3ubuntu1_amd6/ld-linux-x86-64.so. ./ezheap
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
