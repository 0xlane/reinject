---
title: "ret2csu"
date: 2025-01-07
type: posts
draft: false
summary: "ret2csu 是啥，好像也没啥，学习 ret2csu 用意不用力。"
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - stack
  - ret2csu
---

ret2csu 是一种利用 **glibc** 中 `__libc_csu_init` 函数中存在的代码片段进行 **ROP (Return-Oriented Programming)** 攻击的技术。它通常用于绕过某些限制，例如禁用 syscall、RELRO 或者需要更长的 gadget 链时。

实际利用中一般指利用函数开头和结尾的寄存器初始化和还原的一段指令。这段指令具有以下作用：

1. 设置寄存器
2. 调用任意函数
3. 传递参数
4. 调整栈

对于比较短的 gadget，可以使用 pwn 快速搜索，例如需要使用 ‘pop rdi\nret’：

```python
from pwn import *

context.arch = 'amd64'

elf = ELF("./canary")

print(hex(next(elf.search(asm('pop rdi\nret'), executable=True))))
```

相关题目：

- [asadstory](../writeup/DASCTF-challenge-202311/asadstory/)
- [Inequable_Canary](../writeup/chb2024/Inequable_Canary/)
