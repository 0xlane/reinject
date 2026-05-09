---
title: "ret2csu"
date: 2025-01-07
type: posts
draft: false
summary: "What is ret2csu? Nothing too fancy — learning ret2csu is about understanding the concept, not memorizing every detail."
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - stack
  - ret2csu
---

ret2csu is a technique that leverages code gadgets found in **glibc**'s `__libc_csu_init` function for **ROP (Return-Oriented Programming)** attacks. It's commonly used to bypass certain restrictions, such as disabled syscalls, RELRO, or when longer gadget chains are needed.

In practice, it typically refers to using the register initialization and restoration instruction sequences at the beginning and end of functions. These instruction sequences serve the following purposes:

1. Set registers
2. Call arbitrary functions
3. Pass arguments
4. Adjust the stack

For shorter gadgets, you can use pwntools for quick searching. For example, to find a 'pop rdi\nret' gadget:

```python
from pwn import *

context.arch = 'amd64'

elf = ELF("./canary")

print(hex(next(elf.search(asm('pop rdi\nret'), executable=True))))
```

Related challenges:

- [asadstory]({{< relref "/posts/CTF-PWN/writeup/DASCTF-challenge-202311/asadstory" >}})
- [Inequable_Canary]({{< relref "/posts/CTF-PWN/writeup/chb2024/Inequable_Canary" >}})
