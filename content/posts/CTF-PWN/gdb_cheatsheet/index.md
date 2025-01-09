---
title: "GDB Cheatsheet"
date: 2025-01-07
type: posts
draft: false
summary: "总结一下常用的 GDB 命令。"
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - pwntools
  - gdb
  - cheatsheet
---

```bash
# view sharedlibrary baseaddr
i proc mappings

# got
got

# get api addr
p system
print system

# get sharedlibrary .text address range
i sharedlibrary
i dll

# get file all segment address range
i files


# debug
r    # run
c    # continue run
s    # step
n    # next (step out call)
break main # set breakpoint at function
break *0x400180 # set breakpoint at address
info breakpoints # list breakpoints
dis breakpoints # disable breakpoints
en breakpoints # enable breakpoints

disassemble main # disassemble a section of memory
disassembly main,+10 # disassembly a address range of memory

heap -v # list all malloc_chunk
```
