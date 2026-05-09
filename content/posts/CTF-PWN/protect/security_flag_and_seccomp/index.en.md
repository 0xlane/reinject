---
title: "Security Flags and Seccomp Sandbox"
date: 2025-01-07
type: posts
draft: false
summary: "A brief overview of common ELF protection mechanisms — essential knowledge for CTF PWN."
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - checksec
  - seccomp
---

Common protection mechanisms:

- **seccomp sandbox**: Restricts syscall execution through filtering rules
- **NX (No-eXecute)**: Only instructions in executable regions can be executed, forcing attackers to construct gadget chains from existing instruction fragments
- **RELRO (RELocation Read-Only)**: Makes relocation entries read-only, preventing attacks against dynamic linking
  - Partial RELRO:
    - Sets the `.got.plt` section as read-only.
    - However, some other writable areas remain, such as the `.got` section (used for global variable relocation).
    - This provides basic protection but is not fully secure.
  - Full RELRO:
    - Sets both `.got` and `.got.plt` sections as read-only.
    - After the dynamic linker completes all relocations at program startup, these memory regions are made read-only.
    - This provides stronger protection, making it much harder for attackers to tamper with the GOT and PLT tables.
- **PIE (Position Independent Executable)**: Essentially ASLR (Address Space Layout Randomization) — the base address of the program and libraries differs on each load
  - If PIE is enabled, the challenge usually provides a way to leak the PIE base address
  - If PIE is not enabled, the base address remains fixed

Security flags are automatically displayed when loading an ELF with pwntools, or you can use the `checksec` command in GDB.

Seccomp filtering rules can be dumped using [seccomp-tools](https://github.com/david942j/seccomp-tools). For example, the following rule indicates that the program disallows the `open` and `execve` syscalls:

```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x04 0xc000003e  if (A != ARCH_X86_64) goto 0006
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0006
 0004: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x06 0x00 0x00 0x00000000  return KILL
```
