---
title: "安全标志和 seccomp 沙箱"
date: 2025-01-07
type: posts
draft: false
summary: "简单了解下常见的 ELF 防护机制必不可少的。"
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - checksec
  - seccomp
---

常见保护机制：

- seccomp 沙箱 通过过滤规则限制syscall执行
- nx 只有可执行区域的指令可以被执行，使攻击者只能利用现有的指令片段构造gadgets攻击链
- RELRO 重定向只读，防止针对动态链接库的攻击
  - 部分 RELRO (Partial RELRO):
    - 将 .got.plt 段设置为只读。
    - 但仍然会留下一些其他的可写区域，例如 .got 段（用于全局变量的重定位）。
    - 这种方式提供了基本的保护，但并非完全安全。
  - 完全 RELRO (Full RELRO):
    - 将 .got 和 .got.plt 段都设置为只读。
    - 在程序启动时，动态链接器完成所有重定位工作后，将这些内存区域设置为只读。
    - 这种方式提供了更强的保护，使得攻击者更难篡改 GOT 和 PLT 表。
- PIE 实际就是 ASLR（地址空间布局随机化），每次加载程序和库的内存基址都是不一样的
  - 如果启用了 PIE 题目内可能提供个方式会让你知道 PIE 地址
  - 如果没有启用的话，那么基址就是固定不变的

安全标志在使用 pwntools 加载 elf 时自动会显示，或者在 gdb 中使用 `checksec` 命令。

seccomp 过滤规则可以通过 [seccomp-tools](https://github.com/david942j/seccomp-tools) 工具 dump 出来，例如下面这个规则表示程序不允许执行 `open` 和 `execve` syscall：

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
