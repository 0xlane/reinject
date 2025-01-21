---
title: CTF-PWN
---

linux syscall 列表：[https://linasm.sourceforge.net/docs/syscalls/filesystem.php](https://linasm.sourceforge.net/docs/syscalls/filesystem.php)

## 环境准备

- [glibc 多版本切换](heap/glibc/glibc_all_in_one)
- [Mac 安装 pwntools](pwntools/mac_install_pwntools)

## 基础知识

- leaklibc
  - [覆盖 _IO_2_1_stdout 泄漏 libc 地址](leaklibc/overwrite__io_2_1_stdout_to_leak_libc)
- 堆利用
  - [glibc](heap/glibc/)
    - [glibc malloc/free 源码分析](heap/glibc/glibc_malloc_free_source_analysis)
    - [unsortedbin 攻击利用](heap/glibc/unsortedbin_attack/)
    - [largebin 攻击利用](heap/glibc/largebin_attack/)
- 栈利用
  - [从shellcode学习到缓冲区溢出实战](stack/from_shellcode_to_buffer_overflow_practical_experience)
  - [ret2csu](stack/ret2csu)
- ELF 防护机制
  - [安全标志和 seccomp 沙箱](protect/security_flag_and_seccomp)

## writeup

- chb2024
  - [ezheap2](writeup/chb2024/ezheap2/)
  - [Inquable_Canary](writeup/chb2024/Inequable_Canary/)
- DASCTF-challenge-202311
  - [asadstory](writeup/DASCTF-challenge-202311/asadstory/)
