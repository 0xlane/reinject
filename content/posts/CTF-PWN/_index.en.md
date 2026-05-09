---
title: CTF-PWN
---

Linux syscall list: [https://linasm.sourceforge.net/docs/syscalls/filesystem.php](https://linasm.sourceforge.net/docs/syscalls/filesystem.php)

## Environment Setup

- [glibc Multi-version Switching](heap/glibc/glibc_all_in_one)
- [Install pwntools on Mac](pwntools/mac_install_pwntools)

## Fundamentals

- leaklibc
  - [Overwrite _IO_2_1_stdout to Leak libc Address](leaklibc/overwrite__io_2_1_stdout_to_leak_libc)
- Heap Exploitation
  - [glibc](heap/glibc/)
    - [glibc malloc/free Source Code Analysis](heap/glibc/glibc_malloc_free_source_analysis)
    - [Unsortedbin Attack](heap/glibc/unsortedbin_attack/)
    - [Largebin Attack](heap/glibc/largebin_attack/)
- Stack Exploitation
  - [From Shellcode to Buffer Overflow in Practice](stack/from_shellcode_to_buffer_overflow_practical_experience)
  - [ret2csu](stack/ret2csu)
- ELF Protection Mechanisms
  - [Security Flags and seccomp Sandbox](protect/security_flag_and_seccomp)

## Writeups

- chb2024
  - [ezheap2](writeup/chb2024/ezheap2/)
  - [Inquable_Canary](writeup/chb2024/Inequable_Canary/)
- DASCTF-challenge-202311
  - [asadstory](writeup/DASCTF-challenge-202311/asadstory/)
