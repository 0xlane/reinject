---
title: Heap Exploitation
---

Different applications and systems have different memory requirements, so there are many heap implementations:

```bash
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

Standard Linux distributions use glibc for memory management.

## System Calls

There are 2 underlying system calls for allocating and freeing memory:

- brk
  - Heap memory operations
- mmap
  - Memory mapping operations

You can use `cat /proc/<pid>/maps` to view a process's allocated heap memory and mapped memory.
