---
title: heap
---

不同应用或系统对内存的需求和不相同，因此目前堆的实现有很多种：

```bash
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

标准的 Linux 发行版都是 glibc 做内存管理。

## 系统调用

分配释放内存的底层系统调用有2个：

- brk
  - 堆内存操作
- mmap
  - 映射内存操作

可以 `cat /proc/<pid>/maps` 查看进程分配的堆内存和映射内存。
