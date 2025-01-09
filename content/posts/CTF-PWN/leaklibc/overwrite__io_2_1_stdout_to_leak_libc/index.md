---
title: "覆盖 _IO_2_1_stdout 泄漏 libc 地址"
date: 2025-01-08
type: posts
draft: false
categories:
  - CTF-PWN
tags:
  - linux
  - ctf
  - pwn
  - leaklibc
  - _io_2_1_stdout
---


PWN 类型的题基本上都需要用到 libc 的地址，一般情况可以通过获取程序 GOT 表填充的 libc API 地址通过相对偏移计算出 libc 基址。但是也有时候没办法直接读 GOT，这时候如果可以实现任意位置写，那通过覆盖 `_IO_2_1_stdout` 的方式就可以泄漏 libc 地址。

操作上比较简单，直接把 `_IO_2_1_stdout` 结构开头的 `flag` 置为 `0x00000000fbad1800`，并将 `_IO_write_base` 低字节位改小，然后等着程序调用 `puts`、 `printf` 函数即可将 libc 地址泄漏到标准输出里。

<!--more-->

还记得学习 C 代码第一课 —— 打印 `Hello, world!` 吗：

```cpp
#include <stdio.h>

int main() {
  printf("Hello, world!\n");
  return 0;
}
```

只需要导入 `stdio.h` 这个头，就可以完成程序的输入输出功能，`stdio.h` 头就是由 glibc 提供的 ([源码](https://github.com/bminor/glibc/blob/a4c414796a4b7464b24f5e13f35042f3b7a2444b/libio/stdio.h))。

所以就从这个 `printf` 开始了解下为什么可以泄漏 libc 地址吧。

因为 `printf` 除了输出字符串，还提供了字符串格式化的功能，内部代码比较多，所以看得时候跳过字符串格式化的部分，只看输出相关（或者从相对简单的 `puts` 开始）。

在 [glibc-2.27](https://github.com/bminor/glibc/blob/glibc-2.27/) 中找到 `printf` 的实现代码 [printf.c#L27](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/printf.c#L27)：

```cpp
int
__printf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = vfprintf (stdout, format, arg);
  va_end (arg);

  return done;
}
```

内部调用 `vfprintf`，在 [vprintf.c#L28](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vprintf.c#L28) 实现：

```cpp
int
__vprintf (const char *format, __gnuc_va_list arg)
{
  return vfprintf (stdout, format, arg);
}
```

从这里可以看到调用了 `vfprintf` 完成字符串格式化操作，并输出到 `stdout`，从名字看就知道是标准输出，基于对 linux 的了解，一个进程的标准输入 (`stdin`)、标准输出 (`stdout`)、标准错误输出 (`stderr`) 分别和文件描述符 (fd) 0、1、2 绑定，在 libc 中找到相关定义在 [stdio.c#L33](https://github.com/bminor/glibc/blob/glibc-2.27/libio/stdio.c#L33)：

```cpp
_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_;
```

在这里看到了熟悉的 `_IO_2_1_stdout_`，从这里可知，`stdout` 是 `_IO_2_1_stdout_` 的指针。关于 `_IO_2_1_stdout_` 的实现在 [stdfiles.c#L53](https://github.com/bminor/glibc/blob/glibc-2.27/libio/stdfiles.c#L53)：

```cpp
# define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \
  static struct _IO_wide_data _IO_wide_data_##FD \
    = { ._wide_vtable = &_IO_wfile_jumps }; \
  struct _IO_FILE_plus NAME \
    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, &_IO_wide_data_##FD), \
       &_IO_file_jumps};

DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);
```

后面再来继续分析 `stdout`，先继续看 `vfprintf`，实现位置 [vfprintf.c#L1243](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L1243)，真正的 `printf` 功能实现代码是这个函数里，所以这个函数代码很长就不贴了：

```cpp
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap)     // 记住这里 s = stdout = &_IO_2_1_stdout_
```

通过分析可知该函数实际调用了 [process_arg](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L484)、[process_string_arg](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L948)、[outchar](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L155)、[outstring](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L168) 这四个宏定义完成字符串输出，`process_arg` 和 `process_string_arg` 实际也是调用 `outchar` 和 `outstring`，所以只需要关注 `outchar` 和 `outstring`：

```cpp
#define    outchar(Ch)                                         \
  do                                                           \
    {                                                          \
      const INT_T outc = (Ch);                                 \
      if (PUTC (outc, s) == EOF || done == INT_MAX)            \
  {                                                            \
    done = -1;                                                 \
    goto all_done;                                             \
  }                                                            \
      ++done;                                                  \
    }                                                          \
  while (0)

#define outstring(String, Len)                                 \
  do                                                           \
    {                                                          \
      assert ((size_t) done <= (size_t) INT_MAX);              \
      if ((size_t) PUT (s, (String), (Len)) != (size_t) (Len)) \
  {                                                            \
    done = -1;                                                 \
    goto all_done;                                             \
  }                                                            \
      if (__glibc_unlikely (INT_MAX - done < (Len)))           \
      {                                                        \
  done = -1;                                                   \
   __set_errno (EOVERFLOW);                                    \
  goto all_done;                                               \
      }                                                        \
      done += (Len);                                           \
    }                                                          \
  while (0)
```

这两个宏定义通过 [PUTC](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L109) 和 [PUT](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L125) 两个宏定义完成字符、字符串的输出，最终调用的是 `_IO_putc_unlocked` 和 `_IO_sputn`：

```cpp
# define PUTC(C, F)    _IO_putc_unlocked (C, F)            // F = s = stdout = &_IO_2_1_stdout_
# define PUT(F, S, N)  _IO_sputn ((F), (S), (N))
```

`_IO_putc_unlocked` 和 `_IO_sputn` 分别定义在 [libio.h#L411](https://github.com/bminor/glibc/blob/glibc-2.27/libio/bits/libio.h#L411) 和 [libioP.h#L377](https://github.com/bminor/glibc/blob/glibc-2.27/libio/libioP.h#L377) 中，一个对应 `putc`，一个对应 `puts`，弄懂其中一个另外一个也就明白了，`_IO_putc_unlocked` 比较简单，就以这个为切入口：

```cpp
// putc
// libio.h
#define _IO_putc_unlocked(_ch, _fp) \
   (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) \
    ? __overflow (_fp, (unsigned char) (_ch)) \
    : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```

这段代码的意思是当 `(_fp)->_IO_write_ptr` 到达 `(_fp)->_IO_write_end` 位置就调用 `__overflow` 刷新缓冲区到文件流，否则将字符 `_ch` 写入到 `_IO_write_ptr` 位置并使之后移。`_IO_write_ptr`、`_IO_write_end` 都是什么，这时候就需要继续分析 `stdout` 结构，前面知道它是 `_IO_2_1_stdout_` 的指针，`_IO_2_1_stdout_` 是一个被声明为 `_IO_FILE_plus` 结构体类型的全局变量：

```cpp
// https://github.com/bminor/glibc/blob/glibc-2.27/libio/bits/libio.h#L320
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;

// https://github.com/bminor/glibc/blob/glibc-2.27/libio/libioP.h#L322
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

// https://github.com/bminor/glibc/blob/glibc-2.27/libio/bits/libio.h#L245
struct _IO_FILE {
  int _flags;             /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;     /* Current read pointer */
  char* _IO_read_end;     /* End of get area. */
  char* _IO_read_base;    /* Start of putback+get area. */
  char* _IO_write_base;   /* Start of put area. */
  char* _IO_write_ptr;    /* Current put pointer. */
  char* _IO_write_end;    /* End of put area. */
  char* _IO_buf_base;     /* Start of reserve area. */
  char* _IO_buf_end;      /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base;    /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end;     /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

// https://github.com/bminor/glibc/blob/glibc-2.27/libio/libioP.h#L287
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

`_IO_FILE_plus` 是在 `_IO_FILE` 的基础上扩充了一个类 c++ 的虚函数表字段 `vtable`，所以 `_IO_2_1_stdout_` 经常被统一强转成 `_IO_FILE` 进行参数传递，这时 `((_IO_FILE *)stdout)->_IO_write_ptr` 等价于 `stdout->file._IO_write_ptr`。

然后需要知道这个结构里这些字段的含义：

- `_flags`：之前说的要把 `_IO_2_1_stdout_` 开头覆盖为 `0x00000000fbad1800`，其实被覆盖的就是这个字段，它包含了一组位标志，表示文件流的不同状态
- 一些缓冲区相关的指针
  - `_IO_read_ptr`：指向当前读取位置
  - `_IO_read_end`：指向读取结束位置
  - `_IO_read_base`：指向读取开始位置
  - `_IO_write_base`：指向写入开始位置
  - `_IO_write_ptr`：指向当前写入位置
  - `_IO_write_end`：指向写入结束位置
  - `_IO_buf_base`：指向缓冲区开始位置
  - `_IO_buf_end`：指向缓冲区结束位置

`_IO_buf_base ~ _IO_buf_end` 表示整个缓冲区范围，`_IO_write_base ~ _IO_write_end` 表示 put 缓冲区范围，`_IO_read_base ~ _IO_read_end` 表示 get 缓冲区范围，对于 `stdout` 来说应该只可能会有 put 缓冲区吧。

前面看到了当 `_IO_write_ptr` 到达 `_IO_write_end` 位置就会调用 `__overflow` 刷新缓冲区，用户输出内容实际是先被写到 `_IO_write_ptr` 指向的位置，最初指向 `_IO_write_base`，随着输出内容的增加，该指针不断向后移动，当到达 `_IO_write_end` 位置则表示 put 缓冲区被填满，这时才会调用 `__overflow` 将 put 缓冲区中的内容全部输出到文件流。

所以把 `_IO_write_base` 改小之后缓冲区变大，就可以使输出内容变多，至于为什么改小就能输出那么多 libc 的地址，这个后面再细究。但是实际上在调用 `__overflow` 时，`_IO_write_base` 的值受 `_flags` 标志位的影响会变动，所以需要通过控制标志位的值使 `_IO_write_base` 在调用 `__overflow` 过程中不被重置。

根据之前 `_IO_2_1_stdout_` 的定义，可知 `vtable` 由 [fileops.c#L1455](https://github.com/bminor/glibc/blob/glibc-2.27/libio/fileops.c#L1455) 中的 `_IO_file_jumps` 提供虚函数实现：

```cpp
const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_file_jumps)
```

`__overflow` 对应的实现是 `_IO_file_overflow`，它是 `_IO_new_file_overflow` 函数的别名：

```cpp
// https://github.com/bminor/glibc/blob/glibc-2.27/libio/fileops.c#L745
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
    if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }

    // ...

    if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
        // ...
        if (f->_IO_read_ptr == f->_IO_buf_end)
            f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
        f->_IO_write_ptr = f->_IO_read_ptr;
        f->_IO_write_base = f->_IO_write_ptr;
        f->_IO_write_end = f->_IO_buf_end;
        f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

        f->_flags |= _IO_CURRENTLY_PUTTING;
        // ...
    }
    // ...
    _IO_do_write (f, f->_IO_write_base,
            f->_IO_write_ptr - f->_IO_write_base);
    // ...
}

libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

上面只列出了会导致 `_IO_write_base` 被重置的部分，即：

- `_flags` 不包含 `_IO_NO_WRITES` 函数会直接报错返回
- `_flags` 不包含 `_IO_CURRENTLY_PUTTING` 函数会修改 `_IO_write_base` 指向 `_IO_buf_base`，也就是缓冲区开头

最后调用 `_IO_do_write` 完成缓冲区输出，它是 `_IO_new_do_write` 函数的别名，内部调用 `new_do_write`：

```cpp
// https://github.com/bminor/glibc/blob/glibc-2.27/libio/fileops.c#L430
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
      || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
    _IO_size_t count;
    if (fp->_flags & _IO_IS_APPENDING)
        /* On a system without a proper O_APPEND implementation,
        you would need to sys_seek(0, SEEK_END) here, but is
        not needed nor desirable for Unix- or Posix-like systems.
        Instead, just indicate that offset (before and after) is
        unpredictable. */
        fp->_offset = _IO_pos_BAD;
    else if (fp->_IO_read_end != fp->_IO_write_base)
    {
        _IO_off64_t new_pos
            = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
        if (new_pos == _IO_pos_BAD)
            return 0;
        fp->_offset = new_pos;
    }
    count = _IO_SYSWRITE (fp, data, to_do);
    // ...
    _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
    fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
    // ...
    return count;
}
```

函数中调用 `_IO_SYSSEEK` 会改变缓冲区写入文件位置，所以为了排除这个影响，需要使 `_flags & _IO_IS_APPENDING` 或 `fp->_IO_read_end == fp->_IO_write_base` 任一条件成立才能绕过，调用 `_IO_SYSWRITE` 将 put 缓冲区内容输出到标准输出文件流，输出之后 put、get 相关缓冲区指针都会被重置，完成缓冲区刷新操作。

经上可知，为了实现将篡改后 `_IO_write_base` 指向数据能被正确的写入到标准输出，需要使满足下面条件：

- `_flags & _IO_NO_WRITES == _IO_NO_WRITES`
- `_flags & _IO_CURRENTLY_PUTTING == _IO_CURRENTLY_PUTTING`
- `_flags & _IO_IS_APPENDING == _IO_IS_APPENDING` 或 `_IO_read_end == _IO_write_base`

所以使 `_flags = 0x00000000fbad1800` 刚好可以满足上面条件，然后控制 `_IO_write_base` 指针输出原始缓冲区之前的内容即可。

然后再来看为什么只需要将 `_IO_write_base` 改向前一些就可以输出 libc 地址，一般是把低位字节置为 0x00。

这里利用之前的 HelloWorld 代码做个测试，因为满足前面泄漏 libc 的条件，所以不出意外的话输出中包含许多 libc 地址：

```cpp
#include <stdio.h>

int main() {
  setvbuf(stdout, 0, 2, 0);  // no buffer
  stdout->_flags = 0x00000000fbad1800;
  stdout->_IO_write_base = (char *)(((unsigned long long)stdout->_IO_write_base) & 0xffffffffffffffffff00);
  printf("Hello, world!\n");
  return 0;
}
```

用 `g++ main.cpp` 命令编译生成 `a.out`，用这个脚本加载获取返回内容：

```python
from pwn import *

p = process("./a.out")
# gdb.attach(p)
print(p.recvall())

# pause()
```

输出如下：

```bash
[+] Starting local process './a.out': pid 14204
[+] Receiving all data: Done (81B)
[*] Process './a.out' stopped with exit code 0 (pid 14204)
b'DV\x0e\xed\xe0\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0H\x0e\xed\xe0\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00Hello, world!\n
```

能发现正如预期一样，libc 地址泄漏了出来。

然后去掉 `setvbuf(stdout, 0, 2, 0);` 再试试呢，你会发现打印出来的只是 `Hello, world!`，libc 地址并没有被泄漏。

所以只有在将 put 缓冲区设置为 `NULL` 的时候，才可以泄漏出 libc 地址，这是因为这时候 put 缓冲区相关指针指向的是 `_IO_2_1_stdout_` 中的 `char _shortbuf[1]` 字段，并且 `_IO_2_1_stdout_` 整个结构都是静态存储在 `libc` 的 `.data` 区域，所以此时泄漏的是 `.data` 区域的数据，里面包含很多 libc 地址。

默认情况下，整个缓冲区大小是 0x400，调用 `malloc` 分配在堆上，所以这时候 `_IO_write_base` 向前改小并不能泄漏 libc 地址。这块就不具体分析了，有兴趣可以看一下源码中 `setbuf` 相关的实现。

**最后总结下：除了程序有任意位置写漏洞之外，还需要将 `stdout` 缓冲区设置为 `NULL`，才可以用这种方法泄漏 libc 地址。**

相关题目：

- [ezheap2](../../writeup/chb2024/ezheap2)

