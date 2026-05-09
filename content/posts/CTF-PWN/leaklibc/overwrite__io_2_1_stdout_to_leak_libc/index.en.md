---
title: "Overwriting _IO_2_1_stdout to Leak libc Address"
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

PWN challenges almost always require the libc base address. Typically, you can obtain it by reading a libc API address filled in the program's GOT table and calculating the base via relative offset. However, sometimes you can't directly read the GOT. In such cases, if you have an arbitrary write primitive, you can leak the libc address by overwriting `_IO_2_1_stdout`.

The operation is fairly straightforward: set the `flag` field at the beginning of the `_IO_2_1_stdout` structure to `0x00000000fbad1800`, modify the low byte of `_IO_write_base` to a smaller value, then wait for the program to call `puts` or `printf` — the libc address will be leaked to stdout.

<!--more-->

Remember the first lesson in learning C — printing `Hello, world!`:

```cpp
#include <stdio.h>

int main() {
  printf("Hello, world!\n");
  return 0;
}
```

Just by including the `stdio.h` header, you get input/output functionality. The `stdio.h` header is provided by glibc ([source](https://github.com/bminor/glibc/blob/a4c414796a4b7464b24f5e13f35042f3b7a2444b/libio/stdio.h)).

So let's start from `printf` to understand why this technique can leak the libc address.

Since `printf` provides string formatting in addition to output, its internal code is quite extensive. We'll skip the formatting parts and focus only on the output-related code (or start from the simpler `puts`).

In [glibc-2.27](https://github.com/bminor/glibc/blob/glibc-2.27/), the `printf` implementation is found at [printf.c#L27](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/printf.c#L27):

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

Internally it calls `vfprintf`, implemented in [vprintf.c#L28](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vprintf.c#L28):

```cpp
int
__vprintf (const char *format, __gnuc_va_list arg)
{
  return vfprintf (stdout, format, arg);
}
```

Here we can see it calls `vfprintf` to perform string formatting and outputs to `stdout`. As we know from Linux fundamentals, a process's standard input (`stdin`), standard output (`stdout`), and standard error (`stderr`) are bound to file descriptors (fd) 0, 1, and 2 respectively. The related definitions in libc are found at [stdio.c#L33](https://github.com/bminor/glibc/blob/glibc-2.27/libio/stdio.c#L33):

```cpp
_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_;
```

Here we see the familiar `_IO_2_1_stdout_`. From this, we know that `stdout` is a pointer to `_IO_2_1_stdout_`. The implementation of `_IO_2_1_stdout_` is in [stdfiles.c#L53](https://github.com/bminor/glibc/blob/glibc-2.27/libio/stdfiles.c#L53):

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

We'll continue analyzing `stdout` later. First, let's look at `vfprintf`, implemented at [vfprintf.c#L1243](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L1243). This is where the actual `printf` functionality is implemented — the function is very long, so it won't be listed here:

```cpp
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap)     // Remember: s = stdout = &_IO_2_1_stdout_
```

Analysis reveals that this function uses four macro definitions to accomplish string output: [process_arg](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L484), [process_string_arg](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L948), [outchar](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L155), and [outstring](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L168). Since `process_arg` and `process_string_arg` ultimately call `outchar` and `outstring`, we only need to focus on these two:

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

These two macros use [PUTC](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L109) and [PUT](https://github.com/bminor/glibc/blob/glibc-2.27/stdio-common/vfprintf.c#L125) macros for character and string output, ultimately calling `_IO_putc_unlocked` and `_IO_sputn`:

```cpp
# define PUTC(C, F)    _IO_putc_unlocked (C, F)            // F = s = stdout = &_IO_2_1_stdout_
# define PUT(F, S, N)  _IO_sputn ((F), (S), (N))
```

`_IO_putc_unlocked` and `_IO_sputn` are defined in [libio.h#L411](https://github.com/bminor/glibc/blob/glibc-2.27/libio/bits/libio.h#L411) and [libioP.h#L377](https://github.com/bminor/glibc/blob/glibc-2.27/libio/libioP.h#L377) respectively — one corresponds to `putc`, the other to `puts`. Understanding one makes the other clear. Since `_IO_putc_unlocked` is simpler, we'll use it as our entry point:

```cpp
// putc
// libio.h
#define _IO_putc_unlocked(_ch, _fp) \
   (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) \
    ? __overflow (_fp, (unsigned char) (_ch)) \
    : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```

This code means: when `(_fp)->_IO_write_ptr` reaches the `(_fp)->_IO_write_end` position, `__overflow` is called to flush the buffer to the file stream. Otherwise, the character `_ch` is written to the `_IO_write_ptr` position and the pointer is advanced. What are `_IO_write_ptr` and `_IO_write_end`? To understand this, we need to analyze the `stdout` structure. We know it's a pointer to `_IO_2_1_stdout_`, which is a global variable declared as the `_IO_FILE_plus` struct type:

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

`_IO_FILE_plus` extends `_IO_FILE` with a C++ vtable-like `vtable` field. Therefore, `_IO_2_1_stdout_` is often cast to `_IO_FILE` for parameter passing, where `((_IO_FILE *)stdout)->_IO_write_ptr` is equivalent to `stdout->file._IO_write_ptr`.

Now let's understand the meaning of these fields:

- `_flags`: As mentioned earlier, what we overwrite at the beginning of `_IO_2_1_stdout_` with `0x00000000fbad1800` is this field. It contains a set of bit flags representing different states of the file stream.
- Buffer-related pointers:
  - `_IO_read_ptr`: Points to the current read position
  - `_IO_read_end`: Points to the read end position
  - `_IO_read_base`: Points to the read start position
  - `_IO_write_base`: Points to the write start position
  - `_IO_write_ptr`: Points to the current write position
  - `_IO_write_end`: Points to the write end position
  - `_IO_buf_base`: Points to the buffer start position
  - `_IO_buf_end`: Points to the buffer end position

`_IO_buf_base ~ _IO_buf_end` represents the entire buffer range, `_IO_write_base ~ _IO_write_end` represents the put buffer range, and `_IO_read_base ~ _IO_read_end` represents the get buffer range. For `stdout`, only the put buffer should be in use.

We saw earlier that when `_IO_write_ptr` reaches `_IO_write_end`, `__overflow` is called to flush the buffer. User output is first written to the position pointed to by `_IO_write_ptr`, which initially points to `_IO_write_base`. As output content increases, this pointer moves forward. When it reaches `_IO_write_end`, the put buffer is full, and `__overflow` is called to flush all put buffer contents to the file stream.

So by making `_IO_write_base` smaller, the buffer effectively becomes larger, allowing more content to be output. As for why making it smaller causes so many libc addresses to be output — we'll examine that later. In practice, during the `__overflow` call, the value of `_IO_write_base` may be modified depending on the `_flags` bits. Therefore, we need to control the flags to prevent `_IO_write_base` from being reset during the `__overflow` process.

From the earlier definition of `_IO_2_1_stdout_`, we know that `vtable` is implemented by `_IO_file_jumps` in [fileops.c#L1455](https://github.com/bminor/glibc/blob/glibc-2.27/libio/fileops.c#L1455):

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

The `__overflow` implementation is `_IO_file_overflow`, which is an alias for `_IO_new_file_overflow`:

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

The above only shows the parts that could cause `_IO_write_base` to be reset:

- If `_flags` contains `_IO_NO_WRITES`, the function returns an error immediately
- If `_flags` does not contain `_IO_CURRENTLY_PUTTING`, the function resets `_IO_write_base` to point to `_IO_buf_base` (the buffer start)

Finally, `_IO_do_write` is called to perform the buffer output. It is an alias for `_IO_new_do_write`, which internally calls `new_do_write`:

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

The `_IO_SYSSEEK` call in this function would change the buffer write position in the file. To avoid this side effect, either `_flags & _IO_IS_APPENDING` or `fp->_IO_read_end == fp->_IO_write_base` must be true to bypass it. `_IO_SYSWRITE` outputs the put buffer contents to the stdout file stream. After output, all put/get buffer pointers are reset, completing the buffer flush operation.

From the above analysis, to correctly write the tampered `_IO_write_base` data to stdout, the following conditions must be met:

- `_flags & _IO_NO_WRITES == _IO_NO_WRITES`
- `_flags & _IO_CURRENTLY_PUTTING == _IO_CURRENTLY_PUTTING`
- `_flags & _IO_IS_APPENDING == _IO_IS_APPENDING` or `_IO_read_end == _IO_write_base`

Therefore, setting `_flags = 0x00000000fbad1800` satisfies all the above conditions. Then by controlling the `_IO_write_base` pointer, we can output the original buffer content preceding it.

Now let's examine why simply moving `_IO_write_base` slightly forward can output libc addresses — typically the low byte is set to 0x00.

Here we use the HelloWorld code from before as a test. Since it satisfies the libc leak conditions, the output should contain many libc addresses:

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

Compile with `g++ main.cpp` to produce `a.out`, then use this script to load and capture the output:

```python
from pwn import *

p = process("./a.out")
# gdb.attach(p)
print(p.recvall())

# pause()
```

Output:

```bash
[+] Starting local process './a.out': pid 14204
[+] Receiving all data: Done (81B)
[*] Process './a.out' stopped with exit code 0 (pid 14204)
b'DV\x0e\xed\xe0\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0H\x0e\xed\xe0\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00Hello, world!\n
```

As expected, libc addresses are leaked in the output.

Now, what happens if we remove `setvbuf(stdout, 0, 2, 0);`? You'll find that only `Hello, world!` is printed — no libc addresses are leaked.

This is because only when the put buffer is set to `NULL` can libc addresses be leaked. When the buffer is NULL, the put buffer pointers point to the `char _shortbuf[1]` field within the `_IO_2_1_stdout_` structure. Since the entire `_IO_2_1_stdout_` structure is statically stored in libc's `.data` section, the leaked data comes from the `.data` section, which contains many libc addresses.

By default, the buffer size is 0x400, allocated on the heap via `malloc`. In this case, making `_IO_write_base` smaller doesn't leak libc addresses. We won't go into the details here — if you're interested, check the `setbuf`-related implementations in the source code.

**In summary: In addition to having an arbitrary write vulnerability, the program must also have `stdout`'s buffer set to `NULL` for this technique to leak libc addresses.**

Related challenges:

- [ezheap2]({{< relref "/posts/CTF-PWN/writeup/chb2024/ezheap2" >}})
