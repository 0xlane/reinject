---
title: unsortedbin
date: 2025-01-16T16:46:56+08:00
type: posts
draft: true
categories:
  - CTF-PWN
tags:
  - ctf
  - linux
  - glibc
  - unsortedbin
  - heap
---

这篇记录下和 unsortedbin 相关的内容。未排序其实就是未归类，其他 bin 都是有固定大小或范围的，归类到对应 bin 上就相当于按大小排序了。 

之前在 [glibc malloc/free 源码分析](../glibc_malloc_free_source_analysis/) 中比较详细地分析过内存分配、释放的过程，malloc 按 exact-fit 优先原则进行分配，即优先找已有的相同大小 chunk，否则归类 unsortedbin 中的 chunk，同时再进行 exact-fit 匹配找到最合适的，归类后扔没有大小正好合适的就对稍大的 chunk 切割。

如果有 tcache，在归类过程中精确匹配到的 chunk 先存储到 tcache 里，到达阀值之后立即返回 chunk，如果没有 tcache 就立即返回 chunk。没有精确匹配的 chunk 会被分类到对应的 bin 上。

排除 tcache 的影响，unsorted chunk 只会被归类到 smallbin 或 larginbin 上，这块代码不多，直接贴代码看。

## small chunk 归类过程

```cpp
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
    // ... (omitted)
    
    /* remove from unsorted list */
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
    
    // ... (omitted)
    if (in_smallbin_range (size))
    {
      victim_index = smallbin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;
    }
    else
    {
        // ... large chunk (omitted)
    }
    
    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
    
    // ... (omitted)
    
#define MAX_ITERS       10000
  	if (++iters >= MAX_ITERS)
    	break;
}
    

```

没有什么特殊的，就是将 victim 链到 smallbin 上。

## large chunk 归类过程

```cpp
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
    // ... (omitted)

    /* remove from unsorted list */
    unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);

    // ... (omitted)
    if (in_smallbin_range (size))
    {
        // ... (omitted)
    }
    else
    {
        victim_index = largebin_index (size);
        bck = bin_at (av, victim_index);
        fwd = bck->fd;

        /* maintain large bins in sorted order */
        if (fwd != bck)
        {
            /* Or with inuse bit to speed comparisons */
            size |= PREV_INUSE;
            /* if smaller than smallest, bypass loop below */
            assert (chunk_main_arena (bck->bk));
            if ((unsigned long) (size)
                < (unsigned long) chunksize_nomask (bck->bk))
            {
                fwd = bck;
                bck = bck->bk;

                victim->fd_nextsize = fwd->fd;
                victim->bk_nextsize = fwd->fd->bk_nextsize;
                fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
            else
            {
                assert (chunk_main_arena (fwd));
                while ((unsigned long) size < chunksize_nomask (fwd))
                {
                    fwd = fwd->fd_nextsize;
                    assert (chunk_main_arena (fwd));
                }

                if ((unsigned long) size
                    == (unsigned long) chunksize_nomask (fwd))
                    /* Always insert in the second position.  */
                    fwd = fwd->fd;
                else
                {
                    victim->fd_nextsize = fwd;
                    victim->bk_nextsize = fwd->bk_nextsize;
                    fwd->bk_nextsize = victim;
                    victim->bk_nextsize->fd_nextsize = victim;
                }
                bck = fwd->bk;
            }
        }
        else
            victim->fd_nextsize = victim->bk_nextsize = victim;
    }

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    // ... (omitted)

    #define MAX_ITERS       10000
    if (++iters >= MAX_ITERS)
        break;
}
```

