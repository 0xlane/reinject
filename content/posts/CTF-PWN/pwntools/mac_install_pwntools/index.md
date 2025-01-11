---
title: "Mac 安装 pwntools"
date: 2024-12-20
type: posts
draft: false
summary: "在 Mac 上安装 pwntools 报错了，应该都会遇到吧。"
categories:
  - CTF-PWN
tags:
  - mac
  - ctf
  - pwn
  - pwntools
---

直接使用 `pip install pwntools` 会报错，需要安装 `cmake` 和 `pkg-config`。并且需要解决 `unicorn` 编译错误，找到 `unicorn` 对应版本仓库代码手动安装：

```bash
brew install cmake pkg-config
pip install "git+https://github.com/unicorn-engine/unicorn@d568885d64c89db5b9a722f0c1bef05aa92f84ca#subdirectory=bindings/python/"
pip install pwntools
```

后面 `pwntools` 更新，依赖的 `unicorn` 版本会改变，需要替换对应依赖版本 tag 的 commit。
