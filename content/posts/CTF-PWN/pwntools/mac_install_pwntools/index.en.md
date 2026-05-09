---
title: "Installing pwntools on Mac"
date: 2024-12-20
type: posts
draft: false
summary: "Running into errors when installing pwntools on Mac — a common issue and its fix."
categories:
  - CTF-PWN
tags:
  - mac
  - ctf
  - pwn
  - pwntools
---

Running `pip install pwntools` directly will fail. You need to install `cmake` and `pkg-config` first, and resolve the `unicorn` compilation error by manually installing `unicorn` from the corresponding version's repository source:

```bash
brew install cmake pkg-config
pip install "git+https://github.com/unicorn-engine/unicorn@d568885d64c89db5b9a722f0c1bef05aa92f84ca#subdirectory=bindings/python/"
pip install pwntools
```

As `pwntools` gets updated, its `unicorn` dependency version will change. You'll need to replace the commit hash with the one corresponding to the required version tag.
