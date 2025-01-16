---
title: About
layout: default
_build:
  list: never
---

Hello, I'm REinject.

{{< fieldset class="toc" legend="MY PROJECTS" >}}
- [pe-sign](https://github.com/0xlane/pe-sign)

  一个用 Rust 语言开发的跨平台工具，专为解析和验证 PE 文件中的数字签名而设计。它既可以作为独立的命令行工具使用，也可以作为依赖库集成到任何 Rust 项目中。支持提取证书、验证签名、计算 Authenticode 签名摘要以及打印证书详细信息。

- [BypassUAC](https://github.com/0xlane/BypassUAC)

  使用 `ICMLuaUtil` COM 接口 Bypass UAC 的示例代码

- [wechat-dump-rs](https://github.com/0xlane/wechat-dump-rs)

  该工具用于导出正在运行中的微信进程的 key 并自动解密所有微信数据库文件以及导出 key 后数据库文件离线解密。(首个支持微信 4.0 解密的工具)

- [com-process-inject](https://github.com/0xlane/com-process-inject)

  进程注入的另一种方式，利用非公开 COM 接口 `IRundown::DoCallback()` 实现 shellcode/DLL 注入

- [process_ghosting](https://github.com/0xlane/process_ghosting)

  ProcessGhosting 技术的 rust 实现版本

- [cmd-spoofing](https://github.com/0xlane/cmd-spoofing)

  Windows 进程命令行伪造测试用例

- [ppspoofing](https://github.com/0xlane/ppspoofing)

  Windows 父进程PID欺骗测试用例

- [ollvm-rust](https://github.com/0xlane/ollvm-rust)

  一个用于 Rust 的 out-of-tree LLVM 混淆插件，可动态加载无需重新编译 LLVM。（半成品，暂不维护）
  {{< /fieldset >}}
