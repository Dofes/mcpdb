# MCPDB

一个我的世界中国版基岩版 Python 调试器后端，简单实现了 [DAP](https://microsoft.github.io/debug-adapter-protocol/) 协议。

由于中国版未导出 Python API，本项目通过内存技术实现对游戏内嵌 Python 2.7 解释器的访问和控制。

```
┌─────────────────────────────────────┐
│           VS Code / IDE             │
│        (DAP Client - debugpy)       │
└──────────────────┬──────────────────┘
                   │ TCP (DAP/JSON)
                   ▼
┌─────────────────────────────────────┐
│        MCPDB (mcpdb.dll)          │
│   DAP Core / Python Wrapper / Hook  │
└──────────────────┬──────────────────┘
                   │ Hook
                   ▼
┌─────────────────────────────────────┐
│  Minecraft China Bedrock (Py 2.7)   │
└─────────────────────────────────────┘
```

## Build

需要 Windows x64, MSVC 2022+, [xmake](https://xmake.io/), C++20。

```bash
xmake
```

产物：`mcpdb.dll` 和 `mcdbg.exe`

## Usage

1. 启动 `Modpc`
2. 运行 `mcdbg.exe`
3. VS Code 配置 `launch.json`：

```jsonc
{
  "name": "Attach to Minecraft",
  "type": "python",
  "request": "attach",
  "connect": { "host": "127.0.0.1", "port": 5678 }, //由 mcdbg 控制, -p 参数可修改端口
  "pathMappings": [
    {
      "localRoot": "${workspaceFolder}/scripts",
      "remoteRoot": "."
    }
  ]
}
```

4. 设置断点，F5 附加调试

## Dependencies

[nlohmann_json](https://github.com/nlohmann/json),
[fmt](https://github.com/fmtlib/fmt),
[detours](https://github.com/microsoft/Detours),
[expected-lite](https://github.com/martinmoene/expected-lite)

## Notice

- 仅供学习研究
- 特征码可能随游戏更新失效

## License

MIT License

本项目 `src/py/` 目录下的 Python 头文件来自 [Python 2.7](https://www.python.org/)，采用 [PSF License](https://docs.python.org/2/license.html)。
