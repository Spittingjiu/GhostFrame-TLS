@echo off
chcp 65001 >nul
title 启动 GhostFrame-TLS Pro 桌面客户端
cd /d "%~dp0"

echo ========================================================
echo        GhostFrame-TLS (GFT) Pro 图形客户端
echo ========================================================
echo.
echo [*] 正在启动 GhostFrame 桌面独立窗口与代理引擎...
echo [*] 本地 SOCKS5 端口: 127.0.0.1:10808
echo [*] 本地 HTTP 代理端口: 127.0.0.1:10809
echo [*] 自动调用系统浏览器启动原生感无边框 GUI 窗口...
echo.

if exist "gft-client-gui.exe" (
    start "" "gft-client-gui.exe"
) else if exist "02_Source_Code\gft-client-gui.exe" (
    start "" "02_Source_Code\gft-client-gui.exe"
) else (
    echo [!] 未找到 gft-client-gui.exe，正在尝试通过源码运行...
    start "" go run ./02_Source_Code/cmd/gft-client-gui
)

echo [+] 启动指令已发出，GUI 控制面板已在新窗口就绪！
echo.
timeout /t 3 >nul
exit
