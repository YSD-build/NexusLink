@echo off
chcp 65001 >nul 2>&1
title NexusLink Server
echo ========================================
echo   NexusLink Server v0.3.3
echo ========================================
echo.

if not exist "server.yaml" (
    echo [ERROR] 未找到 server.yaml 配置文件
    echo 请先创建配置文件，参考 server.example.yaml
    pause
    exit /b 1
)

echo 正在启动服务端...
echo 按 Ctrl+C 停止
echo.
nexuslink-server.exe -c server.yaml
pause
