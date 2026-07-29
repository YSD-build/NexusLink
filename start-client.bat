@echo off
chcp 65001 >nul 2>&1
title NexusLink Client
echo ========================================
echo   NexusLink Client v0.3.4
echo ========================================
echo.

if not exist "client.yaml" (
    echo [ERROR] 未找到 client.yaml 配置文件
    echo 请先创建配置文件，参考 client.example.yaml
    pause
    exit /b 1
)

echo 正在启动客户端...
echo 按 Ctrl+C 停止
echo.
nexuslink-client.exe -c client.yaml
pause
