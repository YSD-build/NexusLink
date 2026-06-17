#!/bin/bash
# NexusLink 一键安装脚本 v0.2.0.beta

VERSION="0.2.0.beta"
GITHUB="https://github.com/YSD-build/NexusLink/releases/download"

clear
echo "========================================"
echo "   NexusLink 一键安装 v$VERSION"
echo "========================================"
echo ""

# 检测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        PLATFORM="linux-x86_64"
        ;;
    aarch64|arm64)
        PLATFORM="linux-armv8"
        ;;
    armv7l)
        PLATFORM="linux-armv7"
        ;;
    armv6l)
        PLATFORM="linux-armv6"
        ;;
    *)
        echo "❌ 不支持的架构: $ARCH"
        exit 1
        ;;
esac

echo "📦 检测到架构: $PLATFORM"
echo ""

# 选择安装服务端还是客户端
echo "请选择安装:"
echo "1) 服务端 (Server)"
echo "2) 客户端 (Client)"
read -p "请选择 [1-2]: " CHOICE

case $CHOICE in
    1)
        TYPE="server"
        FILE="nexuslink-server-v${VERSION}.${TYPE}-${PLATFORM}"
        BIN_NAME="nexuslink-server"
        ;;
    2)
        TYPE="client"
        FILE="nexuslink-client-v${VERSION}.${TYPE}-${PLATFORM}"
        BIN_NAME="nexuslink-client"
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac

echo ""
echo "🚀 正在下载 $FILE ..."
echo ""

# 下载
curl -L -o $BIN_NAME "$GITHUB/v${VERSION}.${TYPE}/$FILE"

if [ $? -eq 0 ]; then
    chmod +x $BIN_NAME
    echo ""
    echo "✅ 安装成功!"
    echo ""
    echo "运行命令:"
    echo "  chmod +x $BIN_NAME"
    echo "  ./$BIN_NAME.sh  (交互式配置)"
    echo ""
else
    echo "❌ 下载失败"
    exit 1
fi
