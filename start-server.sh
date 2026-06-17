#!/bin/bash
# NexusLink 服务端启动脚本 v0.2.0.beta

VERSION="0.2.0.beta"
CONFIG="server.yaml"

echo "========================================"
echo "   NexusLink 服务端 v$VERSION"
echo "========================================"
echo ""

if [ ! -f "$CONFIG" ]; then
    echo "❌ 配置文件不存在: $CONFIG"
    echo ""
    echo "请复制 server.yaml.example 为 server.yaml 并修改配置"
    echo "  cp server.yaml.example server.yaml"
    echo "  nano server.yaml"
    exit 1
fi

echo "📄 使用配置文件: $CONFIG"
echo ""
cat $CONFIG
echo ""
echo "========================================"
echo "🚀 启动服务端..."
echo "========================================"
echo ""

chmod +x nexuslink-server 2>/dev/null
./nexuslink-server -c $CONFIG
