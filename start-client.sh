#!/bin/bash
# NexusLink 客户端启动脚本 v0.2.0.beta

VERSION="0.2.0.beta"
CONFIG="client.yaml"

echo "========================================"
echo "   NexusLink 客户端 v$VERSION"
echo "========================================"
echo ""

if [ ! -f "$CONFIG" ]; then
    echo "❌ 配置文件不存在: $CONFIG"
    echo ""
    echo "请复制 client.yaml.example 为 client.yaml 并修改配置"
    echo "  cp client.yaml.example client.yaml"
    echo "  nano client.yaml"
    echo ""
    echo "常用映射已在模板中预置，只需修改IP和Token即可！"
    exit 1
fi

echo "📄 使用配置文件: $CONFIG"
echo ""
cat $CONFIG
echo ""
echo "========================================"
echo "🚀 启动客户端..."
echo "========================================"
echo ""

chmod +x nexuslink-client 2>/dev/null
./nexuslink-client -c $CONFIG
