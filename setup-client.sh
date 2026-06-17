#!/bin/bash
# NexusLink 客户端配置向导 v0.2.0.beta
# 新手友好 - 常用映射一键选

VERSION="0.2.0.beta"

clear
echo "========================================"
echo "   NexusLink 客户端配置向导"
echo "   v$VERSION"
echo "========================================"
echo ""

echo "📝 基础配置"
echo ""

read -p "服务端IP地址: " SERVER_IP
if [ -z "$SERVER_IP" ]; then
    echo "❌ 服务端IP不能为空!"
    exit 1
fi

read -p "服务端端口 [7000]: " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-7000}

read -p "连接密钥(Token): " TOKEN
if [ -z "$TOKEN" ]; then
    echo "❌ Token不能为空!"
    exit 1
fi

echo ""
echo "========================================"
echo "📋 选择端口映射类型:"
echo "========================================"
echo ""
echo "  1) Minecraft 游戏 (25565)"
echo "  2) SSH 远程 (22)"
echo "  3) Web 网站 (80)"
echo "  4) 自定义端口"
echo ""

read -p "请选择 [1-4]: " CHOICE

case $CHOICE in
    1)
        PROXY_NAME="mc"
        PROXY_PORT=25565
        LOCAL_PORT=25565
        echo "✅ 已选择: Minecraft 25565"
        ;;
    2)
        PROXY_NAME="ssh"
        PROXY_PORT=6000
        LOCAL_PORT=22
        echo "✅ 已选择: SSH 22 → 6000"
        ;;
    3)
        PROXY_NAME="web"
        PROXY_PORT=8080
        LOCAL_PORT=80
        echo "✅ 已选择: Web 80 → 8080"
        ;;
    4)
        read -p "映射名称: " PROXY_NAME
        read -p "公网端口: " PROXY_PORT
        read -p "本地端口: " LOCAL_PORT
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac

echo ""
echo "✅ 生成配置文件 client.yaml"
cat > client.yaml << EOF
server_ip: $SERVER_IP
server_port: $SERVER_PORT
token: $TOKEN

proxies:
  $PROXY_NAME:
    type: tcp
    port: $PROXY_PORT
    localaddr: 127.0.0.1
    localport: $LOCAL_PORT
EOF

cat client.yaml
echo ""
echo "========================================"
echo "🚀 启动客户端..."
echo "   服务端: $SERVER_IP:$SERVER_PORT"
echo "   映射: $LOCAL_PORT → $PROXY_PORT"
echo "========================================"
echo ""

chmod +x nexuslink-client
./nexuslink-client -c client.yaml
