#!/bin/bash
# NexusLink 客户端 v0.2.0.beta
# 新手友好 - 交互式配置 + 常用映射模板

VERSION="0.2.0.beta"
CONFIG_FILE="client.yaml"

clear
echo "========================================"
echo "   NexusLink 客户端 v$VERSION"
echo "   新手友好 - 交互式配置"
echo "========================================"
echo ""

# 输入服务器信息
read -p "请输入服务器IP: " SERVER_IP
if [ -z "$SERVER_IP" ]; then
    echo "❌ 服务器IP不能为空!"
    exit 1
fi

read -p "请输入服务器端口 [默认7000]: " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-7000}

read -p "请输入连接密钥(Token): " TOKEN
if [ -z "$TOKEN" ]; then
    echo "❌ Token不能为空!"
    exit 1
fi

echo ""
echo "========================================"
echo "📋 选择要映射的服务:"
echo "========================================"
echo "1) Minecraft (25565)"
echo "2) SSH (22)"
echo "3) Web (80)"
echo "4) Web HTTPS (443)"
echo "5) RDP 远程桌面 (3389)"
echo "6) 自定义端口"
echo ""
read -p "请选择 [1-6]: " CHOICE

case $CHOICE in
    1)
        PROXY_NAME="mc"
        PROXY_PORT=25565
        LOCAL_PORT=25565
        PROXY_TYPE="tcp"
        ;;
    2)
        PROXY_NAME="ssh"
        PROXY_PORT=6000
        LOCAL_PORT=22
        PROXY_TYPE="tcp"
        ;;
    3)
        PROXY_NAME="web"
        PROXY_PORT=80
        LOCAL_PORT=80
        PROXY_TYPE="tcp"
        ;;
    4)
        PROXY_NAME="https"
        PROXY_PORT=443
        LOCAL_PORT=443
        PROXY_TYPE="tcp"
        ;;
    5)
        PROXY_NAME="rdp"
        PROXY_PORT=3389
        LOCAL_PORT=3389
        PROXY_TYPE="tcp"
        ;;
    6)
        read -p "代理名称: " PROXY_NAME
        read -p "服务端端口: " PROXY_PORT
        read -p "本地IP [127.0.0.1]: " LOCAL_ADDR
        LOCAL_ADDR=${LOCAL_ADDR:-127.0.0.1}
        read -p "本地端口: " LOCAL_PORT
        PROXY_TYPE="tcp"
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac

# 生成配置文件
cat > $CONFIG_FILE << EOF
# NexusLink 客户端配置 v$VERSION
server_ip: $SERVER_IP
server_port: $SERVER_PORT
token: $TOKEN

proxies:
  $PROXY_NAME:
    type: $PROXY_TYPE
    port: $PROXY_PORT
    localaddr: 127.0.0.1
    localport: $LOCAL_PORT
EOF

echo ""
echo "✅ 配置文件已生成: $CONFIG_FILE"
echo ""
cat $CONFIG_FILE
echo ""
echo "========================================"
echo "🚀 启动 NexusLink 客户端..."
echo "   服务器: $SERVER_IP:$SERVER_PORT"
echo "   映射: $PROXY_NAME $PROXY_PORT -> 127.0.0.1:$LOCAL_PORT"
echo "========================================"
echo ""

# 启动客户端
if [ -f "./nexuslink-client" ]; then
    ./nexuslink-client -c $CONFIG_FILE
else
    echo "⚠️  二进制文件不存在，请先编译或下载预编译版本"
    echo "   下载地址: https://github.com/YSD-build/NexusLink/releases"
fi
