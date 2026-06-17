#!/bin/bash
# NexusLink 服务端 v0.2.0.beta
# 新手友好 - 交互式配置

VERSION="0.2.0.beta"
CONFIG_FILE="server.yaml"

clear
echo "========================================"
echo "   NexusLink 服务端 v$VERSION"
echo "   新手友好 - 交互式配置"
echo "========================================"
echo ""

# 输入监听端口
read -p "请输入监听端口 [默认7000]: " BIND_PORT
BIND_PORT=${BIND_PORT:-7000}

# 输入Token
read -p "请输入连接密钥(Token): " TOKEN
if [ -z "$TOKEN" ]; then
    echo "❌ Token不能为空!"
    exit 1
fi

# 生成配置文件
cat > $CONFIG_FILE << EOF
# NexusLink 服务端配置 v$VERSION
bind_addr: 0.0.0.0
bind_port: $BIND_PORT
token: $TOKEN
EOF

echo ""
echo "✅ 配置文件已生成: $CONFIG_FILE"
cat $CONFIG_FILE
echo ""
echo "========================================"
echo "🚀 启动 NexusLink 服务端..."
echo "   监听端口: $BIND_PORT"
echo "========================================"
echo ""

# 启动服务端（Go版本，C版本编译好后替换）
if [ -f "./nexuslink-server" ]; then
    ./nexuslink-server -c $CONFIG_FILE
else
    echo "⚠️  二进制文件不存在，请先编译或下载预编译版本"
    echo "   下载地址: https://github.com/YSD-build/NexusLink/releases"
fi
