#!/bin/bash
# NexusLink 服务端配置向导 v0.2.0.beta
# 新手友好 - 一键配置启动

VERSION="0.2.0.beta"

clear
echo "========================================"
echo "   NexusLink 服务端配置向导"
echo "   v$VERSION"
echo "========================================"
echo ""

echo "📝 请输入配置参数（直接回车用默认值）"
echo ""

read -p "监听端口 [7000]: " BIND_PORT
BIND_PORT=${BIND_PORT:-7000}

read -p "连接密钥(Token) [nexuslink123]: " TOKEN
TOKEN=${TOKEN:-nexuslink123}

echo ""
echo "✅ 生成配置文件 server.yaml"
cat > server.yaml << EOF
bind_addr: 0.0.0.0
bind_port: $BIND_PORT
token: $TOKEN
EOF

cat server.yaml
echo ""
echo "========================================"
echo "🚀 启动服务端..."
echo "   端口: $BIND_PORT"
echo "   Token: $TOKEN"
echo "========================================"
echo ""

chmod +x nexuslink-server
./nexuslink-server -c server.yaml
