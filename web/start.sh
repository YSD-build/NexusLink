#!/bin/bash

# NexusLink Web 管理面板 一键启动脚本

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║                                              ║"
echo "║   🚀 NexusLink Web 管理面板                  ║"
echo "║                                              ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "❌ 未检测到 Node.js，请先安装 Node.js"
    echo "   下载地址: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js 版本: $(node -v)"

# 检查依赖
if [ ! -d "$SERVER_DIR/node_modules" ]; then
    echo ""
    echo "📦 正在安装依赖..."
    cd "$SERVER_DIR"
    npm install --production
    if [ $? -ne 0 ]; then
        echo "❌ 依赖安装失败"
        exit 1
    fi
    echo "✅ 依赖安装完成"
fi

# 检查二进制文件
if [ ! -f "$SCRIPT_DIR/bin/nexuslink-server" ] || [ ! -f "$SCRIPT_DIR/bin/nexuslink-client" ]; then
    echo ""
    echo "⚠️  警告: 未检测到 C 语言二进制文件"
    echo "   请将 nexuslink-server 和 nexuslink-client 放到 bin/ 目录下"
fi

echo ""
echo "🌐 管理面板即将启动..."
echo "   访问地址: http://localhost:5173"
echo "   默认密码: admin123"
echo ""
echo "   按 Ctrl+C 停止服务"
echo ""

# 启动服务
cd "$SERVER_DIR"
node index.js
