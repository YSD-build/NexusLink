#!/bin/bash
# NexusLink 一键安装脚本
# 版本: v0.2.6.beta.server
# 功能: 自动下载、部署、配置 systemd 保活、生成随机账密

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# 配置
REPO="YSD-build/NexusLink"
VERSION="v0.2.6.beta.server"
INSTALL_DIR="/opt/nexuslink"
SERVICE_NAME="nexuslink-web"
DEFAULT_PORT=7001

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "请使用 root 用户运行此脚本"
        print_info "使用方法: sudo bash $0"
        exit 1
    fi
}

# 检查系统
check_system() {
    print_info "检查系统环境..."
    
    if [ ! -f /etc/os-release ]; then
        print_error "不支持的操作系统"
        exit 1
    fi
    
    # 检查 systemd
    if ! command -v systemctl &> /dev/null; then
        print_warning "未检测到 systemd，将不配置开机自启"
        NO_SYSTEMD=true
    else
        NO_SYSTEMD=false
    fi
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="linux-amd64"
            ;;
        aarch64|arm64)
            ARCH="linux-arm64"
            ;;
        *)
            print_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    print_success "系统检测通过: $ARCH"
}

# 生成随机密码
generate_password() {
    if command -v openssl &> /dev/null; then
        ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
    else
        ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
    fi
}

# 下载 NexusLink
download_nexuslink() {
    print_info "下载 NexusLink $VERSION..."
    
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"
    
    DOWNLOAD_URL="https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz"
    print_info "下载地址: $DOWNLOAD_URL"
    
    if command -v wget &> /dev/null; then
        wget -q --show-progress -O nexuslink.tar.gz "$DOWNLOAD_URL"
    elif command -v curl &> /dev/null; then
        curl -L -# -o nexuslink.tar.gz "$DOWNLOAD_URL"
    else
        print_error "未找到 wget 或 curl，请先安装"
        exit 1
    fi
    
    print_success "下载完成"
    
    print_info "解压文件..."
    tar -xzf nexuslink.tar.gz
    
    EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "NexusLink-*" | head -1)
    if [ -z "$EXTRACTED_DIR" ]; then
        print_error "解压失败，未找到源码目录"
        exit 1
    fi
    
    SOURCE_DIR="$TMP_DIR/$EXTRACTED_DIR"
    print_success "解压完成"
}

# 安装到目标目录
install_files() {
    print_info "安装到 $INSTALL_DIR ..."
    
    mkdir -p "$INSTALL_DIR"
    cp -r "$SOURCE_DIR"/* "$INSTALL_DIR/"
    
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/logs"
    
    print_success "文件安装完成"
}

# 检查 Node.js
check_node() {
    print_info "检查 Node.js 环境..."
    
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v)
        print_success "检测到 Node.js: $NODE_VERSION"
        return 0
    else
        print_warning "未检测到 Node.js"
        return 1
    fi
}

# 安装 Node.js
install_node() {
    if check_node; then
        return 0
    fi
    
    print_info "正在安装 Node.js 18.x..."
    
    if [ -f /etc/debian_version ]; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
    elif [ -f /etc/redhat-release ]; then
        curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
        yum install -y nodejs
    else
        print_error "无法自动安装 Node.js，请手动安装 Node.js 18+"
        exit 1
    fi
    
    if check_node; then
        print_success "Node.js 安装成功"
    else
        print_error "Node.js 安装失败"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    print_info "安装 Web 面板依赖..."
    
    cd "$INSTALL_DIR/web/server"
    
    if [ -f package.json ]; then
        npm install --production --silent
        print_success "依赖安装完成"
    else
        print_warning "未找到 package.json，跳过依赖安装"
    fi
}

# 生成配置
generate_config() {
    print_info "生成配置文件..."
    
    generate_password
    
    CONFIG_FILE="$INSTALL_DIR/web/server/index.js"
    
    if [ -f "$CONFIG_FILE" ]; then
        sed -i "s/password: 'admin123'/password: '$ADMIN_PASSWORD'/" "$CONFIG_FILE"
        print_success "管理员密码已设置"
    else
        print_warning "未找到配置文件，使用默认密码 admin123"
        ADMIN_PASSWORD="admin123"
    fi
}

# 创建 systemd 服务
create_systemd_service() {
    if [ "$NO_SYSTEMD" = true ]; then
        print_warning "跳过 systemd 服务配置"
        return
    fi
    
    print_info "创建 systemd 服务..."
    
    NODE_PATH=$(which node)
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=NexusLink Web Management Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/web/server
ExecStart=$NODE_PATH $INSTALL_DIR/web/server/index.js
Restart=always
RestartSec=5
Environment=PORT=$DEFAULT_PORT
StandardOutput=append:$INSTALL_DIR/logs/web.log
StandardError=append:$INSTALL_DIR/logs/web-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    print_success "systemd 服务创建完成，已设置开机自启"
}

# 启动服务
start_service() {
    print_info "启动 NexusLink Web 管理面板..."
    
    if [ "$NO_SYSTEMD" = false ]; then
        systemctl start $SERVICE_NAME
        sleep 2
        
        if systemctl is-active --quiet $SERVICE_NAME; then
            print_success "服务启动成功"
        else
            print_warning "服务可能未正常启动，请检查日志"
        fi
    else
        cd "$INSTALL_DIR/web/server"
        PORT=$DEFAULT_PORT nohup node index.js > "$INSTALL_DIR/logs/web.log" 2>&1 &
        echo $! > "$INSTALL_DIR/web.pid"
        print_success "服务已后台启动"
    fi
}

# 获取本机 IP
get_local_ip() {
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$IP" ]; then
        IP=$(ip addr show 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | head -1 | awk '{print $2}' | cut -d/ -f1)
    fi
    if [ -z "$IP" ]; then
        IP="127.0.0.1"
    fi
    echo "$IP"
}

# 显示安装结果
show_result() {
    LOCAL_IP=$(get_local_ip)
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}║        🎉 NexusLink 安装成功！                            ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${CYAN}║  🌐 管理地址:                                             ║${NC}"
    echo -e "${WHITE}║     http://$LOCAL_IP:$DEFAULT_PORT                            ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${CYAN}║  👤 管理员账号:                                           ║${NC}"
    echo -e "${WHITE}║     用户名: admin                                         ║${NC}"
    echo -e "${WHITE}║     密码: $ADMIN_PASSWORD                                         ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${CYAN}║  📁 安装目录:                                             ║${NC}"
    echo -e "${WHITE}║     $INSTALL_DIR                                    ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${CYAN}║  🔧 服务管理:                                             ║${NC}"
    echo -e "${WHITE}║     启动: systemctl start $SERVICE_NAME                    ║${NC}"
    echo -e "${WHITE}║     停止: systemctl stop $SERVICE_NAME                     ║${NC}"
    echo -e "${WHITE}║     重启: systemctl restart $SERVICE_NAME                  ║${NC}"
    echo -e "${WHITE}║     状态: systemctl status $SERVICE_NAME                   ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${YELLOW}║  ⚠️  注意: 当前版本仅支持管理功能，穿透功能后续更新        ║${NC}"
    echo -e "${GREEN}║                                                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    cat > "$INSTALL_DIR/install-info.txt" << EOF
NexusLink 安装信息
==================
安装时间: $(date)
版本: $VERSION
安装目录: $INSTALL_DIR
管理地址: http://$LOCAL_IP:$DEFAULT_PORT
管理员账号: admin
管理员密码: $ADMIN_PASSWORD
服务名称: $SERVICE_NAME
EOF
}

# 清理临时文件
cleanup() {
    print_info "清理临时文件..."
    rm -rf "$TMP_DIR"
    print_success "清理完成"
}

# 主函数
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                       ║${NC}"
    echo -e "${CYAN}║     🚀 NexusLink 一键安装脚本         ║${NC}"
    echo -e "${CYAN}║                                       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    check_system
    download_nexuslink
    install_files
    install_node
    install_dependencies
    generate_config
    create_systemd_service
    start_service
    show_result
    cleanup
    
    print_success "安装全部完成！"
}

main
