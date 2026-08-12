#!/bin/bash
# NexusLink Linux 一键安装脚本
# 支持 systemd/openrc, wget/curl
# 用法: sudo ./install-nexuslink.sh [server|client|all] [token]

# 注意：不要使用 <(wget ...) 进程替换方式，请使用以下方法之一：
#   sudo bash install-nexuslink.sh              # 先下载脚本再执行
#   curl -fsSL https://github.com/.../install-nexuslink.sh | sudo bash
#   wget -O - https://github.com/.../install-nexuslink.sh | sudo bash

set -e

# 检测 root 权限
if [[ $EUID -ne 0 ]]; then
    echo "错误: 请使用 $0 sudo 运行"
    exit 1
fi

# 配置参数
ACTION="${1:-all}"
TOKEN="${2:-}"
BASE_DIR="/opt/nexuslink"
BIN_DIR="$BASE_DIR/bin"
CONFIG_DIR="/etc/nexuslink"
SERVICE_NAME="nexuslink"

# 检测可用工具（更健壮的检测方式）
HAS_WGET=false
HAS_CURL=false

if command -v wget &> /dev/null; then
    HAS_WGET=true
fi
if command -v curl &> /dev/null; then
    HAS_CURL=true
fi

echo "可用工具: wget=${HAS_WGET}, curl=${HAS_CURL}"
HAS_SYSTEMD=$(systemctl --version 2>/dev/null && echo true || false)
HAS_OPENRC=$(rc-status 2>/dev/null && echo true || true)

# 版本号（从 GitHub release 获取）
VERSION="v0.4.0"
GITHUB_REPO="YSD-build/Nexuslink"
ASSET_BASE="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/"

# ARM64 判断
get_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64) echo "linux-x86_64" ;;
        aarch64|armv8) echo "linux-armv8" ;;
        armv7l) echo "linux-armv7" ;;
        *) echo "linux-x86_64" ;;
    esac
}

ARCH=$(get_arch)
echo "检测到架构: $ARCH"

# 下载二进制文件
download_bin() {
    local bin_name="nexuslink-$1-${VERSION}-${ARCH}"
    local url="${ASSET_BASE}${bin_name}"
    
    echo "下载: $url"
    
    # 尝试使用 wget 下载
    if [[ "$HAS_WGET" == "true" ]]; then
        if wget -q "$url" -o "$bin_name" --no-check-certificate; then
            echo "✓ 使用 wget 下载成功"
        else
            echo "wget 下载失败，尝试 curl..."
            rm -f "$bin_name" 2>/dev/null
            if [[ "$HAS_CURL" == "true" ]] && curl -sL "$url" -o "$bin_name"; then
                echo "✓ 使用 curl 下载成功"
            else
                echo "错误: 下载失败（wget/curl 均未成功）"
                rm -f "$bin_name" 2>/dev/null
                exit 1
            fi
        fi
    elif [[ "$HAS_CURL" == "true" ]]; then
        # 没有 wget，直接使用 curl
        if curl -sL "$url" -o "$bin_name"; then
            echo "✓ 使用 curl 下载成功"
        else
            echo "错误: curl 下载失败"
            rm -f "$bin_name" 2>/dev/null
            exit 1
        fi
    else
        echo "错误: 未安装 wget 或 curl"
        exit 1
    fi
    
    # 检查下载的文件是否非空
    if [[ -f "$bin_name" && -s "$bin_name" ]]; then
        chmod +x "$bin_name"
        echo "✓ 下载完成: $bin_name ($(du -h "$bin_name" | cut -f1))"
    else
        echo "错误: 下载的文件为空或不存在"
        rm -f "$bin_name" 2>/dev/null
        exit 1
    fi
}

# 安装目录
setup_dirs() {
    mkdir -p "$BIN_DIR" "$CONFIG_DIR"
    echo "设置目录: $BIN_DIR, $CONFIG_DIR"
}

# 安装二进制
install_bins() {
    # 下载客户端
    download_bin "client"
    mv nexuslink-client "${BIN_DIR}/nexuslink-client"
    rm -f nexuslink-client
    
    # 下载服务端
    download_bin "server"
    mv nexuslink-server "${BIN_DIR}/nexuslink-server"
    rm -f nexuslink-server
    
    echo "✓ 二进制安装完成"
}

# 生成默认配置文件
generate_config() {
    if [[ -z "$TOKEN" ]]; then
        TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    fi
    
    # 服务端配置
    cat > "$CONFIG_DIR/server.yaml" << EOF
bind_addr: 0.0.0.0
bind_port: 7000
token: $TOKEN
web_enable: true
web_addr: 127.0.0.1
web_port: 7001
web_password: admin123
EOF
    
    # 客户端配置
    cat > "$CONFIG_DIR/client.yaml" << EOF
server_ip: $(hostname -I | awk '{print $1}')
server_port: 7000
token: $TOKEN
proxies:
  mc:
    type: tcp
    port: 25565
    localaddr: 127.0.0.1
    localport: 25565
EOF
    
    chmod 600 "$CONFIG_DIR/*.yaml"
    echo "✓ 配置文件已生成 (token: $TOKEN)"
}

# 创建 systemd 服务单元
create_systemd_service() {
    if [[ "$HAS_SYSTEMD" == true ]]; then
        cat > /etc/systemd/system/nexuslink-server.service << EOF
[Unit]
描述=NexusLink 内网穿透服务端
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/nexuslink-server -c $CONFIG_DIR/server.yaml
Restart=always
User=nobody
Group=nobody

[Install]
WantedBy=multi-user.target
EOF
        
        cat > /etc/systemd/system/nexuslink-client.service << EOF
[Unit]
描述=NexusLink 内网穿透客户端
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/nexuslink-client -c $CONFIG_DIR/client.yaml
Restart=always
User=nobody
Group=nobody

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        echo "✓ systemd 服务单元已创建"
    fi
}

# 创建 openrc 启动脚本
create_openrc_script() {
    if [[ "$HAS_OPENRC" == true ]]; then
        cat > /etc/init.d/nexuslink-server << 'EOL'
#!/sbin/openrc-run
depend() {
    need net
}

start_stop_cmd() {
    start-stop-daemon --start --make-pidfile --pidfile \
        /var/run/nexuslink-server.pid --background \
        --exec $BIN_DIR/nexuslink-server -- -c $CONFIG_DIR/server.yaml
}

stop_cmd() {
    stop-stop-daemon --stop --pidfile /var/run/nexuslink-server.pid
}
EOL
        chmod +x /etc/init.d/nexuslink-server
        echo "✓ OpenRC 启动脚本已创建"
    fi
}

# 启用服务
enable_service() {
    if [[ "$HAS_SYSTEMD" == true && ("$ACTION" == "server" || "$ACTION" == "all") ]]; then
        systemctl enable nexuslink-server.service
        echo "✓ 已启用 nexuslink-server 服务"
    fi
    if [[ "$HAS_SYSTEMD" == true && ("$ACTION" == "client" || "$ACTION" == "all") ]]; then
        systemctl enable nexuslink-client.service
        echo "✓ 已启用 nexuslink-client 服务"
    fi
}

# 启动服务
start_service() {
    if [[ "$HAS_SYSTEMD" == true && ("$ACTION" == "server" || "$ACTION" == "all") ]]; then
        systemctl start nexuslink-server.service
        echo "✓ 已启动 nexuslink-server"
    fi
    if [[ "$HAS_SYSTEMD" == true && ("$ACTION" == "client" || "$ACTION" == "all") ]]; then
        systemctl start nexuslink-client.service
        echo "✓ 已启动 nexuslink-client"
    fi
}

# 显示安装信息
show_info() {
    echo ""
    echo "=========================================="
    echo "NexusLink $VERSION 安装完成"
    echo "=========================================="
    echo "二进制: $BIN_DIR/"
    echo "配置: $CONFIG_DIR/"
    echo ""
    echo "服务端配置: $CONFIG_DIR/server.yaml"
    echo "客户端配置: $CONFIG_DIR/client.yaml"
    echo ""
    if [[ "$HAS_SYSTEMD" == true ]]; then
        echo "管理服务:"
        echo "  systemctl start/stop nexuslink-server"
        echo "  systemctl start/stop nexuslink-client"
        echo "  systemctl status nexuslink-server"
    fi
    echo ""
    echo "Web 管理面板: http://$(hostname -I | awk '{print $1'}):7001"
    echo "Web 密码: admin123 (请在 config 中修改)"
    echo ""
}

# 主逻辑
main() {
    echo "=== NexusLink $VERSION 一键安装脚本 ==="
    echo "安装模式: $ACTION"
    
    setup_dirs
    
    if [[ "$ACTION" == "server" || "$ACTION" == "all" ]]; then
        install_bins
    fi
    
    if [[ "$ACTION" == "client" || "$ACTION" == "all" ]]; then
        install_bins
    fi
    
    generate_config
    
    create_systemd_service
    create_openrc_script
    enable_service
    
    show_info
}

main
