### 🔧 Linux 一键安装

**推荐方式（分步下载执行，最可靠）：**

```bash
# 1. 下载脚本
curl -fsSL -o install-nexuslink.sh https://github.com/YSD-build/NexusLink/raw/main/scripts/install-nexuslink.sh

# 2. 验证脚本（可选）
sha256sum install-nexuslink.sh

# 3. 执行安装（默认安装 server + client）
sudo bash install-nexuslink.sh all

# 或使用 curl 直接执行（管道方式）
curl -fsSL https://github.com/YSD-build/NexusLink/raw/main/scripts/install-nexuslink.sh | sudo bash all
```

脚本自动检测架构、下载对应二进制、生成配置文件并创建系统服务。所有资产见下方 Release。
---
# NexusLink · 高性能带认证内网穿透
![Version](https://img.shields.io/badge/version-v0.4.0-4f6ef7)
![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fysd-build%2Fnexuslink-blue?logo=docker)
![Platform](https://img.shields.io/badge/platform-Linux%2FWindows%2FAndroid%2FARM-green)
![License](https://img.shields.io/badge/license-GPL-3.0-green)

> 类似 FRP，但**每个数据包都带 HMAC-SHA256 认证**（防篡改、防重放），纯 Go 静态编译、无运行时依赖。
> 支持 **TCP / UDP** 穿透，内置 Web 管理面板，跨平台（x86 / ARM / Android / Windows）。
---
## ✨ 特性
- 🔐 **每数据包认证**：`[32字节 HMAC-SHA256][8字节时间戳][原始数据]`，中间人无法篡改或重放
- 🔁 **防重放**：5 分钟时间窗校验
- 🛡️ **恒时比较**：`hmac.Equal` / `subtle.ConstantTimeCompare`，抵御时序攻击
- 🌐 **TCP + UDP 双协议**：UDP 采用独立数据通道 + session 多路复用
- 🚧 **连接守卫 ConnGuard**：单 IP 连接数/频率限制，异常行为自动封禁
- 📦 **零依赖**：纯 Go 编译，单文件二进制，跨平台
- 🖥️ **Web 管理面板**：状态 / 配置 / 日志 / 隧道管理，登录失败锁定 + CSRF 防护
- ⚙️ **安全中心可调**：会话超时 / 失败锁定阈值 / 防护开关 / 自定义 CSP，实时生效
- 📜 **GPL-3.0 开源**
---
## 📌 当前版本
**v0.4.0** — Web 面板 Vue 3 SPA 重构（组件化 + 现代简洁设计）；强制下线客户端/下线隧道；ConnGuard 白名单系统；宽松化封禁策略；客户端 token 认证失败明确提示
**v0.3.7** — Web 面板重写为 Vue 3 SPA（零图标、离线内嵌）；内置 TLS（Web HTTPS + 隧道可选）；代理 ACL 访问控制；TCP 流量统计
**v0.3.6** — 安全中心新增在线修改密码；主页文案全面更新；Release 与 Docker 发布全自动化
**v0.3.5** — Web 管理面板安全中心全面升级：可调安全策略 + AI 定时巡查 + Webhook 告警 + 实时安全监控；侧边栏固定并去除图标。
**v0.3.4** — Web 管理面板新增「API 令牌」与「关于」页面，完善面板信息展示。
> 下载与资产见下方「下载安装」。历史说明见 [Releases](https://github.com/YSD-build/NexusLink/releases)。📚 详细文档见 [Wiki](https://github.com/YSD-build/NexusLink/wiki)。
---
## 📦 下载安装
所有资产发布在 **[v0.4.0 Release](https://github.com/YSD-build/NexusLink/releases/tag/v0.4.0)**。
### 🖥️ 服务端（6 架构）
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| linux-x86_64 | `nexuslink-server-v0.4.0-linux-x86_64` | PC、云服务器、虚拟机 |
| **linux-arm64** | `nexuslink-server-v0.4.0-linux-armv8` | ✅ ARM 服务器、树莓派 4/5 |
| linux-armv7 | `nexuslink-server-v0.4.0-linux-armv7` | 路由器、树莓派 2/3 |
| linux-armv6 | `nexuslink-server-v0.4.0-linux-armv6` | 旧嵌入式设备 |
| windows-x86_64 | `nexuslink-server-v0.4.0-windows-x86_64.exe` | Windows PC (x64) |
| windows-arm64 | `nexuslink-server-v0.4.0-windows-arm64.exe` | Windows ARM (骁龙 X) |
### 📱 客户端（6 版本）
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| **android-arm64** | `nexuslink-client-v0.4.0-android-arm64` | ✅ 骁龙、天玑、绝大多数安卓手机（Termux 无 Root） |
| linux-x86_64 | `nexuslink-client-v0.4.0-linux-x86_64` | PC、虚拟机 |
| linux-armv8 | `nexuslink-client-v0.4.0-linux-armv8` | ARM 服务器、树莓派 |
| linux-armv7 | `nexuslink-client-v0.4.0-linux-armv7` | 路由器 |
| linux-armv6 | `nexuslink-client-v0.4.0-linux-armv6` | 旧嵌入式设备 |
| windows-x86_64 | `nexuslink-client-v0.4.0-windows-x86_64.exe` | Windows PC |
### 🌐 Web 面板
`nexuslink-web-panel-v0.4.0.zip` — 独立 Node.js 版管理面板（已内置 x86_64 二进制）。服务端二进制本身也已内置面板，直接访问 `web_addr:web_port` 即可。
### 🐳 Docker 部署
镜像托管于 **ghcr.io**（自动构建多架构：linux/amd64、linux/arm64、linux/arm/v7）：
```bash
# 使用默认配置（生产环境请挂载自己的 server.yaml 覆盖默认配置）
docker run -d --name nexuslink \
  -p 7000:7000 -p 7001:7001 \
  -v /path/to/server.yaml:/app/server.yaml \
  ghcr.io/ysd-build/nexuslink:latest
```
> 版本化镜像：`ghcr.io/ysd-build/nexuslink:0.4.0`（`v*` tag 自动触发构建发布）。默认配置见 `docker/server.yaml`。
---
## 🚀 快速开始
### 1️⃣ 服务端部署（公网服务器）
```bash
# 以 ARM64 为例
wget https://github.com/YSD-build/NexusLink/releases/download/v0.4.0/nexuslink-server-v0.4.0-linux-armv8
chmod +x nexuslink-server-v0.4.0-linux-armv8
```
**`server.yaml`：**
```yaml
bind_addr: 0.0.0.0
bind_port: 7000
token: 你的密钥
web_enable: true
web_addr: 127.0.0.1
web_port: 7001
web_password: admin123
# web_trust_proxy: false   # 仅当服务端部署在可信反向代理后才设 true，才用 X-Forwarded-For 取客户端 IP
```
**运行：** `./nexuslink-server-v0.4.0-linux-armv8 -c server.yaml`
正常输出：
```
NexusLink Server v0.3.4 starting...
Listening on 0.0.0.0:7000
```
### 2️⃣ 客户端配置（内网机器 / 手机）
**`client.yaml`：**
```yaml
server_ip: 你的公网服务器IP
server_port: 7000
token: 你的密钥          # 必须与服务端一致
proxies:
  # TCP 示例：Minecraft
  mc:
    type: tcp
    port: 25565          # 服务端暴露的端口
    localaddr: 127.0.0.1
    localport: 25565
  # UDP 示例：游戏 / 查询
  game_udp:
    type: udp
    port: 25566
    localaddr: 127.0.0.1
    localport: 9000
```
**运行（Linux）：** `./nexuslink-client-v0.4.0-linux-armv8 -c client.yaml`
正常输出：
```
NexusLink Client v0.3.4 starting...
Connecting to server 你的IP:7000
Connected to server successfully
Registering proxy [mc] type=tcp local=127.0.0.1:25565 remote=25565
Registering proxy [game_udp] type=udp local=127.0.0.1:9000 remote=25566
```
### 📱 Android 客户端（手机，无需 Root）
1. 安装 Termux：https://f-droid.org/packages/com.termux/
2. 下载 `android-arm64` 版本，Termux 中运行：
   ```bash
   pkg install wget
   wget https://github.com/YSD-build/NexusLink/releases/download/v0.4.0/nexuslink-client-v0.4.0-android-arm64
   chmod +x nexuslink-client-v0.4.0-android-arm64
   ./nexuslink-client-v0.4.0-android-arm64 -c client.yaml
   ```
---
## ⚙️ 配置详解
### 服务端 `server.yaml`
| 字段 | 说明 |
|------|------|
| `bind_addr` / `bind_port` | 服务端监听地址与端口（控制通道） |
| `token` | 认证密钥，客户端须一致 |
| `web_enable` | 是否启用 Web 管理面板 |
| `web_addr` / `web_port` | 面板监听地址与端口 |
| `web_password` | 面板登录密码 |
| `web_trust_proxy` | 仅当部署在可信反向代理后才设 `true`，才用 `X-Forwarded-For` 取客户端 IP（默认 `false`） |
### 客户端 `client.yaml`
| 字段 | 说明 |
|------|------|
| `server_ip` / `server_port` | 服务端公网地址与端口 |
| `token` | 认证密钥，须与服务端一致 |
| `proxies` | 代理列表，每项含： |
| ├ `type` | `tcp` 或 `udp` |
| ├ `port` | 服务端暴露的远程端口 |
| ├ `localaddr` | 内网服务地址 |
| └ `localport` | 内网服务端口 |
---
## 🔐 安全特性
### 每数据包认证机制
```
[32字节 HMAC-SHA256 签名] [8字节 时间戳] [原始数据]
```
- ✅ **防篡改** — 每个数据包独立签名，中间人无法修改
- ✅ **防重放** — 5 分钟时间窗口校验
- ✅ **防时序攻击** — 签名校验使用恒定时间比较（`hmac.Equal`）
- ✅ **登录恒时** — token / 密码 / CSRF 均使用 `subtle.ConstantTimeCompare`
### 连接层防护（ConnGuard）
- 单 IP 并发连接数限制（默认 200，宽松）
- 连接频率限制（1s 最小间隔），**单次超限仅计数**，连续 3 次才封禁
- **EOF / 网络抖动不封禁**（正常断连不拉黑），登录成功后自动清除异常计数
- 封禁时长 1 分钟（便于快速恢复），异常阈值 3 次（容忍偶发抖动）
- 协议层畸形包（非法魔数 / 超长 length / 非法类型）在分配内存前即拒绝
- **白名单系统**：可信客户端 IP/CIDR 加入白名单后**完全 bypass**所有检测（黑名单/频率/连接数），即使被封禁也照常放行
### Web 面板防护
- 登录失败锁定（阈值与时长可在安全中心调整）
- 登录请求体限制 1MB（`MaxBytesReader`），防 OOM
- `HttpOnly` + `SameSite=Strict` Cookie + CSRF Token（可开关）
- 受保护 API 未授权返回 401；`/api/config` 不泄露 token
- **安全中心**：安全策略可调、实时会话 / IP 锁定监控与一键解锁、安全事件审计、在线修改管理密码（成功后强制重登）
---
## 🔒 可选增强（TLS / ACL / 流量统计）

### HTTPS Web 面板 与 隧道 TLS
```yaml
# server.yaml
web_tls_cert: /etc/nexuslink/cert.pem   # 配置后 Web 面板启用 HTTPS
web_tls_key:  /etc/nexuslink/key.pem
bind_tls_cert: /etc/nexuslink/cert.pem  # 配置后隧道控制通道 + TCP 数据通道启用 TLS
bind_tls_key:  /etc/nexuslink/key.pem   # （UDP 数据通道仍为明文，应用层 HMAC 认证）
```
```yaml
# client.yaml（隧道 TLS 时开启）
tls_enable: true
tls_ca: /path/ca.pem      # 可选：服务端 CA 证书
tls_insecure: true        # 可选：自签证书场景跳过校验
```

### 代理创建 ACL
限制客户端可创建的代理（全部为空时不限制）：
```yaml
# server.yaml
proxy_acl:
  allow_names: ["^web-.*"]     # 代理名正则白名单
  allow_ports: [7001, 9000]    # 允许的远程端口
```

### 流量统计
Web 面板「代理 / 隧道列表」实时显示每个隧道的收发流量（TCP，内存统计）。

## 💡 使用示例
### 穿透 Minecraft 服务器（TCP）
```yaml
# client.yaml
proxies:
  mc:
    type: tcp
    port: 25565
    localaddr: 127.0.0.1
    localport: 25565
```
外网玩家连接：`你的服务器IP:25565`
### 转发 UDP 服务（如游戏 / DNS 查询）
```yaml
# client.yaml
proxies:
  dns:
    type: udp
    port: 25566
    localaddr: 127.0.0.1
    localport: 53
```
### 本地测试（服务端客户端同一机器）
```yaml
# client.yaml
server_ip: 127.0.0.1
server_port: 7000
token: test123
```
---
## 📝 常见问题
**Q: 提示 Permission denied?** — `chmod +x nexuslink-*`
**Q: 提示 address already in use?** — 检查端口是否被占用，确认没有重复运行服务端。
**Q: 客户端连接失败?** — 检查服务器防火墙开放 `bind_port` 与代理端口；确认 token 一致；检查 `server_ip` 是否正确。
**Q: 客户端提示 `[认证失败] invalid token` 后退出?** — 这是设计行为：token 错误属于配置问题，客户端不再无限重连，而是明确提示并退出（退出码 1）。请核对 `client.yaml` 的 `token` 与服务端 `server.yaml` 的 `token` 完全一致（注意大小写与空格），然后重新启动客户端。
**Q: UDP 不通?** — 确认服务端 `bind_port` 与 UDP 代理的 `port` 均已放通；NAT 环境下客户端需主动建链（本工具已通过独立 UDP 数据通道处理）。
---
## 📜 开源协议（License）
本项目以 **GNU General Public License v3.0（GPL-3.0）** 开源，遵循以下两条核心原则：
1. **源码公开**：本仓库的全部源代码完全公开，任何人可自由查看、学习、使用与分发。
2. **修改公开（Copyleft 传染）**：任何第三方基于本仓库进行修改、并对外分发（含作为网络服务运行）其修改版本时，**必须以相同的 GPL-3.0 协议公开其修改后的完整源代码**，且不可转为闭源或附加额外限制性条款。
> 简而言之：你可以自由使用与修改，但**改了就必须把改后的源码也开源**，并沿用 GPL-3.0。
完整协议文本见仓库根目录的 [LICENSE](LICENSE) 文件。
---
**NexusLink - 安全、高效、跨平台的内网穿透工具**

### 白名单配置（v0.3.7+）
```yaml
# server.yaml
whitelist:
  - "127.0.0.1"           # 单 IP（自动补 /32）
  - "192.168.1.0/24"      # 内网段
  - "113.13.215.0/24"     # 远程 NAT 公网段
```
- 命中规则：先查白名单 → 完全绕过 ConnGuard（不检查黑名单/频率/连接数，不计数）
- 防误封：白名单 IP 不会被 `BanIP()` 加入黑名单
- 格式错误时启动失败（fail-fast），避免运行时才发现
- 典型用途：客户端在 NAT/防火墙后被频繁误封、调试期临时放行可信 IP

