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
- 🖥️ **Web 管理面板**：状态 / 配置 / 日志 / 代理管理，登录失败锁定 + CSRF 防护
- 📜 **GPL-3.0 开源**
---
## 📌 当前版本
**v0.3.1** — 修复 TCP/UDP 穿透阻断（数据通道与控制通道解耦），并加固数据安全（恒时比较、Web 限流、XFF 收敛、会话清理 5min）。
> 下载与资产见下方「下载安装」。历史说明见 [Releases](https://github.com/YSD-build/NexusLink/releases)。
---
## 📦 下载安装
所有资产发布在 **[v0.3.1 Release](https://github.com/YSD-build/NexusLink/releases/tag/v0.3.1)**。
### 🖥️ 服务端（4 架构）
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| x86_64 | `nexuslink-server-v0.3.1-linux-x86_64` | PC、云服务器、虚拟机 |
| **ARM64** | `nexuslink-server-v0.3.1-linux-armv8` | ✅ ARM 服务器、树莓派 4/5 |
| ARMv7 | `nexuslink-server-v0.3.1-linux-armv7` | 路由器、树莓派 2/3 |
| ARMv6 | `nexuslink-server-v0.3.1-linux-armv6` | 旧嵌入式设备 |
### 📱 客户端（6 版本）
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| **android-arm64** | `nexuslink-client-v0.3.1-android-arm64` | ✅ 骁龙、天玑、绝大多数安卓手机（Termux 无 Root） |
| linux-x86_64 | `nexuslink-client-v0.3.1-linux-x86_64` | PC、虚拟机 |
| linux-armv8 | `nexuslink-client-v0.3.1-linux-armv8` | ARM 服务器、树莓派 |
| linux-armv7 | `nexuslink-client-v0.3.1-linux-armv7` | 路由器 |
| linux-armv6 | `nexuslink-client-v0.3.1-linux-armv6` | 旧嵌入式设备 |
| windows-x86_64 | `nexuslink-client-v0.3.1-windows-x86_64.exe` | Windows PC |
### 🌐 Web 面板
`nexuslink-web-panel-v0.3.1.zip` — 独立 Node.js 版管理面板（已内置 x86_64 二进制）。服务端二进制本身也已内置面板，直接访问 `web_addr:web_port` 即可。
---
## 🚀 快速开始
### 1️⃣ 服务端部署（公网服务器）
```bash
# 以 ARM64 为例
wget https://github.com/YSD-build/NexusLink/releases/download/v0.3.1/nexuslink-server-v0.3.1-linux-armv8
chmod +x nexuslink-server-v0.3.1-linux-armv8
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
**运行：** `./nexuslink-server-v0.3.1-linux-armv8 -c server.yaml`
正常输出：
```
NexusLink Server v0.3.1 starting...
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
**运行（Linux）：** `./nexuslink-client-v0.3.1-linux-armv8 -c client.yaml`
正常输出：
```
NexusLink Client v0.3.1 starting...
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
   wget https://github.com/YSD-build/NexusLink/releases/download/v0.3.1/nexuslink-client-v0.3.1-android-arm64
   chmod +x nexuslink-client-v0.3.1-android-arm64
   ./nexuslink-client-v0.3.1-android-arm64 -c client.yaml
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
- 单 IP 并发连接数限制（默认 10）
- 连接频率限制，超限自动封禁
- 协议层畸形包（非法魔数 / 超长 length / 非法类型）在分配内存前即拒绝
### Web 面板防护
- 登录失败锁定（连续 5 次错误后锁定）
- 登录请求体限制 1MB（`MaxBytesReader`），防 OOM
- `HttpOnly` + `SameSite=Strict` Cookie + CSRF Token
- 受保护 API 未授权返回 401；`/api/config` 不泄露 token
---
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
