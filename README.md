# NexusLink - 高性能带认证内网穿透工具

> 类似FRP但增加**每数据包HMAC-SHA256认证**，防篡改防重放，纯Go编译无依赖

---

## 📦 下载安装

**Release 下载：** https://github.com/YSD-build/NexusLink/releases

| 版本 | 说明 |
|------|------|
| **v0.1.0.Server** | 服务端（Linux x86_64/ARM64/ARMv7/ARMv6） |
| **v0.1.0.Client** | 客户端（Linux/Windows/Android） |

---

## 🚀 快速开始

### 1️⃣ 服务端部署（公网服务器）

**下载服务端：**
```bash
# Linux x86_64
wget https://github.com/YSD-build/NexusLink/releases/download/v0.1.0.Server/nexuslink-server-v0.1.0.Server-linux-x86_64
chmod +x nexuslink-server-*
```

**创建配置 server.yaml：**
```yaml
bind_addr: 0.0.0.0
bind_port: 7000
token: 你的密钥
```

**运行服务端：**
```bash
./nexuslink-server-v0.1.0.Server-linux-x86_64 -c server.yaml
```

---

### 2️⃣ 客户端配置（内网机器/手机）

#### 🐧 Linux 客户端

**创建配置 client.yaml：**
```yaml
server_ip: 你的公网服务器IP
server_port: 7000
token: 你的密钥

proxies:
  mc:
    type: tcp
    port: 25565
    localaddr: 127.0.0.1
    localport: 25565
    
  ssh:
    type: tcp
    port: 6000
    localaddr: 127.0.0.1
    localport: 22
```

**运行：**
```bash
./nexuslink-client-v0.1.0.Client-linux-x86_64 -c client.yaml
```

---

#### 📱 Android 客户端（手机）

**无需Root，Termux直接运行：**

1. 安装 Termux: https://f-droid.org/packages/com.termux/

2. 下载客户端（绝大多数手机选 **android-arm64**）:
   - 骁龙/天玑手机: `nexuslink-client-v0.1.0.Client-android-arm64`
   - 旧设备: `nexuslink-client-v0.1.0.Client-android-armv7`

3. Termux 中运行:
```bash
chmod +x nexuslink-client-android-arm64
./nexuslink-client-android-arm64 -c client.yaml
```

---

#### 🪟 Windows 客户端

**创建配置 client.yaml，运行：**
```cmd
nexuslink-client-v0.1.0.Client-windows-x86_64.exe -c client.yaml
```

---

## ⚙️ 配置文件详解

### 客户端配置 client.yaml

```yaml
# 必填：服务端信息
server_ip: 1.2.3.4        # 你的公网服务器IP
server_port: 7000         # 服务端端口
token: your_secret_key    # 必须与服务端一致

# 代理配置（可添加多个）
proxies:
  # 示例1: Minecraft 服务器
  mc:
    type: tcp             # tcp 或 udp
    port: 25565           # 服务端暴露的端口
    localaddr: 127.0.0.1  # 本地服务地址
    localport: 25565      # 本地服务端口
  
  # 示例2: SSH
  ssh:
    type: tcp
    port: 6000
    localaddr: 127.0.0.1
    localport: 22
  
  # 示例3: Web服务
  web:
    type: tcp
    port: 8080
    localaddr: 127.0.0.1
    localport: 80
```

### 服务端配置 server.yaml

```yaml
bind_addr: 0.0.0.0    # 监听地址（默认0.0.0.0）
bind_port: 7000       # 监听端口
token: your_secret_key # 认证密钥
```

---

## 🔐 安全特性

### 每数据包认证机制

**数据包格式：**
```
[32字节 HMAC-SHA256 签名] [8字节 时间戳] [原始数据]
```

✅ **防篡改** - 每个数据包独立签名，中间人无法修改  
✅ **防重放** - 5分钟时间窗口验证  
✅ **防注入** - 恒时比较防止时序攻击  
✅ **Gzip压缩** - 可选流量压缩节省带宽

---

## 📊 支持架构

### 服务端 v0.1.0.Server
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| x86_64 | nexuslink-server-v0.1.0.Server-linux-x86_64 | PC、云服务器 |
| ARM64 | nexuslink-server-v0.1.0.Server-linux-armv8 | ARM服务器、树莓派4/5 |
| ARMv7 | nexuslink-server-v0.1.0.Server-linux-armv7 | 路由器、树莓派2/3 |
| ARMv6 | nexuslink-server-v0.1.0.Server-linux-armv6 | 旧嵌入式设备 |

### 客户端 v0.1.0.Client
| 架构 | 文件名 | 适用设备 |
|------|--------|----------|
| **android-arm64** | nexuslink-client-v0.1.0.Client-android-arm64 | ✅ 骁龙、天玑、绝大多数安卓手机 |
| android-armv7 | nexuslink-client-v0.1.0.Client-android-armv7 | 旧版安卓设备 |
| linux-x86_64 | nexuslink-client-v0.1.0.Client-linux-x86_64 | PC、虚拟机 |
| linux-armv8 | nexuslink-client-v0.1.0.Client-linux-armv8 | ARM服务器、树莓派 |
| linux-armv7 | nexuslink-client-v0.1.0.Client-linux-armv7 | 路由器 |
| linux-armv6 | nexuslink-client-v0.1.0.Client-linux-armv6 | 旧嵌入式设备 |
| windows-x86_64 | nexuslink-client-v0.1.0.Client-windows-x86_64.exe | Windows PC |

---

## 💡 使用示例

### 示例1: 穿透 Minecraft 服务器

**内网开服，外网可连：**

```yaml
# client.yaml
server_ip: 你的服务器IP
server_port: 7000
token: mc_server_123

proxies:
  mc:
    type: tcp
    port: 25565
    localaddr: 127.0.0.1
    localport: 25565
```

**外网玩家连接：** `你的服务器IP:25565`

---

### 示例2: 穿透本地 Web 服务

```yaml
# client.yaml
proxies:
  web:
    type: tcp
    port: 8080
    localaddr: 127.0.0.1
    localport: 80
```

**外网访问：** `http://你的服务器IP:8080`

---

### 示例3: 远程 SSH 内网机器

```yaml
# client.yaml
proxies:
  ssh:
    type: tcp
    port: 6000
    localaddr: 127.0.0.1
    localport: 22
```

**远程连接：** `ssh -p 6000 user@你的服务器IP`

---

## 🔧 编译说明

**本地编译：**
```bash
git clone https://github.com/YSD-build/NexusLink.git
cd NexusLink
go mod tidy

# 服务端
CGO_ENABLED=0 go build -o nexuslink-server ./cmd/server

# 客户端
CGO_ENABLED=0 go build -o nexuslink-client ./cmd/client

# Android 客户端
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o nexuslink-client-android-arm64 ./cmd/client
```

---

## 📝 常见问题

**Q: 连接失败怎么办？**
- 检查服务器防火墙是否开放 7000 端口和代理端口
- 确认 token 服务端和客户端一致
- 检查 server_ip 是否正确

**Q: Android 怎么下载文件到 Termux？**
```bash
# 在 Termux 中
pkg install wget
wget https://github.com/YSD-build/NexusLink/releases/download/v0.1.0.Client/nexuslink-client-v0.1.0.Client-android-arm64
```

**Q: 支持 UDP 吗？**
- 支持，配置 type: udp 即可

---

**NexusLink - 安全、高效、跨平台的内网穿透工具**
