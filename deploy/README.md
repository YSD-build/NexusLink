# systemd 部署 NexusLink 服务端

以 systemd 托管服务端，实现**开机自启**与**崩溃自动拉起**（`Restart=always`）。适用于 Linux 服务器、树莓派、玩客云等设备。

## 安装步骤

```bash
# 1. 下载服务端二进制（以 linux-armv8 为例，其他架构见 README）
V=v0.3.7
wget https://github.com/YSD-build/NexusLink/releases/download/${V}/nexuslink-server-${V}-linux-armv8
chmod +x nexuslink-server-${V}-linux-armv8
sudo mv nexuslink-server-${V}-linux-armv8 /usr/local/bin/nexuslink-server

# 2. 创建专用用户与目录
sudo useradd -r -s /usr/sbin/nologin nexuslink || true
sudo mkdir -p /opt/nexuslink
sudo chown nexuslink:nexuslink /opt/nexuslink

# 3. 准备配置文件（务必修改 token）
sudo cp server.yaml /opt/nexuslink/server.yaml
sudo chown nexuslink:nexuslink /opt/nexuslink/server.yaml

# 4. 安装 systemd 服务
sudo cp deploy/nexuslink.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nexuslink

# 5. 查看状态与日志
systemctl status nexuslink
journalctl -u nexuslink -f
```

> 服务文件中的用户/路径如需调整，编辑 `/etc/systemd/system/nexuslink.service` 后执行
> `sudo systemctl daemon-reload && sudo systemctl restart nexuslink`。

## 常用命令

| 操作 | 命令 |
|------|------|
| 启动 | `sudo systemctl start nexuslink` |
| 停止 | `sudo systemctl stop nexuslink` |
| 重启 | `sudo systemctl restart nexuslink` |
| 开机自启 | `sudo systemctl enable nexuslink` |
| 查看日志 | `journalctl -u nexuslink -f` |
| 实时状态 | `sudo systemctl status nexuslink` |

## 安全建议

- `server.yaml` 中 `token` 与 `web_password` 务必改为强随机值
- 公网部署建议通过 Nginx/Caddy 反向代理 Web 面板并启用 HTTPS
- systemd 已开启 `NoNewPrivileges`、`ProtectSystem=full` 等加固选项
