# NexusLink 多语言 SDK

对接 NexusLink v0.6.0+ 的 `/api/v1/*` 开放接口（X-API-Key 鉴权），
支持 **Go / Python / Java / Node.js / PHP / C / curl** 七种对接方式。

> 所有 SDK 都基于同一个 REST API（HTTP + JSON），功能一致：
> 客户端管理、**隧道管理（DB 驱动）**、流量查询、API Key 管理。

---

## 快速开始

### 0. 前置：启用 DB 模式并创建 API Key

```yaml
# server.yaml
db_path: /data/nexuslink.db        # 内嵌 SQLite（数据持久化）
api_keys:
  - dev_api_key_789               # 首个 API Key（也可用 API 动态创建）
```

```bash
./nexuslink-server -c server.yaml
```

### 1. Go（标准库，无第三方依赖）

```bash
go run ./sdk/go/demo 2>/dev/null || true   # 或直接 import
```

```go
import "nexuslink/sdk/go/nexuslink"

api := nexuslink.New("http://SERVER:7001", "dev_api_key_789")
api.CreateClient("customer-a", "tok_a_1", 3, 0)
api.CreateProxy("web", "tcp", 8099, 9000, "127.0.0.1", "customer-a")
traffic, _ := api.GetTraffic("customer-a")
```

### 2. Python

```bash
pip install requests
python3 sdk/python/nexuslink_client.py http://SERVER:7001 dev_api_key_789 demo
```

```python
from nexuslink_client import NexusLinkClient
api = NexusLinkClient("http://SERVER:7001", "dev_api_key_789")
api.create_client("customer-a", "tok_a_1", max_tunnels=3, max_traffic_bytes=1048576)
api.create_proxy("web", "tcp", 8099, 9000, "127.0.0.1", "customer-a")
print(api.get_traffic("customer-a"))
api.delete_client("customer-a")
```

### 3. Java（JDK 11+，无第三方依赖）

```java
NexusLinkClient api = new NexusLinkClient("http://SERVER:7001", "dev_api_key_789");
api.createClient("customer-a", "tok_a_1", 3, 1048576);
System.out.println(api.getTraffic("customer-a"));
api.deleteClient("customer-a");
```

编译运行：
```bash
javac NexusLinkClient.java && java NexusLinkClient
```

### 4. Node.js（Node 18+，内置 fetch，零依赖）

```bash
node sdk/node/nexuslink.js http://SERVER:7001 dev_api_key_789 create-client customer-a tok_a_1 3 1048576
node sdk/node/nexuslink.js http://SERVER:7001 dev_api_key_789 create-proxy web tcp 8099 9000 127.0.0.1 customer-a
node sdk/node/nexuslink.js http://SERVER:7001 dev_api_key_789 traffic customer-a
```

```js
const { NexusLinkClient } = require('./nexuslink.js');
const api = new NexusLinkClient('http://SERVER:7001', 'dev_api_key_789');
await api.createClient('customer-a', 'tok_a_1', 3, 0);
console.log(await api.getTraffic('customer-a'));
```

### 5. PHP（php-curl 扩展，零依赖）

```bash
php sdk/php/nexuslink.php demo http://SERVER:7001 dev_api_key_789 create-client customer-a tok_a_1 3 1048576
php sdk/php/nexuslink.php demo http://SERVER:7001 dev_api_key_789 create-proxy web tcp 8099 9000 127.0.0.1 customer-a
```

```php
$api = new NexusLinkClient('http://SERVER:7001', 'dev_api_key_789');
$api->createClient('customer-a', 'tok_a_1', 3, 0);
print_r($api->getTraffic('customer-a'));
```

### 6. C（libcurl）

```bash
gcc -o demo nexuslink_demo.c nexuslink_client.c -lcurl
```

```c
nexuslink_client *api = nexuslink_new("http://SERVER:7001", "dev_api_key_789");
char *r = nexuslink_create_client(api, "customer-a", "tok_a_1", 3, 1048576);
free(r);
r = nexuslink_get_traffic(api, "customer-a");
free(r);
nexuslink_free(api);
```

### 7. curl

```bash
chmod +x sdk/curl/nexuslink.sh
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 create-client customer-a tok_a_1 3 1048576
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 create-proxy web tcp 8099 9000 127.0.0.1 customer-a
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 traffic customer-a
```

---

## API 速查（七种语言等价）

| 功能 | Go | Python | Java | Node.js | PHP | C | curl |
|------|----|--------|------|---------|-----|---|------|
| 创建客户端 | `CreateClient(...)` | `create_client(...)` | `createClient(...)` | `createClient(...)` | `createClient(...)` | `nexuslink_create_client(...)` | `create-client name token max_tunnels max_traffic` |
| 客户端列表 | `ListClients()` | `list_clients()` | `listClients()` | `listClients()` | `listClients()` | `nexuslink_list_clients(...)` | `list-clients` |
| 查询流量 | `GetTraffic(name)` | `get_traffic(name)` | `getTraffic(name)` | `getTraffic(name)` | `getTraffic(name)` | `nexuslink_get_traffic(...)` | `traffic name` |
| 删除客户端 | `DeleteClient(name)` | `delete_client(name)` | `deleteClient(name)` | `deleteClient(name)` | `deleteClient(name)` | `nexuslink_delete_client(...)` | `delete-client name` |
| **创建隧道** | `CreateProxy(...)` | `create_proxy(...)` | `createProxy(...)` | `createProxy(...)` | `createProxy(...)` | `nexuslink_create_proxy(...)` | `create-proxy name type remote local localaddr client` |
| **隧道列表** | `ListProxies()` | `list_proxies()` | `listProxies()` | `listProxies()` | `listProxies()` | `nexuslink_list_proxies(...)` | `list-proxies` |
| **删除隧道** | `DeleteProxy(name)` | `delete_proxy(name)` | `deleteProxy(name)` | `deleteProxy(name)` | `deleteProxy(name)` | `nexuslink_delete_proxy(...)` | `delete-proxy name` |
| **停用隧道** | `DisableProxy(name)` | `disable_proxy(name)` | `disableProxy(name)` | `disableProxy(name)` | `disableProxy(name)` | `nexuslink_disable_proxy(...)` | `disable-proxy name` |
| 下线隧道 | `CloseProxy(name)` | `close_proxy(name)` | `closeProxy(name)` | `closeProxy(name)` | `closeProxy(name)` | `nexuslink_close_proxy(...)` | `close-proxy name` |
| 创建 API Key | `CreateAPIKey(key,note)` | `create_api_key(key,note)` | `createApiKey(key,note)` | `createAPIKey(key,note)` | `createAPIKey(key,note)` | `nexuslink_create_api_key(...)` | `create-api-key key note` |
| 删除 API Key | `DeleteAPIKey(key)` | `delete_api_key(key)` | `deleteApiKey(key)` | `deleteAPIKey(key)` | `deleteAPIKey(key)` | `nexuslink_delete_api_key(...)` | `delete-api-key key` |

> C SDK 的隧道管理函数名与上面一致（`nexuslink_create_proxy` 等），详见 `sdk/c/nexuslink_client.h`。

---

## 隧道保存方式（v0.6.0 DB 驱动）

隧道不再写在客户端的 `client.yaml`，而是**由平台在服务端创建并持久化到 SQLite**：

1. `POST /api/v1/clients` 创建客户（分配 token）
2. `POST /api/v1/proxies` 为该客户创建隧道（服务端 DB 保存）
3. 客户端的 `client.yaml` 只需 `server_ip / server_port / token`，连接后自动从服务端同步隧道并注册
4. 平台随时 `GET /api/v1/proxies` 查看隧道状态（enabled / active），`disable` / `delete` 管控

客户端也支持**命令行 / 环境变量**直接指定接入信息（无需 yaml）：

```bash
# 命令行
nexuslink-client -server 1.2.3.4 -port 7000 -token xxx
# 环境变量
NEXUSLINK_SERVER=1.2.3.4 NEXUSLINK_PORT=7000 NEXUSLINK_TOKEN=xxx nexuslink-client
```

---

## 典型对接流程（第三方平台）

1. **平台创建客户**：`POST /api/v1/clients` 分配 token（含隧道/流量配额）
2. **平台创建隧道**：`POST /api/v1/proxies` 定义隧道（服务端持久化）
3. **下发接入**：把 server/token 发给客户（yaml 或环境变量/命令行）
4. **计量**：定时 `GET /api/v1/clients/{name}/traffic` 查询流量
5. **管控**：超配额 `disable-proxy` / `close-proxy`；停用 `DELETE /api/v1/clients/{name}`
6. **鉴权**：请求头 `X-API-Key`（DB 模式动态管理，API 创建后立即生效，无需重启）

> 详细 API 文档见 [Wiki API](https://github.com/YSD-build/NexusLink/wiki/API)
