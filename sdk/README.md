# NexusLink 多语言 SDK

对接 NexusLink v0.6.0+ 的 `/api/v1/*` 开放接口（X-API-Key 鉴权），
支持 **Java / Python / C / curl** 四种对接方式。

> 所有 SDK 都基于同一个 REST API（HTTP + JSON），功能一致：
> 客户端管理、流量查询、隧道下线、API Key 管理。

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

### 1. Python

```bash
pip install requests
python3 sdk/python/nexuslink_client.py http://SERVER:7001 dev_api_key_789 demo
```

```python
from nexuslink_client import NexusLinkClient
api = NexusLinkClient("http://SERVER:7001", "dev_api_key_789")
api.create_client("customer-a", "tok_a_1", max_tunnels=3, max_traffic_bytes=1048576)
print(api.get_traffic("customer-a"))
api.delete_client("customer-a")
```

### 2. Java（JDK 11+，无第三方依赖）

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

### 3. C（libcurl）

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

### 4. curl

```bash
chmod +x sdk/curl/nexuslink.sh
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 create-client customer-a tok_a_1 3 1048576
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 traffic customer-a
./sdk/curl/nexuslink.sh dev_api_key_789 http://SERVER:7001 delete-client customer-a
```

---

## API 速查（四种语言等价）

| 功能 | Python | Java | C | curl |
|------|--------|------|---|------|
| 创建客户端 | `create_client(name,token,max_tunnels,max_traffic)` | `createClient(...)` | `nexuslink_create_client(...)` | `create-client name token max_tunnels max_traffic` |
| 客户端列表 | `list_clients()` | `listClients()` | `nexuslink_list_clients(...)` | `list-clients` |
| 查询流量 | `get_traffic(name)` | `getTraffic(name)` | `nexuslink_get_traffic(...)` | `traffic name` |
| 删除客户端 | `delete_client(name)` | `deleteClient(name)` | `nexuslink_delete_client(...)` | `delete-client name` |
| 下线隧道 | `close_proxy(name)` | `closeProxy(name)` | `nexuslink_close_proxy(...)` | `close-proxy name` |
| 创建 API Key | `create_api_key(key,note)` | `createApiKey(key,note)` | `nexuslink_create_api_key(...)` | `create-api-key key note` |
| 删除 API Key | `delete_api_key(key)` | `deleteApiKey(key)` | `nexuslink_delete_api_key(...)` | `delete-api-key key` |

---

## 典型对接流程（第三方平台）

1. **平台创建客户**：`POST /api/v1/clients` 分配 token（含隧道/流量配额）
2. **下发配置**：把 token 写入客户的 `client.yaml`
3. **计量**：定时 `GET /api/v1/clients/{name}/traffic` 查询流量
4. **管控**：超配额 `POST /api/v1/proxies/close` 下线隧道；停用 `DELETE /api/v1/clients/{name}`
5. **鉴权**：请求头 `X-API-Key`（DB 模式动态管理，API 创建后立即生效，无需重启）

> 详细 API 文档见 [Wiki API](https://github.com/YSD-build/NexusLink/wiki/API)
