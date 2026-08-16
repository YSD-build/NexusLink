import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * NexusLink Java SDK - 内网穿透平台开放 API 客户端
 *
 * 对接 NexusLink v0.6.0+ 的 /api/v1/* 开放接口（X-API-Key 鉴权）。
 * 纯 JDK 11+（java.net.http），无第三方依赖。
 *
 * 用法：
 *   NexusLinkClient api = new NexusLinkClient("http://127.0.0.1:7001", "dev_api_key_789");
 *   api.createClient("customer-a", "tok_a_1", 3, 1048576);
 *   ClientInfo c = api.getTraffic("customer-a");
 */
public class NexusLinkClient {

    private final String baseUrl;
    private final String apiKey;
    private final HttpClient http;

    public NexusLinkClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    /** 通用请求 */
    private String req(String method, String path, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("X-API-Key", apiKey)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15));
        if ("POST".equals(method)) {
            b = b.POST(body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        } else if ("PATCH".equals(method)) {
            b = b.method("PATCH", body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        } else if ("DELETE".equals(method)) {
            b = b.DELETE();
        } else {
            b = b.GET();
        }
        HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 400) {
            throw new RuntimeException("HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return resp.body();
    }

    // ---------- 客户端管理 ----------

    /** 创建客户端凭据（token 发给客户配置到 client.yaml） */
    public String createClient(String name, String token, int maxTunnels, long maxTrafficBytes) throws Exception {
        return req("POST", "/api/v1/clients",
                String.format("{\"name\":\"%s\",\"token\":\"%s\",\"max_tunnels\":%d,\"max_traffic_bytes\":%d}",
                        name, token, maxTunnels, maxTrafficBytes));
    }

    /** 列出所有客户端 */
    public String listClients() throws Exception {
        return req("GET", "/api/v1/clients", null);
    }

    /** 删除客户端并踢下线 */
    public String deleteClient(String name) throws Exception {
        return req("DELETE", "/api/v1/clients/" + name, null);
    }

    // ---------- 流量查询 ----------

    /** 查询客户端流量 */
    public String getTraffic(String name) throws Exception {
        return req("GET", "/api/v1/clients/" + name + "/traffic", null);
    }

    // ---------- 隧道管理 ----------

    /** 创建隧道（DB 持久化，客户端自动同步注册） */
    public String createProxy(String name, String type, int remotePort, int localPort, String localAddr, String clientName) throws Exception {
        return req("POST", "/api/v1/proxies",
                String.format("{\"name\":\"%s\",\"type\":\"%s\",\"remote_port\":%d,\"local_addr\":\"%s\",\"local_port\":%d,\"client_name\":\"%s\"}",
                        name, type, remotePort, localAddr, localPort, clientName));
    }

    /** 列出所有隧道（DB 定义 + 运行时状态） */
    public String listProxies() throws Exception {
        return req("GET", "/api/v1/proxies", null);
    }

    /** 查看单个隧道详情 */
    public String getProxy(String name) throws Exception {
        return req("GET", "/api/v1/proxies/" + name, null);
    }

    /** 编辑隧道（部分更新，如 {\"remote_port\":8088,\"enabled\":false}） */
    public String updateProxy(String name, String patchJson) throws Exception {
        return req("PATCH", "/api/v1/proxies/" + name, patchJson);
    }

    /** 删除隧道（DB + 运行时下线） */
    public String deleteProxy(String name) throws Exception {
        return req("DELETE", "/api/v1/proxies/" + name, null);
    }

    /** 启用隧道 */
    public String enableProxy(String name) throws Exception {
        return req("POST", "/api/v1/proxies/" + name + "/enable", null);
    }

    /** 停用隧道 */
    public String disableProxy(String name) throws Exception {
        return req("POST", "/api/v1/proxies/" + name + "/disable", null);
    }

    /** 下线隧道（不删除定义） */
    public String closeProxy(String name) throws Exception {
        return req("POST", "/api/v1/proxies/close", "{\"name\":\"" + name + "\"}");
    }

    // ---------- API Key 管理 ----------

    public String listApiKeys() throws Exception {
        return req("GET", "/api/v1/api-keys", null);
    }

    public String createApiKey(String key, String note) throws Exception {
        return req("POST", "/api/v1/api-keys", "{\"key\":\"" + key + "\",\"note\":\"" + note + "\"}");
    }

    public String deleteApiKey(String key) throws Exception {
        return req("DELETE", "/api/v1/api-keys/" + key, null);
    }

    // ==================== 使用示例 ====================
    public static void main(String[] args) throws Exception {
        NexusLinkClient api = new NexusLinkClient("http://127.0.0.1:7001", "dev_api_key_789");

        // 1. 创建客户端
        api.createClient("customer-java", "tok_java_1", 3, 1048576);
        // 2. 列出客户端
        System.out.println("Clients: " + api.listClients());
        // 3. 查询流量
        System.out.println("Traffic: " + api.getTraffic("customer-java"));
        // 4. 清理
        api.deleteClient("customer-java");
    }
}
