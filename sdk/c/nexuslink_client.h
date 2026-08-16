/*
 * NexusLink C SDK - 内网穿透平台开放 API 客户端
 *
 * 对接 NexusLink v0.6.0+ 的 /api/v1/* 开放接口（X-API-Key 鉴权）。
 * 依赖：libcurl + json-c（或用其它 JSON 库解析响应）
 *
 * 编译：
 *   gcc -o nexuslink_demo nexuslink_demo.c nexuslink_client.c -lcurl
 */
#ifndef NEXUSLINK_CLIENT_H
#define NEXUSLINK_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* 客户端句柄 */
typedef struct nexuslink_client nexuslink_client;

/* 创建客户端（base_url 如 http://127.0.0.1:7001，api_key 为 X-API-Key） */
nexuslink_client *nexuslink_new(const char *base_url, const char *api_key);

/* 释放 */
void nexuslink_free(nexuslink_client *c);

/*
 * 通用请求：method = "GET"/"POST"/"DELETE"，path 如 "/api/v1/clients"
 * body 为 JSON 字符串（GET/DELETE 传 NULL）
 * 返回响应体字符串（调用方 free），失败返回 NULL
 */
char *nexuslink_request(nexuslink_client *c, const char *method, const char *path, const char *body);

/* ---------- 便捷封装（返回原始 JSON 字符串，调用方 free） ---------- */

/* 创建客户端凭据 */
char *nexuslink_create_client(nexuslink_client *c, const char *name, const char *token,
                              int max_tunnels, long long max_traffic_bytes);

/* 列出所有客户端 */
char *nexuslink_list_clients(nexuslink_client *c);

/* 删除客户端并踢下线 */
char *nexuslink_delete_client(nexuslink_client *c, const char *name);

/* 查询客户端流量 */
char *nexuslink_get_traffic(nexuslink_client *c, const char *name);

/* ---------- 隧道管理（DB 驱动） ---------- */

/* 创建隧道（name/type/remote_port/local_addr/local_port/client_name） */
char *nexuslink_create_proxy(nexuslink_client *c, const char *name, const char *type,
                             int remote_port, int local_port, const char *local_addr, const char *client_name);

/* 列出所有隧道（DB 定义 + 运行时状态） */
char *nexuslink_list_proxies(nexuslink_client *c);

/* 查看单个隧道详情 */
char *nexuslink_get_proxy(nexuslink_client *c, const char *name);

/* 编辑隧道（部分更新，patch_json 如 {"remote_port":8088,"enabled":false}） */
char *nexuslink_update_proxy(nexuslink_client *c, const char *name, const char *patch_json);

/* 删除隧道（DB + 运行时下线） */
char *nexuslink_delete_proxy(nexuslink_client *c, const char *name);

/* 启用/停用隧道 */
char *nexuslink_enable_proxy(nexuslink_client *c, const char *name);
char *nexuslink_disable_proxy(nexuslink_client *c, const char *name);

/* 下线隧道（不删除定义） */
char *nexuslink_close_proxy(nexuslink_client *c, const char *name);

/* 创建 API Key */
char *nexuslink_create_api_key(nexuslink_client *c, const char *key, const char *note);

/* 删除 API Key */
char *nexuslink_delete_api_key(nexuslink_client *c, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* NEXUSLINK_CLIENT_H */
