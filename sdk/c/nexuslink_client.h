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

/* 下线隧道 */
char *nexuslink_close_proxy(nexuslink_client *c, const char *name);

/* 创建 API Key */
char *nexuslink_create_api_key(nexuslink_client *c, const char *key, const char *note);

/* 删除 API Key */
char *nexuslink_delete_api_key(nexuslink_client *c, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* NEXUSLINK_CLIENT_H */
