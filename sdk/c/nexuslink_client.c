/*
 * NexusLink C SDK 实现（libcurl）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "nexuslink_client.h"

struct nexuslink_client {
    char base_url[256];
    char api_key[128];
};

/* curl 写回调：累积响应体 */
struct mem {
    char *data;
    size_t len;
};

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t n = size * nmemb;
    struct mem *m = (struct mem *)userdata;
    char *p = realloc(m->data, m->len + n + 1);
    if (!p) return 0;
    m->data = p;
    memcpy(m->data + m->len, ptr, n);
    m->len += n;
    m->data[m->len] = '\0';
    return n;
}

nexuslink_client *nexuslink_new(const char *base_url, const char *api_key)
{
    nexuslink_client *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    snprintf(c->base_url, sizeof(c->base_url), "%s", base_url);
    snprintf(c->api_key, sizeof(c->api_key), "%s", api_key);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return c;
}

void nexuslink_free(nexuslink_client *c)
{
    if (c) {
        free(c);
        curl_global_cleanup();
    }
}

char *nexuslink_request(nexuslink_client *c, const char *method, const char *path, const char *body)
{
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    char url[512];
    snprintf(url, sizeof(url), "%s%s", c->base_url, path);

    struct mem resp = {0};
    struct curl_slist *headers = NULL;
    char auth[160];
    snprintf(auth, sizeof(auth), "X-API-Key: %s", c->api_key);
    headers = curl_slist_append(headers, auth);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } /* GET 默认 */

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code >= 400) {
        if (resp.data) free(resp.data);
        return NULL;
    }
    return resp.data; /* 调用方 free */
}

/* ---------- 便捷封装 ---------- */

char *nexuslink_create_client(nexuslink_client *c, const char *name, const char *token,
                              int max_tunnels, long long max_traffic_bytes)
{
    char body[512];
    snprintf(body, sizeof(body),
             "{\"name\":\"%s\",\"token\":\"%s\",\"max_tunnels\":%d,\"max_traffic_bytes\":%lld}",
             name, token, max_tunnels, max_traffic_bytes);
    return nexuslink_request(c, "POST", "/api/v1/clients", body);
}

char *nexuslink_list_clients(nexuslink_client *c)
{
    return nexuslink_request(c, "GET", "/api/v1/clients", NULL);
}

char *nexuslink_delete_client(nexuslink_client *c, const char *name)
{
    char path[320];
    snprintf(path, sizeof(path), "/api/v1/clients/%s", name);
    return nexuslink_request(c, "DELETE", path, NULL);
}

char *nexuslink_get_traffic(nexuslink_client *c, const char *name)
{
    char path[320];
    snprintf(path, sizeof(path), "/api/v1/clients/%s/traffic", name);
    return nexuslink_request(c, "GET", path, NULL);
}

char *nexuslink_close_proxy(nexuslink_client *c, const char *name)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"name\":\"%s\"}", name);
    return nexuslink_request(c, "POST", "/api/v1/proxies/close", body);
}

char *nexuslink_create_api_key(nexuslink_client *c, const char *key, const char *note)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"key\":\"%s\",\"note\":\"%s\"}", key, note);
    return nexuslink_request(c, "POST", "/api/v1/api-keys", body);
}

char *nexuslink_delete_api_key(nexuslink_client *c, const char *key)
{
    char path[320];
    snprintf(path, sizeof(path), "/api/v1/api-keys/%s", key);
    return nexuslink_request(c, "DELETE", path, NULL);
}
