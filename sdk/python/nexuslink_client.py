#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NexusLink Python SDK - 内网穿透平台开放 API 客户端

对接 NexusLink v0.6.0+ 的 /api/v1/* 开放接口（X-API-Key 鉴权）。
支持：客户端管理、流量查询、隧道下线、API Key 管理。

依赖：requests（pip install requests）
"""
import requests


class NexusLinkClient:
    def __init__(self, base_url, api_key, timeout=10):
        """
        :param base_url: 服务端地址，如 http://127.0.0.1:7001
        :param api_key:  开放 API 密钥（X-API-Key）
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})

    # ---------- 通用请求 ----------
    def _req(self, method, path, **kwargs):
        resp = self.session.request(method, self.base_url + path, timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
        return resp.json()

    # ---------- 客户端管理 ----------
    def create_client(self, name, token, max_tunnels=0, max_traffic_bytes=0):
        """创建客户端凭据（token 发给客户配置到 client.yaml）"""
        return self._req("POST", "/api/v1/clients", json={
            "name": name, "token": token,
            "max_tunnels": max_tunnels, "max_traffic_bytes": max_traffic_bytes,
        })

    def list_clients(self):
        """列出所有客户端（含流量/配额/在线状态）"""
        return self._req("GET", "/api/v1/clients").get("clients", [])

    def get_client(self, name):
        """查询单个客户端详情"""
        return self._req("GET", f"/api/v1/clients/{name}").get("client")

    def delete_client(self, name):
        """删除客户端并踢下线"""
        return self._req("DELETE", f"/api/v1/clients/{name}")

    # ---------- 流量查询 ----------
    def get_traffic(self, name):
        """查询客户端流量（bytes_in / bytes_out）"""
        return self._req("GET", f"/api/v1/clients/{name}/traffic").get("client")

    # ---------- 隧道管理 ----------
    def close_proxy(self, name):
        """下线指定隧道"""
        return self._req("POST", "/api/v1/proxies/close", json={"name": name})

    # ---------- API Key 管理 ----------
    def list_api_keys(self):
        return self._req("GET", "/api/v1/api-keys").get("api_keys", [])

    def create_api_key(self, key, note=""):
        return self._req("POST", "/api/v1/api-keys", json={"key": key, "note": note})

    def delete_api_key(self, key):
        return self._req("DELETE", f"/api/v1/api-keys/{key}")


# ==================== 使用示例 ====================
if __name__ == "__main__":
    import sys

    # 用法: nexuslink_client.py [base_url] [api_key] [demo]
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7001"
    api_key = sys.argv[2] if len(sys.argv) > 2 else "dev_api_key_789"
    api = NexusLinkClient(base_url, api_key)

    if len(sys.argv) > 3 and sys.argv[3] == "demo":
        # 完整对接流程示例
        print("1. 创建客户端")
        api.create_client("customer-demo", "tok_demo_1", max_tunnels=3, max_traffic_bytes=1048576)
        print("2. 列出客户端")
        for c in api.list_clients():
            print(f"   {c['name']}: {c['bytesIn']}B in / {c['bytesOut']}B out, 隧道 {c['proxyCount']}")
        print("3. 查询流量")
        print("   ", api.get_traffic("customer-demo"))
        print("4. 创建 API Key")
        api.create_api_key("key_demo_2", "demo")
        print("5. 清理")
        api.delete_api_key("key_demo_2")
        api.delete_client("customer-demo")
    else:
        # 基础查询
        for c in api.list_clients():
            print(f"{c['name']}\t{c['bytesIn']}B in\t{c['bytesOut']}B out\t隧道 {c['proxyCount']}")
