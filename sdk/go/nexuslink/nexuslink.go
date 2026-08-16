// Package nexuslink 提供 NexusLink 开放 API v1 的 Go 客户端。
// 零第三方依赖（标准库 net/http），支持客户端/隧道/流量/API Key 管理。
//
// 使用：
//
//	api := nexuslink.New("http://SERVER:7001", "dev_api_key_789")
//	api.CreateClient("customer-a", "tok_a_1", 3, 0)
//	api.CreateProxy("web", "tcp", 8099, 9000, "127.0.0.1", "customer-a")
package nexuslink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client NexusLink 开放 API 客户端
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New 创建客户端（baseURL 形如 http://SERVER:7001）
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// ClientInfo 客户端信息（API 返回）
type ClientInfo struct {
	Name            string `json:"name"`
	BytesIn         int64  `json:"bytesIn"`
	BytesOut        int64  `json:"bytesOut"`
	Connected       bool   `json:"connected"`
	ProxyCount      int    `json:"proxyCount"`
	MaxTunnels      int    `json:"maxTunnels"`
	MaxTrafficBytes int64  `json:"maxTrafficBytes"`
}

// ProxyInfo 隧道信息（API 返回）
type ProxyInfo struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePort int    `json:"remote_port"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	ClientName string `json:"client_name"`
	Enabled    bool   `json:"enabled"`
	Active     bool   `json:"active"`
}

// APIKey API 密钥信息
type APIKey struct {
	Key       string `json:"key"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

// request 发送请求并解析 JSON 响应
func (c *Client) request(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 先尝试解析 JSON 错误信息
	var envelope struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &envelope)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error != "" {
			return fmt.Errorf("API %d: %s", resp.StatusCode, envelope.Error)
		}
		return fmt.Errorf("API %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ==================== 客户端管理 ====================

// CreateClient 创建客户端凭据（maxTunnels=0 不限，maxTrafficBytes=0 不限）
func (c *Client) CreateClient(name, token string, maxTunnels int, maxTrafficBytes int64) error {
	return c.request("POST", "/api/v1/clients", map[string]any{
		"name": name, "token": token, "max_tunnels": maxTunnels, "max_traffic_bytes": maxTrafficBytes,
	}, nil)
}

// ListClients 列出所有客户端（含流量/配额/在线状态）
func (c *Client) ListClients() ([]ClientInfo, error) {
	var out struct {
		Clients []ClientInfo `json:"clients"`
	}
	if err := c.request("GET", "/api/v1/clients", nil, &out); err != nil {
		return nil, err
	}
	return out.Clients, nil
}

// GetTraffic 查询单个客户端流量
func (c *Client) GetTraffic(name string) (ClientInfo, error) {
	var out struct {
		Client ClientInfo `json:"client"`
	}
	err := c.request("GET", "/api/v1/clients/"+name+"/traffic", nil, &out)
	return out.Client, err
}

// DeleteClient 删除客户端并踢下线
func (c *Client) DeleteClient(name string) error {
	return c.request("DELETE", "/api/v1/clients/"+name, nil, nil)
}

// ==================== 隧道管理（DB 驱动） ====================

// CreateProxy 创建隧道（DB 持久化，客户端自动同步注册）
func (c *Client) CreateProxy(name, typ string, remotePort, localPort int, localAddr, clientName string) error {
	return c.request("POST", "/api/v1/proxies", map[string]any{
		"name": name, "type": typ, "remote_port": remotePort,
		"local_addr": localAddr, "local_port": localPort, "client_name": clientName,
	}, nil)
}

// ListProxies 列出所有隧道（DB 定义 + 运行时状态）
// 支持过滤：ListProxiesFilter{ClientName, Type, Enabled, Active, Search}
func (c *Client) ListProxies() ([]ProxyInfo, error) {
	return c.ListProxiesFilter(ProxyFilter{})
}

// ProxyFilter 隧道列表过滤条件
type ProxyFilter struct {
	ClientName string
	Type       string
	Enabled    *bool
	Active     *bool
	Search     string
}

// ListProxiesFilter 按条件列出部分隧道
func (c *Client) ListProxiesFilter(f ProxyFilter) ([]ProxyInfo, error) {
	q := []string{}
	if f.ClientName != "" {
		q = append(q, "client_name="+f.ClientName)
	}
	if f.Type != "" {
		q = append(q, "type="+f.Type)
	}
	if f.Enabled != nil {
		q = append(q, "enabled="+fmt.Sprint(*f.Enabled))
	}
	if f.Active != nil {
		q = append(q, "active="+fmt.Sprint(*f.Active))
	}
	if f.Search != "" {
		q = append(q, "q="+f.Search)
	}
	path := "/api/v1/proxies"
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	var out struct {
		Proxies []ProxyInfo `json:"proxies"`
	}
	if err := c.request("GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out.Proxies, nil
}

// GetProxy 查看单个隧道详情
func (c *Client) GetProxy(name string) (ProxyInfo, error) {
	var out struct {
		Proxy ProxyInfo `json:"proxy"`
	}
	err := c.request("GET", "/api/v1/proxies/"+name, nil, &out)
	return out.Proxy, err
}

// UpdateProxy 编辑隧道（部分更新：只更新非 nil 字段；name 不可改）
func (c *Client) UpdateProxy(name string, patch ProxyPatch) (ProxyInfo, error) {
	var out struct {
		Proxy ProxyInfo `json:"proxy"`
	}
	err := c.request("PATCH", "/api/v1/proxies/"+name, patch, &out)
	return out.Proxy, err
}

// ProxyPatch 隧道编辑字段（nil 表示不修改）
type ProxyPatch struct {
	Type       *string `json:"type,omitempty"`
	RemotePort *int    `json:"remote_port,omitempty"`
	LocalAddr  *string `json:"local_addr,omitempty"`
	LocalPort  *int    `json:"local_port,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
}

// DeleteProxy 删除隧道（DB + 运行时下线）
func (c *Client) DeleteProxy(name string) error {
	return c.request("DELETE", "/api/v1/proxies/"+name, nil, nil)
}

// EnableProxy 启用隧道
func (c *Client) EnableProxy(name string) error {
	return c.request("POST", "/api/v1/proxies/"+name+"/enable", nil, nil)
}

// DisableProxy 停用隧道
func (c *Client) DisableProxy(name string) error {
	return c.request("POST", "/api/v1/proxies/"+name+"/disable", nil, nil)
}

// CloseProxy 下线运行中的隧道（不删除定义）
func (c *Client) CloseProxy(name string) error {
	return c.request("POST", "/api/v1/proxies/close", map[string]any{"name": name}, nil)
}

// ==================== API Key 管理 ====================

// ListAPIKeys 列出 API 密钥
func (c *Client) ListAPIKeys() ([]APIKey, error) {
	var out struct {
		APIKeys []APIKey `json:"api_keys"`
	}
	if err := c.request("GET", "/api/v1/api-keys", nil, &out); err != nil {
		return nil, err
	}
	return out.APIKeys, nil
}

// CreateAPIKey 创建 API 密钥（立即生效）
func (c *Client) CreateAPIKey(key, note string) error {
	return c.request("POST", "/api/v1/api-keys", map[string]any{"key": key, "note": note}, nil)
}

// DeleteAPIKey 删除 API 密钥
func (c *Client) DeleteAPIKey(key string) error {
	return c.request("DELETE", "/api/v1/api-keys/"+key, nil, nil)
}
