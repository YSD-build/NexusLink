package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"nexuslink/pkg/store"
)

// mock ProxyManager：提供固定的状态与空代理列表
type mockPM struct{}

func (mockPM) GetProxies() []ProxyInfo {
	return []ProxyInfo{}
}

func (mockPM) GetStatus() StatusInfo {
	return StatusInfo{Running: true, BindAddr: "0.0.0.0", BindPort: 7000, Version: "v0.5.1"}
}

func (mockPM) GetClients() []ClientInfo {
	return []ClientInfo{
		{ID: "client-a", Addr: "10.0.0.1:5000", ConnectedAt: "2026-08-12 00:00:00", ProxyCount: 2},
		{ID: "client-b", Addr: "10.0.0.2:6000", ConnectedAt: "2026-08-12 00:05:00", ProxyCount: 0},
	}
}

func (mockPM) KickClient(id string) error {
	return nil
}

func (mockPM) CloseProxy(name string) error {
	return nil
}

// 开放 API mock
func (mockPM) ListClientsTraffic() []ClientTrafficInfo {
	return mockClientsTraffic()
}

func (mockPM) GetClientTraffic(name string) (ClientTrafficInfo, bool) {
	for _, c := range mockClientsTraffic() {
		if c.Name == name {
			return c, true
		}
	}
	return ClientTrafficInfo{}, false
}

func mockClientsTraffic() []ClientTrafficInfo {
	return []ClientTrafficInfo{
		{Name: "client-a", BytesIn: 100, BytesOut: 200, Connected: true, ProxyCount: 2, MaxTunnels: 5, MaxTrafficBytes: 1024},
		{Name: "client-b", BytesIn: 0, BytesOut: 0, Connected: false, ProxyCount: 0, MaxTunnels: 0, MaxTrafficBytes: 0},
	}
}

func (mockPM) AddManagedClient(name, token string, maxTunnels int, maxTrafficBytes int64, owner string) error {
	return nil
}

func (mockPM) RemoveManagedClient(name string) error {
	return nil
}

// 带踢下线记录的 mock：验证请求体中的 ID 被正确透传
type kickRecorderPM struct {
	mockPM
	kicked string
}

func (k *kickRecorderPM) KickClient(id string) error {
	k.kicked = id
	return nil
}

// 带下线隧道记录的 mock：验证请求体中的 name 被正确透传
type closeProxyRecorderPM struct {
	mockPM
	closed string
}

func (k *closeProxyRecorderPM) CloseProxy(name string) error {
	k.closed = name
	return nil
}

// newTestServer 构造与 Start() 相同的路由注册（httptest，无真实监听冲突）
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123"}, mockPM{})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/status", ws.authMiddleware(ws.handleStatus))
	mux.HandleFunc("/api/security", ws.authMiddleware(ws.handleSecurity))
	mux.HandleFunc("/api/change-password", ws.authMiddleware(ws.handleChangePassword))
	mux.HandleFunc("/api/clients", ws.authMiddleware(ws.handleClients))
	mux.HandleFunc("/api/clients/kick", ws.authMiddleware(ws.handleKickClient))
	mux.HandleFunc("/api/proxies/close", ws.authMiddleware(ws.handleCloseProxy))
	return httptest.NewServer(mux)
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func doLogin(t *testing.T, c *http.Client, url, pwd string) (int, string) {
	t.Helper()
	resp, err := c.Post(url+"/api/login", "application/json", strings.NewReader(`{"password":"`+pwd+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var d struct {
		Success bool   `json:"success"`
		Csrf    string `json:"csrf_token"`
	}
	_ = json.Unmarshal(body, &d)
	return resp.StatusCode, d.Csrf
}

// 未授权访问受保护 API 应返回 401
func TestUnauthorized(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	for _, path := range []string{"/api/security", "/api/status", "/api/change-password"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s 未授权应 401，得到 %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// 登录：正确密码成功且返回 CSRF；错误密码 401
func TestLogin(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	code, csrf := doLogin(t, c, ts.URL, "admin123")
	if code != http.StatusOK || csrf == "" {
		t.Fatalf("登录失败: code=%d csrf=%q", code, csrf)
	}
	c2 := newClient(t)
	code2, _ := doLogin(t, c2, ts.URL, "wrong-password")
	if code2 != http.StatusUnauthorized {
		t.Fatalf("错误密码应 401，得到 %d", code2)
	}
}

// GET /api/security 返回默认可调设置
func TestSecurityGetDefaults(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	doLogin(t, c, ts.URL, "admin123")
	resp, err := c.Get(ts.URL + "/api/security")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var d map[string]interface{}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	if d["session_timeout_min"].(float64) != 30 {
		t.Fatalf("默认会话超时应为 30，得到 %v", d["session_timeout_min"])
	}
	if d["csrf_protection"] != true {
		t.Fatalf("默认 CSRF 应为 true")
	}
}

// POST /api/security：无 CSRF 403，带 CSRF 200 且生效
func TestSecurityPostRequiresCSRF(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	_, csrf := doLogin(t, c, ts.URL, "admin123")

	resp, _ := c.Post(ts.URL+"/api/security", "application/json", strings.NewReader(`{"session_timeout_min":45}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无 CSRF 应 403，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/security", strings.NewReader(`{"session_timeout_min":45}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp2, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("带 CSRF 应 200，得到 %d", resp2.StatusCode)
	}
}

// 修改密码闭环：错误当前密码/过短拒绝，正确修改后旧会话失效、旧密码拒登、新密码可登
func TestChangePassword(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	_, csrf := doLogin(t, c, ts.URL, "admin123")

	post := func(cur, nw, token string) (int, string) {
		body := `{"current_password":"` + cur + `","new_password":"` + nw + `"}`
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/change-password", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var d struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(b, &d)
		return resp.StatusCode, d.Error
	}

	if _, e := post("wrong", "newpass123", csrf); e == "" {
		t.Fatal("错误当前密码应返回错误")
	}
	if _, e := post("admin123", "123", csrf); e == "" {
		t.Fatal("过短新密码应返回错误")
	}
	if code, _ := post("admin123", "newpass123", csrf); code != http.StatusOK {
		t.Fatal("正确修改密码应成功")
	}

	// 旧会话失效
	resp, _ := c.Get(ts.URL + "/api/status")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("改密后旧会话应 401，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 旧密码拒登
	c2 := newClient(t)
	if code, _ := doLogin(t, c2, ts.URL, "admin123"); code != http.StatusUnauthorized {
		t.Fatalf("旧密码应拒登，得到 %d", code)
	}
	// 新密码可登
	c3 := newClient(t)
	if code, _ := doLogin(t, c3, ts.URL, "newpass123"); code != http.StatusOK {
		t.Fatalf("新密码应登录成功，得到 %d", code)
	}
}

// 登录失败锁定：连续 5 次失败后第 6 次被拒（429）
func TestLoginLockout(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	for i := 0; i < 5; i++ {
		doLogin(t, c, ts.URL, "wrong")
	}
	code, _ := doLogin(t, c, ts.URL, "wrong")
	if code != http.StatusTooManyRequests {
		t.Fatalf("第 6 次失败应 429，得到 %d", code)
	}
}

// 在线客户端列表：登录后 GET /api/clients 返回客户端信息
func TestClientsList(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	code, csrf := doLogin(t, c, ts.URL, "admin123")
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}
	_ = csrf

	resp, err := c.Get(ts.URL + "/api/clients")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/clients 应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Clients []ClientInfo `json:"clients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if len(d.Clients) != 2 {
		t.Fatalf("应返回 2 个客户端，得到 %d", len(d.Clients))
	}
	if d.Clients[0].ID != "client-a" || d.Clients[0].ProxyCount != 2 {
		t.Fatalf("客户端信息不符: %+v", d.Clients[0])
	}
}

// 强制下线：POST /api/clients/kick 带 CSRF，ID 正确透传
func TestKickClient(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	rec := &kickRecorderPM{}
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123"}, rec)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/clients/kick", ws.authMiddleware(ws.handleKickClient))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newClient(t)
	code, csrf := doLogin(t, c, srv.URL, "admin123")
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}

	// 无 CSRF 拒绝
	resp, err := c.Post(srv.URL+"/api/clients/kick", "application/json",
		strings.NewReader(`{"id":"client-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 CSRF 应拒绝，得到 %d", resp.StatusCode)
	}

	// 带 CSRF 成功
	req, _ := http.NewRequest("POST", srv.URL+"/api/clients/kick",
		strings.NewReader(`{"id":"client-b"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带 CSRF 踢下线应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	if !d.Success {
		t.Fatal("踢下线应返回 success=true")
	}
	if rec.kicked != "client-b" {
		t.Fatalf("透传 ID 应为 client-b，得到 %q", rec.kicked)
	}
}

// 强制下线：缺少 ID 返回 400
func TestKickClientMissingID(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	code, csrf := doLogin(t, c, ts.URL, "admin123")
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/clients/kick",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少 ID 应 400，得到 %d", resp.StatusCode)
	}
}

// 下线隧道：POST /api/proxies/close 带 CSRF，name 正确透传
func TestCloseProxy(t *testing.T) {
	rec := &closeProxyRecorderPM{}
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123"}, rec)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/proxies/close", ws.authMiddleware(ws.handleCloseProxy))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newClient(t)
	code, csrf := doLogin(t, c, srv.URL, "admin123")
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}

	// 无 CSRF 拒绝
	resp, err := c.Post(srv.URL+"/api/proxies/close", "application/json",
		strings.NewReader(`{"name":"mc"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 CSRF 应拒绝，得到 %d", resp.StatusCode)
	}

	// 带 CSRF 成功
	req, _ := http.NewRequest("POST", srv.URL+"/api/proxies/close",
		strings.NewReader(`{"name":"mc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带 CSRF 下线隧道应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	if !d.Success {
		t.Fatal("下线隧道应返回 success=true")
	}
	if rec.closed != "mc" {
		t.Fatalf("透传 name 应为 mc，得到 %q", rec.closed)
	}
}

// 下线隧道：缺少 name 返回 400
func TestCloseProxyMissingName(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	c := newClient(t)
	code, csrf := doLogin(t, c, ts.URL, "admin123")
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/proxies/close",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少 name 应 400，得到 %d", resp.StatusCode)
	}
}

// ==================== 开放 API v1 测试 ====================

// 带 API Key 的测试 server（api_keys: ["test-key-1"]）
func newV1TestServer(t *testing.T) *httptest.Server {
	t.Helper()
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123", APIKeys: []string{"test-key-1"}}, mockPM{})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/clients", ws.apiKeyMiddleware(ws.v1HandleClients))
	mux.HandleFunc("/api/v1/clients/", ws.apiKeyMiddleware(ws.v1HandleClientPath))
	return httptest.NewServer(mux)
}

// 未配置 API Keys 时返回 503
func TestV1APIKeyNotConfigured(t *testing.T) {
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123"}, mockPM{})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/clients", ws.apiKeyMiddleware(ws.v1HandleClients))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/clients")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未配置 API Key 时任何 Key 都应 401，得到 %d", resp.StatusCode)
	}
}

// 无 Key / 错误 Key 返回 401
func TestV1APIKeyAuth(t *testing.T) {
	srv := newV1TestServer(t)
	defer srv.Close()

	// 无 Key
	resp, _ := http.Get(srv.URL + "/api/v1/clients")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 Key 应 401，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 错误 Key
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients", nil)
	req.Header.Set("X-API-Key", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误 Key 应 401，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// GET /api/v1/clients 返回客户端流量列表
func TestV1ListClients(t *testing.T) {
	srv := newV1TestServer(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients", nil)
	req.Header.Set("X-API-Key", "test-key-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET clients 应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Success bool                `json:"success"`
		Clients []ClientTrafficInfo `json:"clients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if !d.Success || len(d.Clients) != 2 {
		t.Fatalf("应返回 2 个客户端, got %+v", d)
	}
	if d.Clients[0].Name != "client-a" || d.Clients[0].BytesIn != 100 {
		t.Fatalf("客户端流量信息不符: %+v", d.Clients[0])
	}
}

// GET /api/v1/clients/{name}/traffic 单客户端流量
func TestV1GetClientTraffic(t *testing.T) {
	srv := newV1TestServer(t)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients/client-a/traffic", nil)
	req.Header.Set("X-API-Key", "test-key-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET traffic 应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Success bool              `json:"success"`
		Client ClientTrafficInfo `json:"client"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	if !d.Success || d.Client.Name != "client-a" || d.Client.BytesOut != 200 {
		t.Fatalf("单客户端流量不符: %+v", d.Client)
	}

	// 不存在
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients/nope/traffic", nil)
	req2.Header.Set("X-API-Key", "test-key-1")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在客户端应 404，得到 %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// POST /api/v1/clients 创建客户端（需要 name+token）
func TestV1CreateClient(t *testing.T) {
	srv := newV1TestServer(t)
	defer srv.Close()

	do := func(body string) *http.Response {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/clients", strings.NewReader(body))
		req.Header.Set("X-API-Key", "test-key-1")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 缺字段 400
	resp := do(`{"name":"x"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 token 应 400，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 正常创建 200
	resp = do(`{"name":"client-c","token":"tok-c","max_tunnels":3,"max_traffic_bytes":1024}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建应 200，得到 %d", resp.StatusCode)
	}
	var d struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	if !d.Success {
		t.Fatal("创建应 success")
	}
	resp.Body.Close()
}

// ==================== 隧道 DB 驱动 mock（v0.6.0） ====================

func (mockPM) NotifyClientSync(clientName string) error { return nil }

// ==================== 隧道 DB 驱动 API 测试（v0.6.0） ====================

// 带 DB 的 v1 测试 server（隧道 CRUD 用真实 SQLite 内存库）
func newV1ProxyTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.AddClient("customer-a", "token_a", 3, 0); err != nil {
		t.Fatalf("add client: %v", err)
	}
	if err := st.AddClient("customer-b", "token_b", 3, 0); err != nil {
		t.Fatalf("add client b: %v", err)
	}
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123", APIKeys: []string{"test-key"}, Store: st}, mockPM{})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/proxies", ws.apiKeyMiddleware(ws.v1HandleProxies))
	mux.HandleFunc("/api/v1/proxies/", ws.apiKeyMiddleware(ws.v1HandleProxyPath))
	return httptest.NewServer(mux), st
}

// 创建隧道 → 列表 → 详情 → 删除 全流程
func TestV1ProxyCRUD(t *testing.T) {
	srv, st := newV1ProxyTestServer(t)
	defer srv.Close()
	defer st.Close()

	key := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	// 创建
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/proxies",
		strings.NewReader(`{"name":"web","type":"tcp","remote_port":8099,"local_addr":"127.0.0.1","local_port":9000,"client_name":"customer-a"}`))
	resp, err := http.DefaultClient.Do(key(req))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if !d.Success || resp.StatusCode != http.StatusOK {
		t.Fatalf("创建隧道应 200 success，得到 %d %v", resp.StatusCode, d)
	}

	// 列表
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/proxies", nil)
	resp2, _ := http.DefaultClient.Do(key(req2))
	var list struct {
		Success bool `json:"success"`
		Proxies []struct {
			Name       string `json:"name"`
			ClientName string `json:"client_name"`
			Enabled    bool   `json:"enabled"`
			Active     bool   `json:"active"`
		} `json:"proxies"`
	}
	json.NewDecoder(resp2.Body).Decode(&list)
	resp2.Body.Close()
	if !list.Success || len(list.Proxies) != 1 || list.Proxies[0].Name != "web" {
		t.Fatalf("列表应包含 1 条 web 隧道，got %+v", list)
	}

	// 详情
	req3, _ := http.NewRequest("GET", srv.URL+"/api/v1/proxies/web", nil)
	resp3, _ := http.DefaultClient.Do(key(req3))
	var detail struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp3.Body).Decode(&detail)
	resp3.Body.Close()
	if !detail.Success {
		t.Fatal("详情应 success")
	}

	// 删除
	req4, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/proxies/web", nil)
	resp4, _ := http.DefaultClient.Do(key(req4))
	var del struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(resp4.Body).Decode(&del)
	resp4.Body.Close()
	if !del.Success {
		t.Fatal("删除应 success")
	}

	// 删除后列表为空
	req5, _ := http.NewRequest("GET", srv.URL+"/api/v1/proxies", nil)
	resp5, _ := http.DefaultClient.Do(key(req5))
	var after struct {
		Proxies []interface{} `json:"proxies"`
	}
	json.NewDecoder(resp5.Body).Decode(&after)
	resp5.Body.Close()
	if len(after.Proxies) != 0 {
		t.Fatalf("删除后应无隧道，got %d", len(after.Proxies))
	}
}

// 配额限制：客户端隧道数达上限后拒绝创建
func TestV1ProxyQuota(t *testing.T) {
	srv, st := newV1ProxyTestServer(t)
	defer srv.Close()
	defer st.Close()

	key := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	create := func(name string, port int) int {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/proxies",
			strings.NewReader(`{"name":"`+name+`","type":"tcp","remote_port":`+fmt.Sprint(port)+`,"local_addr":"127.0.0.1","local_port":9000,"client_name":"customer-a"}`))
		resp, err := http.DefaultClient.Do(key(req))
		if err != nil {
			t.Fatal(err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		return code
	}

	if create("a", 8101) != http.StatusOK {
		t.Fatal("第 1 条应成功")
	}
	if create("b", 8102) != http.StatusOK {
		t.Fatal("第 2 条应成功")
	}
	if create("c", 8103) != http.StatusOK {
		t.Fatal("第 3 条应成功")
	}
	if code := create("d", 8104); code != http.StatusConflict {
		t.Fatalf("第 4 条应 409（配额 3），得到 %d", code)
	}
}

// 编辑隧道：PATCH 部分更新（改端口/启停），其余字段保持
func TestV1ProxyUpdate(t *testing.T) {
	srv, st := newV1ProxyTestServer(t)
	defer srv.Close()
	defer st.Close()

	key := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	// 创建
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/proxies",
		strings.NewReader(`{"name":"web","type":"tcp","remote_port":8099,"local_addr":"127.0.0.1","local_port":9000,"client_name":"customer-a"}`))
	resp, _ := http.DefaultClient.Do(key(req))
	resp.Body.Close()

	// PATCH：只改 remote_port 与 enabled=false
	req2, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/proxies/web",
		strings.NewReader(`{"remote_port":8088,"enabled":false}`))
	resp2, _ := http.DefaultClient.Do(key(req2))
	var d struct {
		Success bool `json:"success"`
		Proxy   struct {
			Name       string `json:"name"`
			RemotePort int    `json:"remote_port"`
			LocalPort  int    `json:"local_port"`
			Type       string `json:"type"`
			Enabled    bool   `json:"enabled"`
		} `json:"proxy"`
	}
	json.NewDecoder(resp2.Body).Decode(&d)
	resp2.Body.Close()
	if !d.Success {
		t.Fatalf("PATCH 应 success，got %+v", d)
	}
	if d.Proxy.RemotePort != 8088 || d.Proxy.Enabled || d.Proxy.Type != "tcp" || d.Proxy.LocalPort != 9000 {
		t.Fatalf("编辑应只更新 remote_port/enabled，got %+v", d.Proxy)
	}

	// 不存在隧道 404
	req3, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/proxies/nope",
		strings.NewReader(`{"remote_port":1}`))
	resp3, _ := http.DefaultClient.Do(key(req3))
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("编辑不存在隧道应 404，得到 %d", resp3.StatusCode)
	}
	resp3.Body.Close()
}

// 列表过滤：client_name / type / enabled / active / q
func TestV1ProxyListFilter(t *testing.T) {
	srv, st := newV1ProxyTestServer(t)
	defer srv.Close()
	defer st.Close()

	key := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	// 创建 3 条
	for _, c := range []struct {
		name, typ string
		port      int
		client    string
	}{
		{"web", "tcp", 8101, "customer-a"},
		{"api", "udp", 8102, "customer-a"},
		{"db", "tcp", 8103, "customer-b"},
	} {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/proxies",
			strings.NewReader(`{"name":"`+c.name+`","type":"`+c.typ+`","remote_port":`+fmt.Sprint(c.port)+`,"local_addr":"127.0.0.1","local_port":9000,"client_name":"`+c.client+`"}`))
		resp, _ := http.DefaultClient.Do(key(req))
		resp.Body.Close()
	}
	// 停用 api
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/proxies/api/disable", nil)
	resp, _ := http.DefaultClient.Do(key(req))
	resp.Body.Close()

	getNames := func(path string) []string {
		r, _ := http.NewRequest("GET", srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(key(r))
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			Proxies []struct {
				Name string `json:"name"`
			} `json:"proxies"`
		}
		json.NewDecoder(resp.Body).Decode(&d)
		resp.Body.Close()
		out := []string{}
		for _, p := range d.Proxies {
			out = append(out, p.Name)
		}
		return out
	}

	if names := getNames("/api/v1/proxies?client_name=customer-a"); len(names) != 2 || names[0] != "web" {
		t.Fatalf("client_name 过滤应 2 条，got %v", names)
	}
	if names := getNames("/api/v1/proxies?type=udp"); len(names) != 1 || names[0] != "api" {
		t.Fatalf("type 过滤应 1 条 api，got %v", names)
	}
	if names := getNames("/api/v1/proxies?enabled=true"); len(names) != 2 {
		t.Fatalf("enabled=true 应 2 条，got %v", names)
	}
	if names := getNames("/api/v1/proxies?enabled=false"); len(names) != 1 || names[0] != "api" {
		t.Fatalf("enabled=false 应 1 条 api，got %v", names)
	}
	if names := getNames("/api/v1/proxies?q=db"); len(names) != 1 || names[0] != "db" {
		t.Fatalf("q 模糊搜索应 1 条 db，got %v", names)
	}
}

// ==================== 用户体系测试（v0.6.0） ====================

// 带用户系统的测试 server
func newUserTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.CreateUser("alice", "pass123", "user"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// 归属 mock：alice-client 属于 alice，other-client 属于他人
	pm := &ownerMockPM{}
	ws := NewWebServer(&WebConfig{AdminPassword: "admin123", APIKeys: []string{"admin-key"}, Store: st}, pm)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", ws.apiKeyMiddleware(ws.v1HandleUsers))
	mux.HandleFunc("/api/v1/users/", ws.apiKeyMiddleware(ws.v1HandleUserPath))
	mux.HandleFunc("/api/v1/login", ws.v1HandleLogin)
	mux.HandleFunc("/api/v1/clients", ws.apiKeyMiddleware(ws.v1HandleClients))
	mux.HandleFunc("/api/v1/clients/", ws.apiKeyMiddleware(ws.v1HandleClientPath))
	return httptest.NewServer(mux), st
}

// 管理员创建用户 → 用户密码登录 → 拿 token 访问
func TestV1UserFlow(t *testing.T) {
	srv, st := newUserTestServer(t)
	defer srv.Close()
	defer st.Close()

	admin := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", "admin-key")
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	// 管理员创建用户 bob
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/users",
		strings.NewReader(`{"username":"bob","password":"bobpass","role":"user"}`))
	resp, _ := http.DefaultClient.Do(admin(req))
	var created struct {
		Success bool `json:"success"`
		User    struct {
			Username string `json:"username"`
			APIToken string `json:"api_token"`
		} `json:"user"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if !created.Success || created.User.Username != "bob" || created.User.APIToken == "" {
		t.Fatalf("创建用户失败: %+v", created)
	}

	// bob 密码登录
	login, _ := http.NewRequest("POST", srv.URL+"/api/v1/login",
		strings.NewReader(`{"username":"bob","password":"bobpass"}`))
	lresp, _ := http.DefaultClient.Do(login)
	var lg struct {
		Success  bool   `json:"success"`
		Username string `json:"username"`
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(lresp.Body).Decode(&lg)
	lresp.Body.Close()
	if !lg.Success || lg.Username != "bob" {
		t.Fatalf("登录失败: %+v", lg)
	}

	// bob token 可用
	withToken := func(req *http.Request) *http.Request {
		req.Header.Set("X-API-Key", lg.APIToken)
		return req
	}
	creq, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients", nil)
	cresp, _ := http.DefaultClient.Do(withToken(creq))
	var cl struct {
		Success bool `json:"success"`
	}
	json.NewDecoder(cresp.Body).Decode(&cl)
	cresp.Body.Close()
	if !cl.Success {
		t.Fatal("用户 token 应可访问 /api/v1/clients")
	}
}

// 用户隔离：普通用户不能创建用户 / 不能访问他人客户端
func TestV1UserIsolation(t *testing.T) {
	srv, st := newUserTestServer(t)
	defer srv.Close()
	defer st.Close()

	// alice 创建客户端（归属 alice）
	if err := st.AddClientWithOwner("alice-client", "tok_a", 3, 0, "alice"); err != nil {
		t.Fatal(err)
	}

	// alice 密码登录
	login, _ := http.NewRequest("POST", srv.URL+"/api/v1/login",
		strings.NewReader(`{"username":"alice","password":"pass123"}`))
	lresp, _ := http.DefaultClient.Do(login)
	var lg struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(lresp.Body).Decode(&lg)
	lresp.Body.Close()

	// alice 不能创建用户（403）
	ureq, _ := http.NewRequest("POST", srv.URL+"/api/v1/users",
		strings.NewReader(`{"username":"x","password":"y"}`))
	ureq.Header.Set("X-API-Key", lg.APIToken)
	uresp, _ := http.DefaultClient.Do(ureq)
	if uresp.StatusCode != http.StatusForbidden {
		t.Fatalf("普通用户创建用户应 403，得到 %d", uresp.StatusCode)
	}
	uresp.Body.Close()

	// alice 能看到自己的客户端
	creq, _ := http.NewRequest("GET", srv.URL+"/api/v1/clients", nil)
	creq.Header.Set("X-API-Key", lg.APIToken)
	cresp, _ := http.DefaultClient.Do(creq)
	var cl struct {
		Clients []struct {
			Name string `json:"name"`
		} `json:"clients"`
	}
	json.NewDecoder(cresp.Body).Decode(&cl)
	cresp.Body.Close()
	if len(cl.Clients) != 1 || cl.Clients[0].Name != "alice-client" {
		t.Fatalf("alice 应只看到自己的客户端，got %+v", cl.Clients)
	}
}

// ownerMockPM 带归属数据的 mock：ListClientsTraffic 返回属于 alice 与他人的客户端
type ownerMockPM struct{ mockPM }

func (m *ownerMockPM) ListClientsTraffic() []ClientTrafficInfo {
	return []ClientTrafficInfo{
		{Name: "alice-client", Connected: true},
		{Name: "other-client", Connected: false},
	}
}
