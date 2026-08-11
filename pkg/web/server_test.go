package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// mock ProxyManager：提供固定的状态与空代理列表
type mockPM struct{}

func (mockPM) GetProxies() []ProxyInfo {
	return []ProxyInfo{}
}

func (mockPM) GetStatus() StatusInfo {
	return StatusInfo{Running: true, BindAddr: "0.0.0.0", BindPort: 7000, Version: "v0.3.7"}
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

// 带踢下线记录的 mock：验证请求体中的 ID 被正确透传
type kickRecorderPM struct {
	mockPM
	kicked string
}

func (k *kickRecorderPM) KickClient(id string) error {
	k.kicked = id
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
