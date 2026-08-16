// Package web 内置Web管理面板 - 安全增强版
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"nexuslink/pkg/store"
	"nexuslink/pkg/webhook"
)

//go:embed static/*
var staticFiles embed.FS

// WebServer Web管理面板服务
type WebServer struct {
	server        *http.Server
	passwordHash  string
	passwordSalt  string
	sessions      map[string]sessionInfo
	failedLogins  map[string]loginAttempt
	sessionMu     sync.RWMutex
	loginMu       sync.RWMutex
	logs          []LogEntry
	logsMu        sync.RWMutex
	proxyManager  ProxyManager
	config        *WebConfig
	security      SecuritySettings
	secMu         sync.RWMutex
	settingsFile  string
	apiKeys       map[string]bool // 静态 API Key（向后兼容）
	store         *store.Store    // 内嵌 SQLite（DB 驱动，动态 API Key）
}

// apiIdentity API 调用者身份（全局 API Key = 管理员；用户 API Token = 对应用户）
type apiIdentity struct {
	Admin    bool   // 全局 API Key（可管理一切）
	Username string // 用户 token 对应的用户名
	Role     string // admin / user
}

type ctxKey string

const identityKey ctxKey = "api_identity"

type sessionInfo struct {
	expireTime time.Time
	csrfToken  string
}

type loginAttempt struct {
	count     int
	lockUntil time.Time
}

// WebConfig Web面板配置
type WebConfig struct {
	Addr          string
	Port          int
	AdminPassword string
	TrustProxy    bool
	SettingsFile  string // web_settings.json 持久化路径
	CertFile      string // Web 面板 HTTPS 证书（可选，配置即启用 HTTPS）
	KeyFile       string // Web 面板 HTTPS 私钥
	APIKeys       []string // 静态 API Key（向后兼容；DB 模式下以数据库为准）
	Store         *store.Store // 内嵌 SQLite（DB 驱动，动态管理 API Key / 客户端）
	WebhookURL    string // Webhook 事件回调地址（隧道创建/删除/启停时推送）
}

// ClientTrafficInfo 客户端流量与配额信息（开放 API 返回结构）
type ClientTrafficInfo struct {
	Name            string `json:"name"`
	BytesIn         int64  `json:"bytesIn"`
	BytesOut        int64  `json:"bytesOut"`
	Connected       bool   `json:"connected"`
	ProxyCount      int    `json:"proxyCount"`
	MaxTunnels      int    `json:"maxTunnels"`
	MaxTrafficBytes int64  `json:"maxTrafficBytes"`
}

// SecuritySettings 可调整的安全策略
type ProxyManager interface {
	GetProxies() []ProxyInfo
	GetStatus() StatusInfo
	GetClients() []ClientInfo
	KickClient(id string) error
	CloseProxy(name string) error
	// 开放 API（v0.5.0 多租户）
	ListClientsTraffic() []ClientTrafficInfo
	GetClientTraffic(name string) (ClientTrafficInfo, bool)
	AddManagedClient(name, token string, maxTunnels int, maxTrafficBytes int64, owner string) error
	RemoveManagedClient(name string) error
	// NotifyClientSync 通知指定客户端的在线连接重新同步隧道（触发重连加载）
	NotifyClientSync(clientName string) error
}

// ProxyInfo 代理信息
type ProxyInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePort int    `json:"remotePort"`
	LocalAddr  string `json:"localAddr"`
	LocalPort  int    `json:"localPort"`
	Active     bool   `json:"active"`
	BytesIn    int64  `json:"bytesIn"`  // 入站字节（TCP）
	BytesOut   int64  `json:"bytesOut"` // 出站字节（TCP）
}

// ClientInfo 在线客户端信息
type ClientInfo struct {
	ID          string `json:"id"`       // clientID（服务端内部唯一标识）
	Name        string `json:"name"`     // 客户端名称（多租户身份；未托管为 "default"）
	Addr        string `json:"addr"`     // 客户端来源地址
	ConnectedAt string `json:"connectedAt"` // 连接时间（格式化）
	ProxyCount  int    `json:"proxyCount"`  // 该客户端拥有的隧道数
}

// StatusInfo 状态信息
type StatusInfo struct {
	Running     bool        `json:"running"`
	BindAddr    string      `json:"bindAddr"`
	BindPort    int         `json:"bindPort"`
	ClientCount int         `json:"clientCount"`
	ProxyCount  int         `json:"proxyCount"`
	Proxies     []ProxyInfo `json:"proxies"`
	Version     string      `json:"version"`
	Uptime      string      `json:"uptime"`
	StartTime   string      `json:"startTime"`
}

// LogEntry 日志条目
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// NewWebServer 创建Web服务器
func NewWebServer(cfg *WebConfig, proxyManager ProxyManager) *WebServer {
	// 生成随机盐值
	salt := generateSalt()

	settings := loadWebSettings(cfg.SettingsFile)

	ws := &WebServer{
		passwordHash: hashPasswordWithSalt(cfg.AdminPassword, salt),
		passwordSalt: salt,
		sessions:     make(map[string]sessionInfo),
		failedLogins: make(map[string]loginAttempt),
		logs:         make([]LogEntry, 0),
		proxyManager: proxyManager,
		config:       cfg,
		security:     settings.Security,
		settingsFile: cfg.SettingsFile,
	}

	// 开放 API Key（/api/v1/*）
	if len(cfg.APIKeys) > 0 {
		ws.apiKeys = make(map[string]bool, len(cfg.APIKeys))
		for _, k := range cfg.APIKeys {
			if k != "" {
				ws.apiKeys[k] = true
			}
		}
	}
	// DB 驱动：持有 store 引用（动态 API Key / 客户端管理）
	ws.store = cfg.Store
	if ws.store != nil {
		if keys, err := ws.store.ListAPIKeys(); err == nil && len(keys) > 0 {
			if ws.apiKeys == nil {
				ws.apiKeys = make(map[string]bool)
			}
			for _, k := range keys {
				ws.apiKeys[k.Key] = true
			}
			log.Printf("[API] 从数据库加载 %d 个 API Key", len(keys))
		}
	}

	// 优先使用 web_settings.json 中持久化的管理密码（修改过密码后重启仍生效）
	if settings.AdminPasswordHash != "" && settings.AdminPasswordSalt != "" {
		ws.passwordHash = settings.AdminPasswordHash
		ws.passwordSalt = settings.AdminPasswordSalt
	}

	// 启动session清理
	go ws.cleanupSessions()

	return ws
}

// Start 启动Web服务器
func (ws *WebServer) Start() error {
	mux := http.NewServeMux()

	// 静态文件
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// API接口
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/logout", ws.authMiddleware(ws.handleLogout))
	mux.HandleFunc("/api/status", ws.authMiddleware(ws.handleStatus))
	mux.HandleFunc("/api/proxies", ws.authMiddleware(ws.handleProxies))
	mux.HandleFunc("/api/config", ws.authMiddleware(ws.handleConfig))
	mux.HandleFunc("/api/logs", ws.authMiddleware(ws.handleLogs))
	mux.HandleFunc("/api/security", ws.authMiddleware(ws.handleSecurity))
	mux.HandleFunc("/api/security-status", ws.authMiddleware(ws.handleSecurityStatus))
	mux.HandleFunc("/api/security-unlock", ws.authMiddleware(ws.handleSecurityUnlock))
	mux.HandleFunc("/api/security-events", ws.authMiddleware(ws.handleSecurityEvents))
	mux.HandleFunc("/api/change-password", ws.authMiddleware(ws.handleChangePassword))
	mux.HandleFunc("/api/clients", ws.authMiddleware(ws.handleClients))
	mux.HandleFunc("/api/clients/kick", ws.authMiddleware(ws.handleKickClient))
	mux.HandleFunc("/api/proxies/close", ws.authMiddleware(ws.handleCloseProxy))

	// 开放 API v1（X-API-Key 鉴权，供第三方程序对接）
	mux.HandleFunc("/api/v1/clients", ws.apiKeyMiddleware(ws.v1HandleClients))
	mux.HandleFunc("/api/v1/clients/", ws.apiKeyMiddleware(ws.v1HandleClientPath))
	mux.HandleFunc("/api/v1/proxies/close", ws.apiKeyMiddleware(ws.v1HandleCloseProxy))
	mux.HandleFunc("/api/v1/proxies", ws.apiKeyMiddleware(ws.v1HandleProxies))
	mux.HandleFunc("/api/v1/proxies/", ws.apiKeyMiddleware(ws.v1HandleProxyPath))
	mux.HandleFunc("/api/v1/api-keys", ws.apiKeyMiddleware(ws.v1HandleAPIKeys))
	mux.HandleFunc("/api/v1/api-keys/", ws.apiKeyMiddleware(ws.v1HandleAPIKeyPath))
	mux.HandleFunc("/api/v1/users", ws.apiKeyMiddleware(ws.v1HandleUsers))
	mux.HandleFunc("/api/v1/users/", ws.apiKeyMiddleware(ws.v1HandleUserPath))
	mux.HandleFunc("/api/v1/login", ws.v1HandleLogin)

	addr := ws.config.Addr
	if addr == "" {
		addr = "127.0.0.1" // 默认只监听本地，安全
	}
	addr = addr + ":" + itoa(ws.config.Port)

	ws.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[Web] 管理面板启动于 http://%s (安全模式)", addr)
	ws.AddLog("info", fmt.Sprintf("Web管理面板已启动: %s", addr))

	// 安全警告
	host, _, _ := net.SplitHostPort(addr)
	if host == "0.0.0.0" || host == "" {
		log.Printf("[Web] 警告: Web面板监听在0.0.0.0，存在安全风险！建议仅监听127.0.0.1")
		ws.AddLog("warn", "警告：Web管理面板监听在0.0.0.0，存在安全风险")
	}

	go func() {
		var err error
		if ws.config.CertFile != "" && ws.config.KeyFile != "" {
			err = ws.server.ListenAndServeTLS(ws.config.CertFile, ws.config.KeyFile)
		} else {
			err = ws.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[Web] 服务器错误: %v", err)
			ws.AddLog("error", fmt.Sprintf("Web服务器错误: %v", err))
		}
	}()

	return nil
}

// Stop 停止Web服务器
func (ws *WebServer) Stop() {
	if ws.server != nil {
		ws.server.Close()
	}
}

// AddLog 添加日志
func (ws *WebServer) AddLog(level, msg string) {
	ws.logsMu.Lock()
	defer ws.logsMu.Unlock()

	entry := LogEntry{
		Time:    time.Now().Format("2006-01-02 15:04:05"),
		Level:   level,
		Message: msg,
	}
	ws.logs = append(ws.logs, entry)

	// 最多保留500条
	if len(ws.logs) > 500 {
		ws.logs = ws.logs[len(ws.logs)-500:]
	}
}

// ==================== 安全相关 ====================

// 生成随机盐值
func generateSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 带盐值的密码哈希
func hashPasswordWithSalt(password, salt string) string {
	// 多次哈希增加破解难度
	hash := sha256.Sum256([]byte(salt + password + salt))
	for i := 0; i < 1000; i++ {
		hash = sha256.Sum256(hash[:])
	}
	return hex.EncodeToString(hash[:])
}

// 生成Session ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 生成CSRF Token
func generateCSRFToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 获取客户端IP（方法：依据 WebConfig.TrustProxy 决定是否信任 X-Forwarded-For）
func (ws *WebServer) getClientIP(r *http.Request) string {
	// 仅当显式配置信任反向代理时，才采用 X-Forwarded-For（默认 false，避免伪造 IP 绕过登录锁定）
	if ws.config != nil && ws.config.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return xff
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// 检查IP是否被锁定
func (ws *WebServer) isIPLocked(ip string) bool {
	ws.loginMu.RLock()
	defer ws.loginMu.RUnlock()

	attempt, exists := ws.failedLogins[ip]
	if !exists {
		return false
	}
	return time.Now().Before(attempt.lockUntil)
}

// 记录登录失败
func (ws *WebServer) recordFailedLogin(ip string) {
	ws.loginMu.Lock()
	defer ws.loginMu.Unlock()

	attempt := ws.failedLogins[ip]
	attempt.count++

	// 5次失败后锁定15分钟
	if attempt.count >= ws.getRateLimitMax() {
		attempt.lockUntil = time.Now().Add(time.Duration(ws.getRateLimitLockMin()) * time.Minute)
		attempt.count = 0
		log.Printf("[Web] IP %s 因登录失败次数过多被锁定15分钟", ip)
	}

	ws.failedLogins[ip] = attempt
}

// 记录登录成功，清除失败记录
func (ws *WebServer) recordSuccessfulLogin(ip string) {
	ws.loginMu.Lock()
	defer ws.loginMu.Unlock()
	delete(ws.failedLogins, ip)
}

// 清理过期session
func (ws *WebServer) cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// 清理过期session
		ws.sessionMu.Lock()
		now := time.Now()
		for id, session := range ws.sessions {
			if now.After(session.expireTime) {
				delete(ws.sessions, id)
			}
		}
		ws.sessionMu.Unlock()

		// 清理过期的登录失败记录
		ws.loginMu.Lock()
		for ip, attempt := range ws.failedLogins {
			if now.After(attempt.lockUntil) && attempt.count == 0 {
				delete(ws.failedLogins, ip)
			}
		}
		ws.loginMu.Unlock()
	}
}

// ==================== HTTP处理函数 ====================

// 登录处理
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 安全头
	ws.applySecurityHeaders(w)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := ws.getClientIP(r)

	// 检查IP是否被锁定
	if ws.isIPLocked(ip) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("登录失败次数过多，请%d分钟后再试", ws.getRateLimitLockMin()),
		})
		ws.AddLog("warn", fmt.Sprintf("登录尝试被拒绝（IP已锁定）: %s", ip))
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	// 限制请求体大小（默认 1MB）：防止超大 body 触发连接重置而非规范 413
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 验证密码（使用恒时比较防止时序攻击）
	hash := hashPasswordWithSalt(req.Password, ws.passwordSalt)
	if subtle.ConstantTimeCompare([]byte(hash), []byte(ws.passwordHash)) != 1 {
		ws.recordFailedLogin(ip)
		ws.AddLog("warn", fmt.Sprintf("登录失败（密码错误）: %s", ip))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "密码错误"})
		return
	}

	// 登录成功
	ws.recordSuccessfulLogin(ip)

	// 创建Session
	sessionID := generateSessionID()
	csrfToken := generateCSRFToken()

	ws.sessionMu.Lock()
	ws.sessions[sessionID] = sessionInfo{
		expireTime: time.Now().Add(ws.getSessionTimeout()),
		csrfToken:  csrfToken,
	}
	ws.sessionMu.Unlock()

	// 设置Cookie（安全选项）
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: ws.security.HttpOnlyCookie, // 防止XSS窃取
		Secure:   r.TLS != nil,               // HTTPS时启用Secure
		SameSite: ws.sameSite(),              // 防止CSRF
		MaxAge:   ws.getSessionTimeoutSec(),  // 30分钟
	})

	ws.AddLog("info", fmt.Sprintf("管理员登录成功: %s", ip))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"csrf_token": csrfToken,
	})
}

// 登出处理
func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		ws.sessionMu.Lock()
		delete(ws.sessions, cookie.Value)
		ws.sessionMu.Unlock()
	}

	// 清除Cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	ws.AddLog("info", "管理员登出")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// 状态处理
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := ws.proxyManager.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// 代理处理
func (ws *WebServer) handleProxies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		proxies := ws.proxyManager.GetProxies()
		json.NewEncoder(w).Encode(proxies)
	default:
		// 不支持修改操作，安全考虑
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "暂不支持在线修改代理，请修改配置文件后重启服务",
		})
	}
}

// 配置处理（只读，安全考虑）
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		// 只返回非敏感信息
		json.NewEncoder(w).Encode(map[string]interface{}{
			"web_addr": ws.config.Addr,
			"web_port": ws.config.Port,
		})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "暂不支持在线修改配置，请修改配置文件后重启服务",
		})
	}
}

// 在线客户端列表
func (ws *WebServer) handleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": ws.proxyManager.GetClients(),
	})
}

// 强制下线客户端
func (ws *WebServer) handleKickClient(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少客户端 ID"})
		return
	}
	if err := ws.proxyManager.KickClient(req.ID); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	ws.AddLog("info", fmt.Sprintf("Web 强制下线客户端 [%s]", req.ID))
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// 下线隧道
func (ws *WebServer) handleCloseProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少隧道名称"})
		return
	}
	if err := ws.proxyManager.CloseProxy(req.Name); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// 日志处理
func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		ws.logsMu.RLock()
		logs := make([]LogEntry, len(ws.logs))
		copy(logs, ws.logs)
		ws.logsMu.RUnlock()

		// 反转顺序，最新的在前
		for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
			logs[i], logs[j] = logs[j], logs[i]
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":  logs,
			"total": len(logs),
		})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

// 安全信息
func (ws *WebServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 安全头
		ws.applySecurityHeaders(w)

		// 从Cookie获取Session
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ws.sessionMu.RLock()
		session, exists := ws.sessions[cookie.Value]
		ws.sessionMu.RUnlock()

		if !exists || time.Now().After(session.expireTime) {
			// 清理过期session
			if exists {
				ws.sessionMu.Lock()
				delete(ws.sessions, cookie.Value)
				ws.sessionMu.Unlock()
			}
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// 续期（每次访问续期30分钟）
		ws.sessionMu.Lock()
		ws.sessions[cookie.Value] = sessionInfo{
			expireTime: time.Now().Add(30 * time.Minute),
			csrfToken:  session.csrfToken,
		}
		ws.sessionMu.Unlock()

		// 对于状态改变的请求，检查CSRF Token
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			if ws.security.CSRFProtection {
				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					csrfToken = r.FormValue("csrf_token")
				}
				if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(session.csrfToken)) != 1 {
					http.Error(w, "Invalid CSRF token", http.StatusForbidden)
					return
				}
			}
		}

		next(w, r)
	}
}

// 设置安全头
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ==================== 设置与 AI 巡查 ====================

// ==================== 开放 API v1（API Key 鉴权） ====================

// apiKeyMiddleware 鉴权并识别调用者身份：
//   - 全局 API Key（server.yaml api_keys 或 DB api_keys 表）→ 管理员（可管理一切）
//   - 用户 API Token（users.api_token）→ 该用户（仅管理自己的客户端/隧道）
// 凭据来源：X-API-Key 请求头，或 Authorization: Bearer <token>
func (ws *WebServer) apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				key = strings.TrimPrefix(h, "Bearer ")
			}
		}
		if key == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少 X-API-Key 或 Authorization: Bearer"})
			return
		}
		// 1) DB 全局 API Key → 管理员
		if ws.store != nil {
			if ok, _ := ws.store.HasAPIKey(key); ok {
				next(w, r.WithContext(context.WithValue(r.Context(), identityKey, apiIdentity{Admin: true, Role: "admin"})))
				return
			}
			// 2) 用户 API Token → 对应用户
			if u, ok, _ := ws.store.GetUserByToken(key); ok {
				next(w, r.WithContext(context.WithValue(r.Context(), identityKey, apiIdentity{Username: u.Username, Role: u.Role})))
				return
			}
		}
		// 3) 静态 map 回退（管理员）
		if len(ws.apiKeys) > 0 && ws.apiKeys[key] {
			next(w, r.WithContext(context.WithValue(r.Context(), identityKey, apiIdentity{Admin: true, Role: "admin"})))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid API key or token"})
	}
}

// currentIdentity 从请求上下文取调用者身份
func (ws *WebServer) currentIdentity(r *http.Request) apiIdentity {
	if v, ok := r.Context().Value(identityKey).(apiIdentity); ok {
		return v
	}
	return apiIdentity{Admin: true} // 兜底：未注入则视为管理员（不应发生）
}

// canAccessClient 判断当前身份是否能访问指定客户端（管理员全量 / 用户限自己）
func (ws *WebServer) canAccessClient(r *http.Request, clientName string) bool {
	id := ws.currentIdentity(r)
	if id.Admin {
		return true
	}
	if ws.store == nil {
		return false
	}
	c, found, _ := ws.store.GetClient(clientName)
	return found && c.Owner == id.Username
}

// GET /api/v1/clients  → 客户端列表（含流量与配额）
// POST /api/v1/clients → 创建客户端凭据 {name, token, max_tunnels, max_traffic_bytes}
func (ws *WebServer) v1HandleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		id := ws.currentIdentity(r)
		all := ws.proxyManager.ListClientsTraffic()
		if id.Admin {
			// 管理员：附加客户端归属（owner）
			ownerOf := map[string]string{}
			if ws.store != nil {
				if clis, err := ws.store.ListClients(); err == nil {
					for _, c := range clis {
						ownerOf[c.Name] = c.Owner
					}
				}
			}
			type clientRow struct {
				ClientTrafficInfo
				Owner string `json:"owner"`
			}
			rows := make([]clientRow, 0, len(all))
			for _, c := range all {
				rows = append(rows, clientRow{ClientTrafficInfo: c, Owner: ownerOf[c.Name]})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "clients": rows})
			return
		}
		// 用户：只返回自己拥有的客户端
		mine := map[string]bool{}
		if ws.store != nil {
			if clis, err := ws.store.ListClientsByOwner(id.Username); err == nil {
				for _, c := range clis {
					mine[c.Name] = true
				}
			}
		}
		filtered := make([]ClientTrafficInfo, 0, len(all))
		for _, c := range all {
			if mine[c.Name] {
				filtered = append(filtered, c)
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "clients": filtered})
	case http.MethodPost:
		var req struct {
			Name            string `json:"name"`
			Token           string `json:"token"`
			MaxTunnels      int    `json:"max_tunnels"`
			MaxTrafficBytes int64  `json:"max_traffic_bytes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Token == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 name 与 token"})
			return
		}
		id := ws.currentIdentity(r)
		owner := ""
		if !id.Admin {
			owner = id.Username // 用户创建的客户端归自己
		}
		if err := ws.proxyManager.AddManagedClient(req.Name, req.Token, req.MaxTunnels, req.MaxTrafficBytes, owner); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// GET    /api/v1/clients/{name}/traffic → 单客户端流量
// GET    /api/v1/clients/{name}         → 单客户端详情
// DELETE /api/v1/clients/{name}         → 删除客户端并踢下线
func (ws *WebServer) v1HandleClientPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少客户端名称"})
		return
	}
	name := parts[0]

	// 用户隔离：非管理员只能操作自己拥有的客户端
	if id := ws.currentIdentity(r); !id.Admin {
		if ws.store != nil {
			c, found, _ := ws.store.GetClient(name)
			if !found || c.Owner != id.Username {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "无权访问该客户端"})
				return
			}
		}
	}

	switch r.Method {
	case http.MethodGet:
		if len(parts) >= 2 && parts[1] == "traffic" {
			info, found := ws.proxyManager.GetClientTraffic(name)
			if !found {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "客户端不存在"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "client": info})
			return
		}
		info, found := ws.proxyManager.GetClientTraffic(name)
		if !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "客户端不存在"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "client": info})
	case http.MethodDelete:
		if err := ws.proxyManager.RemoveManagedClient(name); err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// POST /api/v1/proxies/close → 下线隧道 {name}
func (ws *WebServer) v1HandleCloseProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少隧道名称"})
		return
	}
	if err := ws.proxyManager.CloseProxy(req.Name); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// GET  /api/v1/api-keys         → 列出 API 密钥
// POST /api/v1/api-keys         → 创建 API 密钥 {key, note}
func (ws *WebServer) v1HandleAPIKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "未启用 DB 模式（db_path 未配置），API Key 管理不可用"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		keys, err := ws.store.ListAPIKeys()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "api_keys": keys})
	case http.MethodPost:
		var req struct {
			Key  string `json:"key"`
			Note string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 key"})
			return
		}
		if err := ws.store.AddAPIKey(req.Key, req.Note); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		// 同步内存索引（立即生效）
		if ws.apiKeys == nil {
			ws.apiKeys = make(map[string]bool)
		}
		ws.apiKeys[req.Key] = true
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// DELETE /api/v1/api-keys/{key} → 删除 API 密钥
func (ws *WebServer) v1HandleAPIKeyPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
		return
	}
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "未启用 DB 模式"})
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
	key = strings.Trim(key, "/")
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少 key"})
		return
	}
	ok, err := ws.store.DeleteAPIKey(key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "API Key 不存在"})
		return
	}
	delete(ws.apiKeys, key)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// ==================== 隧道 DB 驱动 API（v0.6.0） ====================

// GET  /api/v1/proxies → 隧道列表（DB 定义 + 运行时状态）
// POST /api/v1/proxies → 创建隧道 {name,type,remote_port,local_addr,local_port,client_name}
func (ws *WebServer) v1HandleProxies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道 DB 驱动未启用（需配置 db_path）"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		// 过滤参数：?client_name=&type=&enabled=&active=&q=（名称模糊搜索）
		qClient := r.URL.Query().Get("client_name")
		qType := r.URL.Query().Get("type")
		qEnabled := r.URL.Query().Get("enabled")
		qActive := r.URL.Query().Get("active")
		qSearch := r.URL.Query().Get("q")

		proxies, err := ws.store.ListProxies()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		// 附加运行时状态
		runtime := map[string]bool{}
		for _, p := range ws.proxyManager.GetProxies() {
			runtime[p.Name] = p.Active
		}
		type row struct {
			store.Proxy
			Active bool `json:"active"`
		}
		rows := make([]row, 0, len(proxies))
		for _, p := range proxies {
			active := runtime[p.Name]
			// 用户隔离：非管理员只能看自己客户端的隧道
			if !ws.canAccessClient(r, p.ClientName) {
				continue
			}
			// 过滤：client_name
			if qClient != "" && p.ClientName != qClient {
				continue
			}
			// 过滤：type
			if qType != "" && p.Type != qType {
				continue
			}
			// 过滤：enabled
			if qEnabled != "" {
				want := qEnabled == "1" || qEnabled == "true"
				if p.Enabled != want {
					continue
				}
			}
			// 过滤：active（运行时状态）
			if qActive != "" {
				want := qActive == "1" || qActive == "true"
				if active != want {
					continue
				}
			}
			// 过滤：q 名称模糊搜索
			if qSearch != "" && !strings.Contains(p.Name, qSearch) {
				continue
			}
			rows = append(rows, row{Proxy: p, Active: active})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "proxies": rows})
	case http.MethodPost:
		var req struct {
			Name       string `json:"name"`
			Type       string `json:"type"`
			RemotePort int    `json:"remote_port"`
			LocalAddr  string `json:"local_addr"`
			LocalPort  int    `json:"local_port"`
			ClientName string `json:"client_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "JSON 解析失败"})
			return
		}
		if req.Name == "" || req.ClientName == "" || req.RemotePort <= 0 || req.RemotePort > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 name/client_name 且 remote_port 在 1-65535"})
			return
		}
		if req.Type == "" {
			req.Type = "tcp"
		}
		if req.Type != "tcp" && req.Type != "udp" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "type 仅支持 tcp / udp"})
			return
		}
		if req.LocalAddr == "" {
			req.LocalAddr = "127.0.0.1"
		}
		// 校验客户端存在 + 用户隔离
		if !ws.canAccessClient(r, req.ClientName) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "客户端 [" + req.ClientName + "] 不存在"})
			return
		}
		// 配额校验：隧道数上限（0=不限）
		if cli, found, _ := ws.store.GetClient(req.ClientName); found && cli.MaxTunnels > 0 {
			existing, _ := ws.store.ListProxiesByClient(req.ClientName)
			if len(existing) >= cli.MaxTunnels {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": fmt.Sprintf("客户端 [%s] 隧道数已达上限 %d", req.ClientName, cli.MaxTunnels)})
				return
			}
		}
		if _, err := ws.store.CreateProxy(store.Proxy{
			Name:       req.Name,
			Type:       req.Type,
			RemotePort: req.RemotePort,
			LocalAddr:  req.LocalAddr,
			LocalPort:  req.LocalPort,
			ClientName: req.ClientName,
			Enabled:    true,
		}); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		// 通知在线客户端重连加载
		ws.proxyManager.NotifyClientSync(req.ClientName)
		webhook.Send(ws.config.WebhookURL, "proxy_created", map[string]any{
			"name": req.Name, "type": req.Type, "remote_port": req.RemotePort,
			"local_addr": req.LocalAddr, "local_port": req.LocalPort, "client_name": req.ClientName,
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "msg": "隧道已创建，客户端重连后生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// GET    /api/v1/proxies/{name}           → 单隧道详情
// DELETE /api/v1/proxies/{name}           → 删除隧道（DB + 运行时下线）
// POST   /api/v1/proxies/{name}/enable    → 启用
// POST   /api/v1/proxies/{name}/disable   → 停用
func (ws *WebServer) v1HandleProxyPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道 DB 驱动未启用（需配置 db_path）"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proxies/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" || parts[0] == "close" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少隧道名称"})
		return
	}
	name := parts[0]

	// 用户隔离：非管理员只能操作自己客户端名下的隧道
	if id := ws.currentIdentity(r); !id.Admin {
		p, found, _ := ws.store.GetProxy(name)
		if !found || !ws.canAccessClient(r, p.ClientName) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "无权访问该隧道"})
			return
		}
	}

	if len(parts) >= 2 {
		// enable / disable
		var enabled bool
		switch parts[1] {
		case "enable":
			enabled = true
		case "disable":
			enabled = false
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "仅支持 enable / disable"})
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
			return
		}
		p, found, err := ws.store.GetProxy(name)
		if err != nil || !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道不存在"})
			return
		}
		if _, err := ws.store.SetProxyEnabled(name, enabled); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		// 停用时下线运行中的隧道
		if !enabled {
			ws.proxyManager.CloseProxy(name)
		}
		ws.proxyManager.NotifyClientSync(p.ClientName)
		webhook.Send(ws.config.WebhookURL, "proxy_disabled", map[string]any{
			"name": name, "client_name": p.ClientName,
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, found, err := ws.store.GetProxy(name)
		if err != nil || !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道不存在"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "proxy": p})
	case http.MethodPatch:
		// 编辑隧道（部分更新：只更新提供的字段）
		p, found, err := ws.store.GetProxy(name)
		if err != nil || !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道不存在"})
			return
		}
		var req struct {
			Type       *string `json:"type"`
			RemotePort *int    `json:"remote_port"`
			LocalAddr  *string `json:"local_addr"`
			LocalPort  *int    `json:"local_port"`
			Enabled    *bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "JSON 解析失败"})
			return
		}
		typ := p.Type
		if req.Type != nil {
			typ = *req.Type
		}
		remotePort := p.RemotePort
		if req.RemotePort != nil {
			remotePort = *req.RemotePort
		}
		localAddr := p.LocalAddr
		if req.LocalAddr != nil {
			localAddr = *req.LocalAddr
		}
		localPort := p.LocalPort
		if req.LocalPort != nil {
			localPort = *req.LocalPort
		}
		enabled := p.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if typ != "tcp" && typ != "udp" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "type 仅支持 tcp / udp"})
			return
		}
		if remotePort <= 0 || remotePort > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "remote_port 需在 1-65535"})
			return
		}
		if localAddr == "" {
			localAddr = "127.0.0.1"
		}
		if ok, err := ws.store.UpdateProxy(name, typ, remotePort, localPort, localAddr, enabled); err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "更新失败"})
			return
		}
		// 停用则下线运行中；更新后通知客户端重连
		if !enabled {
			ws.proxyManager.CloseProxy(name)
		}
		ws.proxyManager.NotifyClientSync(p.ClientName)
		webhook.Send(ws.config.WebhookURL, "proxy_updated", map[string]any{
			"name": name, "type": typ, "remote_port": remotePort,
			"local_addr": localAddr, "local_port": localPort, "enabled": enabled, "client_name": p.ClientName,
		})
		updated, _, _ := ws.store.GetProxy(name)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "proxy": updated})
	case http.MethodDelete:
		p, found, err := ws.store.GetProxy(name)
		if err != nil || !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "隧道不存在"})
			return
		}
		if ok, err := ws.store.DeleteProxy(name); err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "删除失败"})
			return
		}
		ws.proxyManager.CloseProxy(name)
		ws.proxyManager.NotifyClientSync(p.ClientName)
		webhook.Send(ws.config.WebhookURL, "proxy_deleted", map[string]any{
			"name": name, "client_name": p.ClientName,
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// ==================== 用户体系 API（v0.6.0） ====================

// GET  /api/v1/users → 用户列表（管理员）
// POST /api/v1/users → 创建用户 {username, password, role?}（管理员）
func (ws *WebServer) v1HandleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := ws.currentIdentity(r)
	if !id.Admin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "仅管理员可管理用户"})
		return
	}
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "未启用 DB 模式（需配置 db_path）"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := ws.store.ListUsers()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "users": users})
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 username 与 password"})
			return
		}
		if req.Role == "" {
			req.Role = "user"
		}
		if req.Role != "user" && req.Role != "admin" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "role 仅支持 user / admin"})
			return
		}
		u, err := ws.store.CreateUser(req.Username, req.Password, req.Role)
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户名已存在或创建失败: " + err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "user": u})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// GET    /api/v1/users/{username}             → 用户详情（含 API token；管理员或本人）
// DELETE /api/v1/users/{username}             → 删除用户（管理员）
// POST   /api/v1/users/{username}/reset-token → 重置 API token（管理员或本人）
// POST   /api/v1/users/{username}/password    → 修改密码（管理员或本人）
// POST   /api/v1/users/{username}/disable|enable → 停用/启用（管理员）
func (ws *WebServer) v1HandleUserPath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "缺少用户名"})
		return
	}
	username := parts[0]
	id := ws.currentIdentity(r)
	// 非管理员只能操作自己
	if !id.Admin && id.Username != username {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "无权操作其他用户"})
		return
	}
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "未启用 DB 模式"})
		return
	}

	// 子操作：reset-token / password / disable / enable
	if len(parts) >= 2 {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
			return
		}
		switch parts[1] {
		case "reset-token":
			token, ok, err := ws.store.ResetUserToken(username)
			if err != nil || !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户不存在"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "api_token": token})
		case "password":
			var req struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 password"})
				return
			}
			if ok, err := ws.store.UpdateUserPassword(username, req.Password); err != nil || !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户不存在"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case "disable", "enable":
			if !id.Admin {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "仅管理员可停用/启用用户"})
				return
			}
			status := "active"
			if parts[1] == "disable" {
				status = "disabled"
			}
			if ok, err := ws.store.SetUserStatus(username, status); err != nil || !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户不存在"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "仅支持 reset-token / password / disable / enable"})
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		u, found, err := ws.store.GetUser(username)
		if err != nil || !found {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户不存在"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "user": u})
	case http.MethodDelete:
		if !id.Admin {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "仅管理员可删除用户"})
			return
		}
		if ok, err := ws.store.DeleteUser(username); err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户不存在"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "method not allowed"})
	}
}

// POST /api/v1/login → 用户密码登录，换取 API token（第三方对接更友好）
func (ws *WebServer) v1HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if ws.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "未启用 DB 模式"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "需要 username 与 password"})
		return
	}
	u, ok := ws.store.VerifyUserPassword(req.Username, req.Password)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "用户名或密码错误"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "username": u.Username, "role": u.Role, "api_token": u.APIToken})
}
