// Package web 内置Web管理面板 - 安全增强版
package web

import (
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
	"sync"
	"time"
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
}

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
}

// SecuritySettings 可调整的安全策略
type ProxyManager interface {
	GetProxies() []ProxyInfo
	GetStatus() StatusInfo
	GetClients() []ClientInfo
	KickClient(id string) error
	CloseProxy(name string) error
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
