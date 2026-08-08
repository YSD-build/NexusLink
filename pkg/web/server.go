// Package web 内置Web管理面板 - 安全增强版
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"bytes"
	"io"
	"os"
	"strings"
	"sync/atomic"
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
	ai            AISettings
	secMu         sync.RWMutex
	patrols       []PatrolResult
	patrolMu      sync.RWMutex
	patrolQuit    chan struct{}
	patrolRunning int32
	settingsFile  string
	patrolFile    string
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
	PatrolFile    string // AI 巡查历史持久化路径（patrol_history.json）
}



// SecuritySettings 可调整的安全策略
type SecuritySettings struct {
	SessionTimeoutMin int    `json:"session_timeout_min"`
	RateLimitMax      int    `json:"rate_limit_max"`
	RateLimitLockMin  int    `json:"rate_limit_lock_min"`
	CSRFProtection    bool   `json:"csrf_protection"`
	SecurityHeaders   bool   `json:"security_headers"`
	HttpOnlyCookie    bool   `json:"httponly_cookie"`
	SameSiteCookie    bool   `json:"samesite_cookie"`
	CustomCSP         string `json:"custom_csp"`
}

// AISettings AI 巡查配置（OpenAI 兼容 /v1/chat/completions）
type AISettings struct {
	Enabled     bool   `json:"enabled"`
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
	Model       string `json:"model"`
	IntervalMin int    `json:"interval_min"`
	Prompt      string `json:"prompt"`
	WebhookURL  string `json:"webhook_url"` // 风险告警通知地址（可选）
}

// WebSettings 持久化设置
type WebSettings struct {
	Security           SecuritySettings `json:"security"`
	AI                 AISettings       `json:"ai"`
	AdminPasswordHash  string           `json:"admin_password_hash,omitempty"`
	AdminPasswordSalt  string           `json:"admin_password_salt,omitempty"`
}

// PatrolResult AI 巡查结果
type PatrolResult struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}

// ProxyManager 代理管理器接口
type ProxyManager interface {
	GetProxies() []ProxyInfo
	GetStatus() StatusInfo
}

// ProxyInfo 代理信息
type ProxyInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePort int    `json:"remotePort"`
	LocalAddr  string `json:"localAddr"`
	LocalPort  int    `json:"localPort"`
	Active     bool   `json:"active"`
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
		ai:           settings.AI,
		patrolQuit:   make(chan struct{}),
		settingsFile: cfg.SettingsFile,
		patrolFile:   cfg.PatrolFile,
		patrols:      loadPatrolHistory(cfg.PatrolFile),
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
	mux.HandleFunc("/api/ai-config", ws.authMiddleware(ws.handleAIConfig))
	mux.HandleFunc("/api/ai-patrol", ws.authMiddleware(ws.handleAIPatrol))
	mux.HandleFunc("/api/security-status", ws.authMiddleware(ws.handleSecurityStatus))
	mux.HandleFunc("/api/security-unlock", ws.authMiddleware(ws.handleSecurityUnlock))
	mux.HandleFunc("/api/security-events", ws.authMiddleware(ws.handleSecurityEvents))
	mux.HandleFunc("/api/change-password", ws.authMiddleware(ws.handleChangePassword))

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
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Web] 服务器错误: %v", err)
			ws.AddLog("error", fmt.Sprintf("Web服务器错误: %v", err))
		}
	}()

	ws.startAIPatrolScheduler()

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
		HttpOnly: ws.security.HttpOnlyCookie,                          // 防止XSS窃取
		Secure:   r.TLS != nil,                  // HTTPS时启用Secure
		SameSite: ws.sameSite(),       // 防止CSRF
		MaxAge:   ws.getSessionTimeoutSec(),                          // 30分钟
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
func (ws *WebServer) handleSecurity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		ws.secMu.RLock()
		sec := ws.security
		ws.secMu.RUnlock()
		json.NewEncoder(w).Encode(sec)
		return
	}
	if r.Method == http.MethodPost {
		var req SecuritySettings
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if req.SessionTimeoutMin < 1 {
			req.SessionTimeoutMin = 1
		}
		if req.SessionTimeoutMin > 1440 {
			req.SessionTimeoutMin = 1440
		}
		if req.RateLimitMax < 1 {
			req.RateLimitMax = 1
		}
		if req.RateLimitMax > 100 {
			req.RateLimitMax = 100
		}
		if req.RateLimitLockMin < 1 {
			req.RateLimitLockMin = 1
		}
		if req.RateLimitLockMin > 1440 {
			req.RateLimitLockMin = 1440
		}
		ws.secMu.Lock()
		ws.security = req
		sec := ws.security
		ai := ws.ai
		ws.secMu.Unlock()
		if err := ws.saveSettings(sec, ai, ws.passwordHash, ws.passwordSalt); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "保存失败: " + err.Error()})
			return
		}
		ws.AddLog("info", "安全策略已更新")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "不支持的方法"})
}

// ==================== 中间件 ====================

// 认证中间件
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
func (ws *WebServer) applySecurityHeaders(w http.ResponseWriter) {
	ws.secMu.RLock()
	enabled := ws.security.SecurityHeaders
	csp := ws.security.CustomCSP
	ws.secMu.RUnlock()
	if !enabled {
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	if csp != "" {
		w.Header().Set("Content-Security-Policy", csp)
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	}
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

// ==================== 工具函数 ====================

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

func defaultSecuritySettings() SecuritySettings {
	return SecuritySettings{
		SessionTimeoutMin: 30,
		RateLimitMax:      5,
		RateLimitLockMin:  15,
		CSRFProtection:    true,
		SecurityHeaders:    true,
		HttpOnlyCookie:     true,
		SameSiteCookie:     true,
		CustomCSP:          "",
	}
}

func defaultAISettings() AISettings {
	return AISettings{
		Enabled:     false,
		BaseURL:     "https://api.openai.com/v1",
		APIKey:      "",
		Model:       "gpt-4o-mini",
		IntervalMin: 30,
		Prompt:      "",
		WebhookURL:  "",
	}
}

func loadWebSettings(path string) *WebSettings {
	ws := &WebSettings{Security: defaultSecuritySettings(), AI: defaultAISettings()}
	if path == "" {
		return ws
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ws
	}
	_ = json.Unmarshal(data, ws)
	return ws
}

func (ws *WebServer) saveSettings(sec SecuritySettings, ai AISettings, pwdHash, pwdSalt string) error {
	if ws.settingsFile == "" {
		return nil
	}
	data, err := json.MarshalIndent(WebSettings{Security: sec, AI: ai, AdminPasswordHash: pwdHash, AdminPasswordSalt: pwdSalt}, "", "  ")
	if err != nil {
		return err
	}
	tmp := ws.settingsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, ws.settingsFile)
}

func (ws *WebServer) getSessionTimeout() time.Duration {
	ws.secMu.RLock()
	defer ws.secMu.RUnlock()
	m := ws.security.SessionTimeoutMin
	if m <= 0 {
		m = 30
	}
	return time.Duration(m) * time.Minute
}

func (ws *WebServer) getSessionTimeoutSec() int {
	ws.secMu.RLock()
	defer ws.secMu.RUnlock()
	m := ws.security.SessionTimeoutMin
	if m <= 0 {
		m = 30
	}
	return m * 60
}

func (ws *WebServer) getRateLimitMax() int {
	ws.secMu.RLock()
	defer ws.secMu.RUnlock()
	m := ws.security.RateLimitMax
	if m <= 0 {
		m = 5
	}
	return m
}

func (ws *WebServer) getRateLimitLockMin() int {
	ws.secMu.RLock()
	defer ws.secMu.RUnlock()
	m := ws.security.RateLimitLockMin
	if m <= 0 {
		m = 15
	}
	return m
}

func (ws *WebServer) sameSite() http.SameSite {
	ws.secMu.RLock()
	defer ws.secMu.RUnlock()
	if ws.security.SameSiteCookie {
		return http.SameSiteStrictMode
	}
	return http.SameSiteDefaultMode
}

func (ws *WebServer) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		ws.secMu.RLock()
		ai := ws.ai
		ws.secMu.RUnlock()
		masked := ai
		if masked.APIKey != "" {
			if len(masked.APIKey) > 4 {
				masked.APIKey = "****" + masked.APIKey[len(masked.APIKey)-4:]
			} else {
				masked.APIKey = "****"
			}
		}
		json.NewEncoder(w).Encode(masked)
		return
	}
	if r.Method == http.MethodPost {
		var req AISettings
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if req.IntervalMin < 5 {
			req.IntervalMin = 5
		}
		if req.IntervalMin > 1440 {
			req.IntervalMin = 1440
		}
		ws.secMu.Lock()
		if req.APIKey == "" || strings.HasPrefix(req.APIKey, "****") {
			req.APIKey = ws.ai.APIKey
		}
		wasEnabled := ws.ai.Enabled
		ws.ai = req
		sec := ws.security
		ai := ws.ai
		ws.secMu.Unlock()
		if err := ws.saveSettings(sec, ai, ws.passwordHash, ws.passwordSalt); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "保存失败: " + err.Error()})
			return
		}
		ws.AddLog("info", "AI 巡查配置已更新")
		if ai.Enabled {
			ws.stopAIPatrolScheduler()
			ws.startAIPatrolScheduler()
		} else if wasEnabled {
			ws.stopAIPatrolScheduler()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "不支持的方法"})
}

func (ws *WebServer) handleAIPatrol(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		ws.patrolMu.RLock()
		list := make([]PatrolResult, len(ws.patrols))
		copy(list, ws.patrols)
		ws.patrolMu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"patrols": list,
			"total":   len(list),
		})
		return
	}
	if r.Method == http.MethodPost {
		if !ws.doAIPatrol() {
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "AI 巡查未启用或未配置"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false})
}

func normalizeChatURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	if strings.Contains(base, "/chat/completions") {
		return base
	}
	return base + "/chat/completions"
}

func parsePatrolContent(content string) (string, string, string) {
	c := strings.TrimSpace(content)
	if strings.HasPrefix(c, "```") {
		if i := strings.Index(c, "\n"); i >= 0 {
			c = c[i+1:]
		}
		if strings.HasSuffix(c, "```") {
			c = c[:len(c)-3]
		}
		c = strings.TrimSpace(c)
	}
	var obj struct {
		Level   string `json:"level"`
		Summary string `json:"summary"`
		Details string `json:"details"`
	}
	if err := json.Unmarshal([]byte(c), &obj); err == nil && obj.Summary != "" {
		level := obj.Level
		if level == "" {
			level = "ok"
		}
		return level, obj.Summary, obj.Details
	}
	return "info", strings.TrimSpace(content), ""
}

func (ws *WebServer) doAIPatrol() bool {
	if !atomic.CompareAndSwapInt32(&ws.patrolRunning, 0, 1) {
		return true
	}
	defer atomic.StoreInt32(&ws.patrolRunning, 0)

	ws.secMu.RLock()
	ai := ws.ai
	ws.secMu.RUnlock()
	if !ai.Enabled || ai.APIKey == "" || ai.BaseURL == "" || ai.Model == "" {
		return false
	}

	ws.logsMu.RLock()
	logs := make([]LogEntry, len(ws.logs))
	copy(logs, ws.logs)
	ws.logsMu.RUnlock()
	if len(logs) > 50 {
		logs = logs[len(logs)-50:]
	}
	var sb strings.Builder
	for _, l := range logs {
		sb.WriteString(fmt.Sprintf("[%s][%s] %s\n", l.Time, l.Level, l.Message))
	}
	logText := sb.String()
	st := ws.proxyManager.GetStatus()

	systemPrompt := "你是内网穿透服务 NexusLink 的安全巡查助手。请根据提供的运行日志与状态判断是否存在异常、攻击迹象或安全隐患。用简体中文回复，且只输出一个 JSON 对象：{\"level\":\"ok|warn|danger\",\"summary\":\"一句话结论\",\"details\":\"详细分析与建议\"}。不要输出 JSON 以外的任何内容。"
	var userPrompt string
	if ai.Prompt != "" {
		userPrompt = fmt.Sprintf("%s\n\n【当前状态】版本:%s 客户端数:%d 代理数:%d 监听:%s:%d\n【最近日志】\n%s",
			ai.Prompt, st.Version, st.ClientCount, st.ProxyCount, st.BindAddr, st.BindPort, logText)
	} else {
		userPrompt = fmt.Sprintf("以下是 NexusLink 服务端最近的运行日志和当前状态，请巡查分析：\n\n【当前状态】\n版本:%s 运行:%v 客户端数:%d 代理数:%d 监听:%s:%d\n\n【最近日志】\n%s",
			st.Version, st.Running, st.ClientCount, st.ProxyCount, st.BindAddr, st.BindPort, logText)
	}

	url := normalizeChatURL(ai.BaseURL)
	body := map[string]interface{}{
		"model": ai.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": 0.2,
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		ws.recordPatrol("error", "AI 请求构建失败", err.Error())
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ai.APIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		ws.recordPatrol("error", "AI 接口调用失败", err.Error())
		return true
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		ws.recordPatrol("error", "AI 接口返回错误", fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(rb)))
		return true
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || len(out.Choices) == 0 {
		ws.recordPatrol("warn", "AI 响应解析失败", string(rb))
		return true
	}
	level, summary, details := parsePatrolContent(out.Choices[0].Message.Content)
	ws.recordPatrol(level, summary, details)
	ws.notifyPatrol(ai, level, summary, details)
	return true
}

func (ws *WebServer) recordPatrol(level, summary, details string) {
	if level == "" {
		level = "info"
	}
	r := PatrolResult{
		Time:    time.Now().Format("2006-01-02 15:04:05"),
		Level:   level,
		Summary: summary,
		Details: details,
	}
	ws.patrolMu.Lock()
	ws.patrols = append(ws.patrols, r)
	if len(ws.patrols) > 100 {
		ws.patrols = ws.patrols[len(ws.patrols)-100:]
	}
	ws.patrolMu.Unlock()
	ws.savePatrolHistory()
	ws.AddLog("info", "AI 巡查完成: "+summary)
}

func (ws *WebServer) startAIPatrolScheduler() {
	ws.secMu.RLock()
	enabled := ws.ai.Enabled
	interval := ws.ai.IntervalMin
	ws.secMu.RUnlock()
	if !enabled {
		return
	}
	if interval < 5 {
		interval = 5
	}
	ws.stopAIPatrolScheduler()
	ws.patrolQuit = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ws.patrolQuit:
				return
			case <-ticker.C:
				ws.doAIPatrol()
			}
		}
	}()
}

func (ws *WebServer) stopAIPatrolScheduler() {
	if ws.patrolQuit != nil {
		close(ws.patrolQuit)
		ws.patrolQuit = nil
	}
}


// 实时安全状态：活动会话数 + 被锁定的 IP
func (ws *WebServer) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ws.sessionMu.RLock()
	activeSessions := len(ws.sessions)
	ws.sessionMu.RUnlock()

	ws.loginMu.RLock()
	locked := make([]map[string]interface{}, 0)
	now := time.Now()
	for ip, a := range ws.failedLogins {
		if now.Before(a.lockUntil) {
			locked = append(locked, map[string]interface{}{
				"ip":        ip,
				"unlock_at": a.lockUntil.Format("2006-01-02 15:04:05"),
			})
		}
	}
	ws.loginMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_sessions": activeSessions,
		"locked_ips":      locked,
	})
}

// 手动解锁某个被锁定的 IP
func (ws *WebServer) handleSecurityUnlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	ws.loginMu.Lock()
	delete(ws.failedLogins, req.IP)
	ws.loginMu.Unlock()
	ws.AddLog("info", fmt.Sprintf("手动解锁 IP: %s", req.IP))
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// 安全事件流：从运行日志中筛选安全相关条目（倒序，最多 50 条）
func (ws *WebServer) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ws.logsMu.RLock()
	logs := make([]LogEntry, len(ws.logs))
	copy(logs, ws.logs)
	ws.logsMu.RUnlock()

	keywords := []string{"登录", "锁定", "安全", "巡查", "登出", "密码", "IP", "失败", "CSRF", "会话", "解锁", "告警"}
	out := make([]LogEntry, 0)
	for i := len(logs) - 1; i >= 0; i-- {
		l := logs[i]
		hit := false
		for _, k := range keywords {
			if strings.Contains(l.Message, k) {
				hit = true
				break
			}
		}
		if hit {
			out = append(out, l)
		}
		if len(out) >= 50 {
			break
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"events": out, "total": len(out)})
}


// notifyPatrol 风险告警：巡查结果为 warn/danger 且配置了 Webhook 时异步发送通知
func (ws *WebServer) notifyPatrol(ai AISettings, level, summary, details string) {
	if ai.WebhookURL == "" {
		return
	}
	if level != "warn" && level != "danger" {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"time":    time.Now().Format("2006-01-02 15:04:05"),
		"level":   level,
		"summary": summary,
		"details": details,
	})
	go func() {
		req, err := http.NewRequest(http.MethodPost, ai.WebhookURL, bytes.NewReader(payload))
		if err != nil {
			ws.AddLog("warn", "告警 Webhook 请求构建失败: "+err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			ws.AddLog("warn", "告警 Webhook 调用失败: "+err.Error())
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		ws.AddLog("info", fmt.Sprintf("风险告警已发送至 Webhook (HTTP %d)", resp.StatusCode))
	}()
}


// 修改管理密码（校验当前密码，成功后清除全部会话强制重新登录）
func (ws *WebServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	hash := hashPasswordWithSalt(req.CurrentPassword, ws.passwordSalt)
	if subtle.ConstantTimeCompare([]byte(hash), []byte(ws.passwordHash)) != 1 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "当前密码错误"})
		return
	}
	if len(req.NewPassword) < 6 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "新密码至少需要 6 位"})
		return
	}
	if req.NewPassword == req.CurrentPassword {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "新密码不能与当前密码相同"})
		return
	}
	newSalt := generateSalt()
	newHash := hashPasswordWithSalt(req.NewPassword, newSalt)
	ws.passwordSalt = newSalt
	ws.passwordHash = newHash

	ws.secMu.RLock()
	sec := ws.security
	ai := ws.ai
	ws.secMu.RUnlock()
	if err := ws.saveSettings(sec, ai, newHash, newSalt); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "保存失败: " + err.Error()})
		return
	}
	// 清除所有会话（强制重新登录）
	ws.sessionMu.Lock()
	ws.sessions = make(map[string]sessionInfo)
	ws.sessionMu.Unlock()
	ws.AddLog("warn", "管理密码已修改，所有会话已失效")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}


// 加载巡查历史（重启后保留）
func loadPatrolHistory(path string) []PatrolResult {
	if path == "" {
		return make([]PatrolResult, 0)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return make([]PatrolResult, 0)
	}
	var list []PatrolResult
	if err := json.Unmarshal(data, &list); err != nil {
		return make([]PatrolResult, 0)
	}
	if list == nil {
		list = make([]PatrolResult, 0)
	}
	return list
}

// 保存巡查历史（原子写盘，上限 100 条与内存一致）
func (ws *WebServer) savePatrolHistory() {
	if ws.patrolFile == "" {
		return
	}
	ws.patrolMu.RLock()
	list := make([]PatrolResult, len(ws.patrols))
	copy(list, ws.patrols)
	ws.patrolMu.RUnlock()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := ws.patrolFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, ws.patrolFile)
}
