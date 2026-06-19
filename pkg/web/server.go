package web

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

// WebServer Web管理面板服务
type WebServer struct {
	server       *http.Server
	adminPassword string
	tokens       map[string]time.Time
	tokenMu      sync.RWMutex
	logs         []LogEntry
	logsMu       sync.RWMutex
	proxyManager ProxyManager
	config       *WebConfig
}

// WebConfig Web面板配置
type WebConfig struct {
	Addr         string
	Port         int
	AdminPassword string
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
	Running     bool   `json:"running"`
	BindAddr    string `json:"bindAddr"`
	BindPort    int    `json:"bindPort"`
	ClientCount int    `json:"clientCount"`
	ProxyCount  int    `json:"proxyCount"`
	Proxies     []ProxyInfo `json:"proxies"`
}

// LogEntry 日志条目
type LogEntry struct {
	Time string `json:"time"`
	Msg  string `json:"msg"`
}

// NewWebServer 创建Web服务器
func NewWebServer(cfg *WebConfig, proxyManager ProxyManager) *WebServer {
	ws := &WebServer{
		adminPassword: hashPassword(cfg.AdminPassword),
		tokens:        make(map[string]time.Time),
		logs:          make([]LogEntry, 0),
		proxyManager:  proxyManager,
		config:        cfg,
	}

	// 启动token清理
	go ws.cleanupTokens()

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
	mux.HandleFunc("/api/status", ws.authMiddleware(ws.handleStatus))
	mux.HandleFunc("/api/proxies", ws.authMiddleware(ws.handleProxies))
	mux.HandleFunc("/api/config", ws.authMiddleware(ws.handleConfig))
	mux.HandleFunc("/api/logs", ws.authMiddleware(ws.handleLogs))

	addr := ws.config.Addr
	if addr == "" {
		addr = "0.0.0.0"
	}
	addr = addr + ":" + itoa(ws.config.Port)

	ws.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("[Web] 管理面板启动于 http://%s", addr)
	go func() {
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Web] 服务器错误: %v", err)
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
func (ws *WebServer) AddLog(msg string) {
	ws.logsMu.Lock()
	defer ws.logsMu.Unlock()

	entry := LogEntry{
		Time: time.Now().Format("2006-01-02 15:04:05"),
		Msg:  msg,
	}
	ws.logs = append(ws.logs, entry)

	// 最多保留1000条
	if len(ws.logs) > 1000 {
		ws.logs = ws.logs[len(ws.logs)-1000:]
	}
}

// 登录处理
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if hashPassword(req.Password) != ws.adminPassword {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "密码错误"})
		return
	}

	// 生成token
	token := generateToken()
	ws.tokenMu.Lock()
	ws.tokens[token] = time.Now().Add(24 * time.Hour)
	ws.tokenMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
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
	case http.MethodPost:
		// 添加代理（需要服务端支持动态添加）
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "服务端暂不支持动态添加代理，请修改配置文件后重启",
		})
	case http.MethodDelete:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "服务端暂不支持动态删除代理，请修改配置文件后重启",
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 配置处理
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"bindAddr": ws.config.Addr,
			"bindPort": ws.config.Port,
			"webPort":  ws.config.Port,
		})
	} else if r.Method == http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "暂不支持在线修改配置，请修改配置文件后重启",
		})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

		// 返回最近100条
		if len(logs) > 100 {
			logs = logs[len(logs)-100:]
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs": logs,
		})
	} else if r.Method == http.MethodDelete {
		ws.logsMu.Lock()
		ws.logs = make([]LogEntry, 0)
		ws.logsMu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 认证中间件
func (ws *WebServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ws.tokenMu.RLock()
		expireTime, exists := ws.tokens[token]
		ws.tokenMu.RUnlock()

		if !exists || time.Now().After(expireTime) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 刷新token过期时间
		ws.tokenMu.Lock()
		ws.tokens[token] = time.Now().Add(24 * time.Hour)
		ws.tokenMu.Unlock()

		// 安全头部
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next(w, r)
	}
}

// 清理过期token
func (ws *WebServer) cleanupTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ws.tokenMu.Lock()
		now := time.Now()
		for token, expire := range ws.tokens {
			if now.After(expire) {
				delete(ws.tokens, token)
			}
		}
		ws.tokenMu.Unlock()
	}
}

// 工具函数
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

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
