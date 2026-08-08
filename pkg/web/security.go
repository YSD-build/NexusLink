// Package web 安全设置与安全中心模块（从 server.go 拆分）
package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

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
type WebSettings struct {
	Security          SecuritySettings `json:"security"`
	AI                AISettings       `json:"ai"`
	AdminPasswordHash string           `json:"admin_password_hash,omitempty"`
	AdminPasswordSalt string           `json:"admin_password_salt,omitempty"`
}

// PatrolResult AI 巡查结果

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

func defaultSecuritySettings() SecuritySettings {
	return SecuritySettings{
		SessionTimeoutMin: 30,
		RateLimitMax:      5,
		RateLimitLockMin:  15,
		CSRFProtection:    true,
		SecurityHeaders:   true,
		HttpOnlyCookie:    true,
		SameSiteCookie:    true,
		CustomCSP:         "",
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
