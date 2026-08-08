// Package web AI 智能巡查模块（从 server.go 拆分）
package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

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

type PatrolResult struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Summary string `json:"summary"`
	Details string `json:"details"`
}

// ProxyManager 代理管理器接口

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
