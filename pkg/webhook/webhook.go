// Package webhook 提供轻量 Webhook 事件推送（POST JSON 到第三方平台）。
// 异步发送，失败仅记日志，不阻塞主流程。
package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Event Webhook 事件
type Event struct {
	Event   string         `json:"event"`   // 事件类型：client_connected / proxy_created / traffic_limit ...
	Time    string         `json:"time"`    // 事件时间（RFC3339）
	Payload map[string]any `json:"payload"` // 事件数据
}

// Send 异步推送事件到指定 URL（URL 为空时静默跳过）
func Send(url, event string, payload map[string]any) {
	if url == "" {
		return
	}
	go func() {
		body, err := json.Marshal(Event{
			Event:   event,
			Time:    time.Now().Format(time.RFC3339),
			Payload: payload,
		})
		if err != nil {
			log.Printf("[webhook] marshal event %s failed: %v", event, err)
			return
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("[webhook] push %s failed: %v", event, err)
			return
		}
		resp.Body.Close()
		log.Printf("[webhook] pushed event %s -> %s (%d)", event, url, resp.StatusCode)
	}()
}
