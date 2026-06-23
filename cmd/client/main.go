// NexusLink Client - 带数据包认证的内网穿透客户端
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"nexuslink/pkg/auth"
	"nexuslink/pkg/config"
	"nexuslink/pkg/protocol"
)

var Version = "dev"

var (
	configFile = flag.String("c", "client.yaml", "config file path")
	tunnelID   = flag.String("id", "", "tunnel ID (start only specified tunnel)")
	apiAddr    = flag.String("api", "", "API server address (for fetching config by ID)")
	apiToken   = flag.String("token", "", "API auth token (JWT)")
)

// Proxy 代理配置
type Proxy struct {
	Name       string
	Type       protocol.ProxyType
	LocalAddr  string
	LocalPort  int
	RemotePort int
}

// Client 客户端
type Client struct {
	cfg     *config.ClientConfig
	auth    *auth.Auth
	proxies map[string]*Proxy
	conn    net.Conn
	mu      sync.RWMutex
}

func main() {
	flag.Parse()

	var cfg *config.ClientConfig
	var err error

	// 方式一：通过 API + ID 获取配置
	if *apiAddr != "" && *tunnelID != "" {
		log.Printf("Fetching config from API: %s, tunnel ID: %s", *apiAddr, *tunnelID)
		cfg, err = fetchConfigFromAPI(*apiAddr, *tunnelID, *apiToken)
		if err != nil {
			log.Fatalf("Fetch config from API failed: %v", err)
		}
		log.Println("Config fetched from API successfully")
	} else {
		// 方式二：从配置文件加载
		cfg, err = config.LoadClientConfig(*configFile)
		if err != nil {
			log.Fatalf("Load config failed: %v", err)
		}

		// 如果指定了 -id，只保留对应 ID 的隧道
		if *tunnelID != "" {
			filtered := make(map[string]config.ProxyConfig)
			// 支持两种格式：直接用 ID 作为 key，或者 tunnel_{ID} 作为 key
			for name, proxy := range cfg.Proxies {
				if name == *tunnelID || name == "tunnel_"+*tunnelID {
					filtered[name] = proxy
					log.Printf("Selected tunnel: %s", name)
				}
			}
			if len(filtered) == 0 {
				log.Fatalf("Tunnel ID %s not found in config", *tunnelID)
			}
			cfg.Proxies = filtered
		}
	}

	client := &Client{
		cfg:     cfg,
		auth:    auth.NewAuth(cfg.Token),
		proxies: make(map[string]*Proxy),
	}

	log.Printf("NexusLink Client v%s starting...", Version)
	log.Printf("Connecting to server %s:%d", cfg.ServerIP, cfg.ServerPort)
	log.Printf("Proxies to start: %d", len(cfg.Proxies))

	for {
		err := client.connect()
		if err != nil {
			log.Printf("Connection failed: %v, reconnecting in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		client.handleMessages()

		log.Printf("Disconnected, reconnecting in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// fetchConfigFromAPI 从 API 获取隧道配置
func fetchConfigFromAPI(apiAddr, tunnelID, token string) (*config.ClientConfig, error) {
	// 确保 API 地址格式正确
	if !strings.HasPrefix(apiAddr, "http") {
		apiAddr = "https://" + apiAddr
	}
	apiAddr = strings.TrimRight(apiAddr, "/")

	url := fmt.Sprintf("%s/tunnel.php?action=config&id=%s", apiAddr, tunnelID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// 解析 API 响应
	var apiResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Config string `json:"config"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parse API response: %w", err)
	}

	if apiResp.Code != 0 {
		return nil, fmt.Errorf("API error: %s", apiResp.Msg)
	}

	// 解析配置文件内容（yaml 格式）
	var cfg config.ClientConfig
	if err := yaml.Unmarshal([]byte(apiResp.Data.Config), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 设置默认值
	if cfg.ServerIP == "" {
		cfg.ServerIP = "127.0.0.1"
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 7000
	}

	return &cfg, nil
}

// connect 连接到服务端
func (c *Client) connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", c.cfg.ServerIP, c.cfg.ServerPort))
	if err != nil {
		return err
	}

	// 发送登录消息
	err = protocol.WriteMessage(conn, protocol.TypeLogin, protocol.Login{
		Token: c.cfg.Token,
	})
	if err != nil {
		conn.Close()
		return err
	}

	// 读取登录响应
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		conn.Close()
		return err
	}

	if msg.Type != protocol.TypeLoginResp {
		conn.Close()
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	resp, err := protocol.ParseMessage[protocol.LoginResp](msg)
	if err != nil {
		conn.Close()
		return err
	}

	if !resp.Success {
		conn.Close()
		return fmt.Errorf("login failed: %s", resp.Error)
	}

	conn.SetReadDeadline(time.Time{})
	c.conn = conn
	log.Println("Connected to server successfully")

	// 注册所有代理
	for name, proxy := range c.cfg.Proxies {
		c.registerProxy(name, proxy)
	}

	// 启动心跳
	go c.heartbeat()

	return nil
}

// registerProxy 注册代理
func (c *Client) registerProxy(name string, proxy config.ProxyConfig) {
	log.Printf("Registering proxy [%s] type=%s local=%s:%d remote=%d",
		name, proxy.Type, proxy.LocalAddr, proxy.LocalPort, proxy.Port)

	err := protocol.WriteMessage(c.conn, protocol.TypeNewProxy, protocol.NewProxy{
		Name:       name,
		Type:       protocol.ProxyType(proxy.Type),
		RemotePort: proxy.Port,
	})
	if err != nil {
		log.Printf("Register proxy [%s] failed: %v", name, err)
		return
	}

	c.proxies[name] = &Proxy{
		Name:       name,
		Type:       protocol.ProxyType(proxy.Type),
		LocalAddr:  proxy.LocalAddr,
		LocalPort:  proxy.LocalPort,
		RemotePort: proxy.Port,
	}
}

// heartbeat 心跳
func (c *Client) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		protocol.WriteMessage(conn, protocol.TypeHeartbeat, struct{}{})
	}
}

// handleMessages 处理服务端消息
func (c *Client) handleMessages() {
	for {
		msg, err := protocol.ReadMessage(c.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read message error: %v", err)
			}
			break
		}

		switch msg.Type {
		case protocol.TypeNewConn:
			c.handleNewConn(msg)
		case protocol.TypeHeartbeatResp:
			// ignore
		}
	}
}

// handleNewConn 处理新连接
func (c *Client) handleNewConn(msg *protocol.Message) {
	newConn, err := protocol.ParseMessage[protocol.NewConn](msg)
	if err != nil {
		log.Printf("Parse new conn failed: %v", err)
		return
	}

	proxy, exists := c.proxies[newConn.ProxyName]
	if !exists {
		log.Printf("Proxy [%s] not found", newConn.ProxyName)
		return
	}

	log.Printf("New connection on proxy [%s], conn_id=%s", newConn.ProxyName, newConn.ConnID)

	// 连接到本地服务
	localConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", proxy.LocalAddr, proxy.LocalPort))
	if err != nil {
		log.Printf("Connect to local service failed: %v", err)
		return
	}

	// 带认证双向转发
	go c.forwardWithAuth(localConn, c.conn, newConn.ConnID)
}

// forwardWithAuth 带认证的数据转发
func (c *Client) forwardWithAuth(localConn, serverConn net.Conn, connID string) {
	defer localConn.Close()

	errChan := make(chan error, 2)
	bufSize := 32 * 1024

	// server -> local (验证)
	go func() {
		buf := make([]byte, bufSize+auth.HeaderSize)
		for {
			n, err := serverConn.Read(buf)
			if n > 0 {
				data, ok := c.auth.Verify(buf[:n])
				if !ok {
					errChan <- fmt.Errorf("invalid signature")
					return
				}
				_, writeErr := localConn.Write(data)
				if writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// local -> server (签名)
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				signed := c.auth.Sign(buf[:n])
				_, writeErr := serverConn.Write(signed)
				if writeErr != nil {
					errChan <- writeErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	<-errChan
	log.Printf("Connection %s closed", connID)
}
