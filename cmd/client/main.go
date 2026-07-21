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
	"sync/atomic"
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
	apiKey     = flag.String("api-key", "", "API key for authentication")
	reportAddr = flag.String("report", "", "traffic report server address (default same as api)")
	reportInterval = flag.Int("report-interval", 30, "traffic report interval in seconds")
)

// udpSession client 侧 UDP session：映射到本地后端连接（connected UDP socket）。
type udpSession struct {
	id         string
	conn       *net.UDPConn
	lastActive time.Time
}

// Proxy 代理配置（含运行态）
type Proxy struct {
	Name       string
	Type       protocol.ProxyType
	LocalAddr  string
	LocalPort  int
	RemotePort int
	BytesIn    int64
	BytesOut   int64

	// UDP 独立数据通道相关（与控制通道解耦）
	udpDataConn *net.UDPConn           // 到服务端的独立 UDP 数据通道
	udpServer   *net.UDPAddr           // 服务端数据通道地址
	udpSessions map[string]*udpSession // sessionID -> 本地后端连接
	udpMu       sync.Mutex
	udpQuit     chan struct{}
}

// Client 客户端
type Client struct {
	cfg        *config.ClientConfig
	auth       *auth.Auth
	proxies    map[string]*Proxy
	conn       net.Conn
	mu         sync.RWMutex
	apiAddr    string
	apiKey     string
	tunnelID   string
	reportAddr string
}

func main() {
	flag.Parse()

	var cfg *config.ClientConfig
	var err error

	// 方式一：通过 API + ID 获取配置
	if *apiAddr != "" && *tunnelID != "" {
		log.Printf("Fetching config from API: %s, tunnel ID: %s", *apiAddr, *tunnelID)
		cfg, err = fetchConfigFromAPI(*apiAddr, *tunnelID, *apiToken, *apiKey)
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
		cfg:        cfg,
		auth:       auth.NewAuth(cfg.Token),
		proxies:    make(map[string]*Proxy),
		apiAddr:    *apiAddr,
		apiKey:     *apiKey,
		tunnelID:   *tunnelID,
		reportAddr: *reportAddr,
	}

	log.Printf("NexusLink Client %s starting...", Version)
	log.Printf("Connecting to server %s:%d", cfg.ServerIP, cfg.ServerPort)
	log.Printf("Proxies to start: %d", len(cfg.Proxies))

	// 启动流量上报
	if *apiKey != "" {
		if *reportAddr == "" {
			client.reportAddr = *apiAddr
		}
		go client.startTrafficReporter()
		log.Printf("Traffic reporter started, interval: %ds", *reportInterval)
	}

	for {
		err := client.connect()
		if err != nil {
			log.Printf("Connection failed: %v, reconnecting in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		client.handleMessages()

		client.shutdownProxies()

		log.Printf("Disconnected, reconnecting in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// fetchConfigFromAPI 从 API 获取隧道配置
func fetchConfigFromAPI(apiAddr, tunnelID, token, apiKey string) (*config.ClientConfig, error) {
	// 确保 API 地址格式正确
	if !strings.HasPrefix(apiAddr, "http") {
		apiAddr = "https://" + apiAddr
	}
	apiAddr = strings.TrimRight(apiAddr, "/")

	var url string
	if apiKey != "" {
		// 使用 API 密钥认证
		url = fmt.Sprintf("%s/api/tunnel.php?action=api_config&id=%s", apiAddr, tunnelID)
	} else {
		// 使用 JWT token 认证
		url = fmt.Sprintf("%s/api/tunnel.php?action=config&id=%s", apiAddr, tunnelID)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
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

	p := &Proxy{
		Name:       name,
		Type:       protocol.ProxyType(proxy.Type),
		LocalAddr:  proxy.LocalAddr,
		LocalPort:  proxy.LocalPort,
		RemotePort: proxy.Port,
	}

	err := protocol.WriteMessage(c.conn, protocol.TypeNewProxy, protocol.NewProxy{
		Name:       name,
		Type:       protocol.ProxyType(proxy.Type),
		RemotePort: proxy.Port,
	})
	if err != nil {
		log.Printf("Register proxy [%s] failed: %v", name, err)
		return
	}

	// 读取服务端响应（含 UDP 独立数据通道端口）。此时 handleMessages 尚未启动，独占到 c.conn 的读取。
	conn := c.conn
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respMsg, err := protocol.ReadMessage(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("Register proxy [%s] resp failed: %v", name, err)
		return
	}
	resp, err := protocol.ParseMessage[protocol.NewProxyResp](respMsg)
	if err != nil {
		log.Printf("Register proxy [%s] resp parse failed: %v", name, err)
		return
	}
	if !resp.Success {
		log.Printf("Register proxy [%s] rejected: %s", name, resp.Error)
		return
	}

	c.proxies[name] = p

	// UDP 代理：建立独立数据通道并启动收发
	if p.Type == protocol.ProxyUDP {
		if resp.UDPDataPort == 0 {
			log.Printf("Register proxy [%s]: server didn't return UDP data port", name)
			return
		}
		if err := c.startUDPDataChannel(p, resp.UDPDataPort); err != nil {
			log.Printf("Start UDP data channel for [%s] failed: %v", name, err)
			return
		}
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

// handleNewConn 处理新连接（仅 TCP；UDP 由 client 主动建立数据通道，不在此处理）
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

	// 仅 TCP 走 TypeNewConn 通知；UDP 由 client 主动建立数据通道，不会收到此消息
	if proxy.Type != protocol.ProxyTCP {
		return
	}

	log.Printf("New connection on proxy [%s], conn_id=%s data_port=%d", newConn.ProxyName, newConn.ConnID, newConn.DataPort)

	// 连接到本地服务
	localConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", proxy.LocalAddr, proxy.LocalPort))
	if err != nil {
		log.Printf("Connect to local service failed: %v", err)
		return
	}

	// 连接服务端独立 TCP 数据通道（随机端口），发送首帧标识
	dataConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", c.cfg.ServerIP, newConn.DataPort))
	if err != nil {
		log.Printf("Connect to data port failed: %v", err)
		localConn.Close()
		return
	}
	if err := protocol.WriteMessage(dataConn, protocol.TypeDataConn, protocol.DataConnIdentify{ConnID: newConn.ConnID}); err != nil {
		log.Printf("Send data conn identify failed: %v", err)
		dataConn.Close()
		localConn.Close()
		return
	}

	// 在独立数据通道上做 HMAC 签名转发
	go c.forwardWithAuth(localConn, dataConn, newConn.ConnID, proxy)
}

// forwardWithAuth 带认证的数据转发
func (c *Client) forwardWithAuth(localConn, serverConn net.Conn, connID string, proxy *Proxy) {
	defer localConn.Close()
	defer serverConn.Close() // 数据通道连接关闭，触发对端 EOF -> 关闭用户连接

	errChan := make(chan error, 2)
	bufSize := 32 * 1024

	// server -> local (验证) - 入站流量
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
				// 统计入站流量
				atomic.AddInt64(&proxy.BytesIn, int64(len(data)))
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

	// local -> server (签名) - 出站流量
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				// 统计出站流量
				atomic.AddInt64(&proxy.BytesOut, int64(n))
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

// startUDPDataChannel 为 UDP 代理建立到服务端的独立 UDP 数据通道，并发送 hello 握手。
func (c *Client) startUDPDataChannel(p *Proxy, dataPort int) error {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.cfg.ServerIP, dataPort))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	p.udpDataConn = conn
	p.udpServer = serverAddr
	p.udpSessions = make(map[string]*udpSession)
	p.udpQuit = make(chan struct{})

	// 发送 hello，让服务端登记本 client 的数据通道地址（首包）
	hello := c.auth.Sign(protocol.MarshalEnvelope(protocol.UDPEnvelope{Kind: 0x00}))
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return err
	}

	go c.handleUDPDataChannel(p)
	log.Printf("UDP data channel for [%s] ready (data_port=%d)", p.Name, dataPort)
	return nil
}

// handleUDPDataChannel 处理服务端经独立 UDP 数据通道发来的数据（签名验证 + 后端转发）。
func (c *Client) handleUDPDataChannel(p *Proxy) {
	buf := make([]byte, 65535)
	for {
		n, _, err := p.udpDataConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.udpQuit:
				return
			default:
			}
			break
		}

		data, ok := c.auth.Verify(buf[:n])
		if !ok {
			continue // 签名无效：忽略
		}
		env, ok := protocol.UnmarshalEnvelope(data)
		if !ok {
			continue
		}

		switch env.Kind {
		case 0x01: // reg：确保后端连接已建（无负载）
			c.getOrCreateBackend(p, env.SessionID)
		case 0x02: // data：转发到本地后端
			if len(env.Data) == 0 {
				continue
			}
			backend := c.getOrCreateBackend(p, env.SessionID)
			if backend != nil {
				_, _ = backend.Write(env.Data)
			}
		case 0x03: // 关闭 session
			c.closeBackendSession(p, env.SessionID)
		default:
		}
	}
}

// getOrCreateBackend 为 UDP session 建立/复用本地后端连接（connected UDP socket）。
func (c *Client) getOrCreateBackend(p *Proxy, sid string) *net.UDPConn {
	p.udpMu.Lock()
	defer p.udpMu.Unlock()

	if s, ok := p.udpSessions[sid]; ok {
		s.lastActive = time.Now()
		return s.conn
	}
	backendAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", p.LocalAddr, p.LocalPort))
	if err != nil {
		log.Printf("[%s] resolve backend failed: %v", p.Name, err)
		return nil
	}
	conn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Printf("[%s] dial backend failed: %v", p.Name, err)
		return nil
	}
	p.udpSessions[sid] = &udpSession{id: sid, conn: conn, lastActive: time.Now()}
	go c.readBackend(p, sid, conn)
	return conn
}

// readBackend 读取本地后端回包，经数据通道发回服务端（带 sessionID + HMAC 签名）。
func (c *Client) readBackend(p *Proxy, sid string, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		env := protocol.UDPEnvelope{Kind: 0x02, SessionID: sid, Data: payload}
		signed := c.auth.Sign(protocol.MarshalEnvelope(env))
		if len(signed) > 65507 {
			continue
		}
		_, _ = p.udpDataConn.Write(signed)
	}
	// 后端关闭：清理 session 并通知服务端
	c.closeBackendSession(p, sid)
	bye := c.auth.Sign(protocol.MarshalEnvelope(protocol.UDPEnvelope{Kind: 0x03, SessionID: sid}))
	_, _ = p.udpDataConn.Write(bye)
}

// closeBackendSession 关闭指定 UDP session 的本地后端连接。
func (c *Client) closeBackendSession(p *Proxy, sid string) {
	p.udpMu.Lock()
	defer p.udpMu.Unlock()
	if s, ok := p.udpSessions[sid]; ok {
		s.conn.Close()
		delete(p.udpSessions, sid)
	}
}

// shutdownProxies 连接断开时关闭所有 UDP 数据通道与后端连接。
func (c *Client) shutdownProxies() {
	c.mu.RLock()
	proxies := make([]*Proxy, 0, len(c.proxies))
	for _, p := range c.proxies {
		proxies = append(proxies, p)
	}
	c.mu.RUnlock()

	for _, p := range proxies {
		if p.Type != protocol.ProxyUDP || p.udpDataConn == nil {
			continue
		}
		close(p.udpQuit)
		p.udpMu.Lock()
		for _, s := range p.udpSessions {
			s.conn.Close()
		}
		p.udpSessions = make(map[string]*udpSession)
		p.udpMu.Unlock()
		p.udpDataConn.Close()
	}
}

// startTrafficReporter 启动流量上报定时器
func (c *Client) startTrafficReporter() {
	interval := time.Duration(*reportInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.reportTraffic()
	}
}

// reportTraffic 上报流量到服务器
func (c *Client) reportTraffic() {
	if c.reportAddr == "" || c.apiKey == "" {
		return
	}

	// 累加所有隧道的流量
	var totalBytesIn, totalBytesOut int64
	c.mu.RLock()
	for _, proxy := range c.proxies {
		totalBytesIn += atomic.LoadInt64(&proxy.BytesIn)
		totalBytesOut += atomic.LoadInt64(&proxy.BytesOut)
	}
	c.mu.RUnlock()

	if totalBytesIn == 0 && totalBytesOut == 0 {
		return
	}

	// 确保地址格式正确
	reportAddr := c.reportAddr
	if !strings.HasPrefix(reportAddr, "http") {
		reportAddr = "https://" + reportAddr
	}
	reportAddr = strings.TrimRight(reportAddr, "/")

	url := fmt.Sprintf("%s/api/tunnel.php?action=traffic_report", reportAddr)

	// 构造 POST 数据
	formData := fmt.Sprintf("tunnel_id=%s&bytes_in=%d&bytes_out=%d",
		c.tunnelID, totalBytesIn, totalBytesOut)

	req, err := http.NewRequest("POST", url, strings.NewReader(formData))
	if err != nil {
		log.Printf("Create traffic report request failed: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", c.apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Traffic report failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			TrafficText string `json:"traffic_text"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		log.Printf("Parse traffic report response failed: %v", err)
		return
	}

	if apiResp.Code != 0 {
		log.Printf("Traffic report error: %s", apiResp.Msg)
		return
	}

	log.Printf("Traffic reported: in=%d, out=%d, %s",
		totalBytesIn, totalBytesOut, apiResp.Data.TrafficText)

	// 重置已上报的流量计数（避免重复上报）
	c.mu.RLock()
	for _, proxy := range c.proxies {
		atomic.AddInt64(&proxy.BytesIn, -totalBytesIn)
		atomic.AddInt64(&proxy.BytesOut, -totalBytesOut)
	}
	c.mu.RUnlock()
}
