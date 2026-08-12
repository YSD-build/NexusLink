// Secure Tunnel Server - 带数据包认证的内网穿透服务端
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nexuslink/pkg/auth"
	"nexuslink/pkg/config"
	"nexuslink/pkg/protocol"
	"nexuslink/pkg/security"
	"nexuslink/pkg/web"
)

var Version = "v0.3.7"

var (
	configFile = flag.String("c", "server.yaml", "config file path")
	genToken   = flag.Bool("gen-token", false, "generate a random token")
)

// UDPSession UDP 会话（按 user 远端地址区分）
type UDPSession struct {
	userAddr   *net.UDPAddr
	lastActive time.Time
}

// Proxy 代理信息
type Proxy struct {
	Name       string
	Type       protocol.ProxyType
	RemotePort int
	Listener   net.Listener
	UDPConn    *net.UDPConn
	ClientConn net.Conn
	Active     bool
	Owner      string // 所属客户端 ID，断开时只清理本客户端代理（多客户端隔离）
	BytesIn    int64  // 入站字节（TCP，atomic）
	BytesOut   int64  // 出站字节（TCP，atomic）

	// TCP 独立数据通道（与控制通道解耦）
	DataListener net.Listener
	DataPort     int
	pending      map[string]chan net.Conn // connID -> 等待数据连接的 chan（由 s.mu 保护）

	// UDP 独立数据通道 + session 多路复用（与控制通道解耦）
	UDPDataConn  *net.UDPConn
	udpDataPort  int
	clientDataAddr *net.UDPAddr
	sessions     map[string]*UDPSession
	addrIndex    map[string]string
	sessionSeq   uint64
	sessionQuit  chan struct{}
	sessionMu    sync.RWMutex
	pendingOut   []protocol.UDPEnvelope // 待发往客户端的数据通道包（client 数据地址未知时缓存）
}

// Server 服务端
type Server struct {
	cfg       *config.ServerConfig
	auth      *auth.Auth
	proxies   map[string]*Proxy
	clients   map[string]net.Conn // 多客户端支持：clientID -> 控制连接
	webServer *web.WebServer
	connGuard *security.ConnGuard // 第一防：连接守卫
	tlsConf   *tls.Config       // 隧道 TLS（配置证书后非空）
	mu        sync.RWMutex
	startTime time.Time
}

// GetProxies 获取代理列表（实现ProxyManager接口）
func (s *Server) GetProxies() []web.ProxyInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	proxies := make([]web.ProxyInfo, 0, len(s.proxies))
	for name, p := range s.proxies {
		proxies = append(proxies, web.ProxyInfo{
			Name:       name,
			Type:       string(p.Type),
			RemotePort: p.RemotePort,
			Active:     p.Active,
			BytesIn:    atomic.LoadInt64(&p.BytesIn),
			BytesOut:   atomic.LoadInt64(&p.BytesOut),
		})
	}
	return proxies
}

// GetStatus 获取状态信息（实现ProxyManager接口）
func (s *Server) GetStatus() web.StatusInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	proxies := make([]web.ProxyInfo, 0, len(s.proxies))
	for name, p := range s.proxies {
		proxies = append(proxies, web.ProxyInfo{
			Name:       name,
			Type:       string(p.Type),
			RemotePort: p.RemotePort,
			Active:     p.Active,
			BytesIn:    atomic.LoadInt64(&p.BytesIn),
			BytesOut:   atomic.LoadInt64(&p.BytesOut),
		})
	}

	clientCount := 0
	s.mu.RLock()
	clientCount = len(s.clients)
	s.mu.RUnlock()

	uptime := time.Since(s.startTime)
	uptimeStr := fmt.Sprintf("%d天%d小时%d分",
		int(uptime.Hours())/24,
		int(uptime.Hours())%24,
		int(uptime.Minutes())%60,
	)

	return web.StatusInfo{
		Running:     true,
		BindAddr:    s.cfg.BindAddr,
		BindPort:    s.cfg.BindPort,
		ClientCount: clientCount,
		ProxyCount:  len(s.proxies),
		Proxies:     proxies,
		Version:     Version,
		Uptime:      uptimeStr,
		StartTime:   s.startTime.Format("2006-01-02 15:04:05"),
	}
}

// addLog 添加日志
func (s *Server) addLog(msg string) {
	if s.webServer != nil {
		s.webServer.AddLog("info", msg)
	}
	log.Println(msg)
}

// GetClients 获取在线客户端列表（实现 ProxyManager 接口）
func (s *Server) GetClients() []web.ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]web.ClientInfo, 0, len(s.clients))
	for id, conn := range s.clients {
		proxyCount := 0
		for _, p := range s.proxies {
			if p.Owner == id {
				proxyCount++
			}
		}
		clients = append(clients, web.ClientInfo{
			ID:          id,
			Addr:        conn.RemoteAddr().String(),
			ConnectedAt: clientConnectedAt(id),
			ProxyCount:  proxyCount,
		})
	}
	return clients
}

// KickClient 强制下线客户端：关闭控制连接，触发 handleControlMessages 退出并清理其代理
func (s *Server) KickClient(id string) error {
	s.mu.RLock()
	conn, ok := s.clients[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("客户端不存在或已离线")
	}
	conn.Close()
	s.addLogWarn(fmt.Sprintf("强制下线客户端 [%s]", id))
	return nil
}

// CloseProxy 下线指定隧道：关闭服务端监听资源并通知客户端停止该代理
func (s *Server) CloseProxy(name string) error {
	s.mu.Lock()
	proxy, ok := s.proxies[name]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("隧道 [%s] 不存在", name)
	}
	// 通知客户端关闭该代理（尽力而为，失败不影响服务端清理）
	if proxy.ClientConn != nil {
		_ = protocol.WriteMessage(proxy.ClientConn, protocol.TypeCloseProxy, protocol.CloseProxy{Name: name})
	}
	s.cleanupProxy(name, proxy)
	s.mu.Unlock()
	s.addLogWarn(fmt.Sprintf("Web 下线隧道 [%s]", name))
	return nil
}

// clientConnectedAt 从 clientID（格式 addr-unixnano）解析连接时间
func clientConnectedAt(id string) string {
	idx := strings.LastIndex(id, "-")
	if idx < 0 || idx == len(id)-1 {
		return ""
	}
	n, err := strconv.ParseInt(id[idx+1:], 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(0, n).Format("2006-01-02 15:04:05")
}

// addLogWarn 添加警告日志
func (s *Server) addLogWarn(msg string) {
	if s.webServer != nil {
		s.webServer.AddLog("warn", msg)
	}
	log.Println("[WARN]", msg)
}

// addLogError 添加错误日志
func (s *Server) addLogError(msg string) {
	if s.webServer != nil {
		s.webServer.AddLog("error", msg)
	}
	log.Println("[ERROR]", msg)
}

func main() {
	flag.Parse()

	if *genToken {
		fmt.Println("Generated token:", auth.GenerateToken())
		return
	}

	cfg, err := config.LoadServerConfig(*configFile)
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}

	server := &Server{
		cfg:       cfg,
		auth:      auth.NewAuth(cfg.Token),
		proxies:   make(map[string]*Proxy),
		clients:   make(map[string]net.Conn),
		connGuard: mustConnGuard(cfg.Whitelist), // 初始化连接守卫（带白名单）
		startTime: time.Now(),
	}

	log.Printf("NexusLink Server %s starting...", Version)
	log.Printf("Listening on %s:%d", cfg.BindAddr, cfg.BindPort)

	// 启动Web管理面板（默认启用）
	if cfg.WebEnable || cfg.WebPassword != "" {
		// 计算 web 设置持久化文件路径（与配置文件同目录）
		settingsFile := "web_settings.json"
		if *configFile != "" {
			if dir := filepath.Dir(*configFile); dir != "." && dir != "" {
				settingsFile = filepath.Join(dir, "web_settings.json")
			}
		}
		webCfg := &web.WebConfig{
			Addr:          cfg.WebAddr,
			Port:          cfg.WebPort,
			AdminPassword: cfg.WebPassword,
			SettingsFile:  settingsFile,
			CertFile:      cfg.WebTLSCert,
			KeyFile:       cfg.WebTLSKey,
		}
		server.webServer = web.NewWebServer(webCfg, server)
		if err := server.webServer.Start(); err != nil {
			log.Printf("Web panel start failed: %v", err)
		} else {
			log.Printf("Web admin panel: http://%s:%d", cfg.WebAddr, cfg.WebPort)
			log.Printf("Web admin password: %s", cfg.WebPassword)
		}
	}

	server.addLog(fmt.Sprintf("NexusLink Server %s 启动", Version))
	server.addLog(fmt.Sprintf("监听地址: %s:%d", cfg.BindAddr, cfg.BindPort))

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.BindPort))
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	// 隧道 TLS：配置 bind_tls_cert/key 后启用（控制通道 + TCP 数据通道）
	var tlsConf *tls.Config
	if cfg.BindTLSCert != "" && cfg.BindTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.BindTLSCert, cfg.BindTLSKey)
		if err != nil {
			log.Fatalf("Load TLS cert failed: %v", err)
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}
		ln = tls.NewListener(ln, tlsConf)
		log.Printf("Tunnel TLS enabled")
	}
	server.tlsConf = tlsConf

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go server.handleClient(conn)
	}
}

// handleClient 处理客户端连接
func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()

	// 第一防：连接层检查
	if !s.connGuard.Check(conn) {
		return
	}
	defer s.connGuard.Release(conn)

	s.addLog(fmt.Sprintf("新客户端连接: %s", remoteAddr))

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 读取登录消息（第二防：协议层校验在 ReadMessage 内部）
	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		if err == io.EOF {
			// EOF：客户端在登录前关闭连接（网络抖动 / NAT 波动 / 正常断开）
			// 宽松策略：不封禁，仅记录
			s.addLog(fmt.Sprintf("[%s] 登录前连接关闭(EOF)，网络波动不封禁", remoteAddr))
		} else {
			s.addLog(fmt.Sprintf("[%s] 读取登录消息失败: %v", remoteAddr, err))
			// 协议异常：连续多次才封禁（由 ConnGuard 阈值控制）
			s.connGuard.BanForBadBehavior(conn, err.Error())
		}
		return
	}

	if msg.Type != protocol.TypeLogin {
		s.addLog(fmt.Sprintf("[%s] 期望登录消息，收到类型: %d", remoteAddr, msg.Type))
		s.connGuard.BanForBadBehavior(conn, "消息类型错误")
		return
	}

	login, err := protocol.ParseMessage[protocol.Login](msg)
	if err != nil {
		s.addLog(fmt.Sprintf("[%s] 解析登录失败: %v", remoteAddr, err))
		return
	}

	// 验证token（第三防：应用层）
	if subtle.ConstantTimeCompare([]byte(login.Token), []byte(s.cfg.Token)) != 1 {
		s.addLog(fmt.Sprintf("[%s] Token无效", remoteAddr))
		protocol.WriteMessage(conn, protocol.TypeLoginResp, protocol.LoginResp{
			Success: false,
			Error:   "invalid token",
		})
		return
	}

	// 登录成功
	conn.SetReadDeadline(time.Time{})
	protocol.WriteMessage(conn, protocol.TypeLoginResp, protocol.LoginResp{Success: true})
	// 登录成功 → 清除该 IP 的异常计数，避免历史抖动导致后续误封
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		s.connGuard.ClearMisbehavior(host)
	}
	s.addLog(fmt.Sprintf("[%s] 客户端认证成功", remoteAddr))

	// 多客户端：每个连接分配独立 ID，代理按 Owner 归属，断开时只清理自己的代理
	clientID := fmt.Sprintf("%s-%d", remoteAddr, time.Now().UnixNano())
	s.mu.Lock()
	s.clients[clientID] = conn
	s.mu.Unlock()

	// 处理后续消息
	s.handleControlMessages(conn, clientID)
}

// handleControlMessages 处理控制消息
func (s *Server) handleControlMessages(conn net.Conn, clientID string) {
	for {
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			if err != io.EOF {
				s.addLog(fmt.Sprintf("读取控制消息错误: %v", err))
			}
			break
		}

		switch msg.Type {
		case protocol.TypeNewProxy:
			s.handleNewProxy(conn, msg, clientID)
		case protocol.TypeHeartbeat:
			protocol.WriteMessage(conn, protocol.TypeHeartbeatResp, struct{}{})
		}
	}

	// 清理资源：仅清理本客户端拥有的代理，互不干扰（多客户端隔离）
	s.mu.Lock()
	for name, proxy := range s.proxies {
		if proxy.Owner == clientID {
			s.cleanupProxy(name, proxy)
		}
	}
	delete(s.clients, clientID)
	s.mu.Unlock()
	s.addLog(fmt.Sprintf("客户端 [%s] 断开连接", clientID))
}

// cleanupProxy 关闭并移除指定代理（调用方需持有 s.mu 写锁）
func (s *Server) cleanupProxy(name string, proxy *Proxy) {
	if proxy.Listener != nil {
		proxy.Listener.Close()
	}
	if proxy.DataListener != nil {
		proxy.DataListener.Close() // 令 acceptDataConnections 退出
	}
	if proxy.UDPConn != nil {
		proxy.UDPConn.Close()
	}
	if proxy.UDPDataConn != nil {
		proxy.UDPDataConn.Close() // 令 handleUDP* goroutine 退出
	}
	if proxy.sessionQuit != nil {
		close(proxy.sessionQuit) // 停止 cleanupUDPSessions
	}
	delete(s.proxies, name)
	s.addLog(fmt.Sprintf("代理 [%s] 已关闭", name))
}

// handleNewProxy 处理新建代理请求
func (s *Server) handleNewProxy(conn net.Conn, msg *protocol.Message, clientID string) {
	newProxy, err := protocol.ParseMessage[protocol.NewProxy](msg)
	if err != nil {
		s.addLog(fmt.Sprintf("解析新代理失败: %v", err))
		return
	}

	s.addLog(fmt.Sprintf("创建代理 [%s] 类型=%s 远程端口=%d 属主=%s", newProxy.Name, newProxy.Type, newProxy.RemotePort, clientID))

	resp := protocol.NewProxyResp{
		Name:    newProxy.Name,
		Success: false,
	}

	// ACL 校验：代理名/端口是否被允许
	if !s.proxyAllowed(newProxy.Name, newProxy.RemotePort) {
		resp.Error = "proxy creation blocked by ACL"
		protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
		s.addLogWarn(fmt.Sprintf("代理 [%s] 被 ACL 拒绝 (port=%d)", newProxy.Name, newProxy.RemotePort))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.proxies[newProxy.Name]; exists {
		resp.Error = fmt.Sprintf("proxy [%s] already exists", newProxy.Name)
		protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
		return
	}

	proxy := &Proxy{
		Name:       newProxy.Name,
		Type:       newProxy.Type,
		RemotePort: newProxy.RemotePort,
		ClientConn: conn,
		Active:     true,
		Owner:      clientID,
	}

	switch newProxy.Type {
		case protocol.ProxyTCP:
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", newProxy.RemotePort))
			if err != nil {
				resp.Error = fmt.Sprintf("listen port %d failed: %v", newProxy.RemotePort, err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			proxy.Listener = ln

			// 独立 TCP 数据通道（随机端口），彻底与控制通道解耦
			dln, err := net.Listen("tcp", ":0")
			if err != nil {
				ln.Close()
				resp.Error = fmt.Sprintf("listen data port failed: %v", err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			if s.tlsConf != nil {
				dln = tls.NewListener(dln, s.tlsConf)
			}
			proxy.DataListener = dln
			proxy.DataPort = dln.Addr().(*net.TCPAddr).Port
			proxy.pending = make(map[string]chan net.Conn)
			go s.acceptDataConnections(proxy)

			go s.acceptTCPConnections(proxy)

		case protocol.ProxyUDP:
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", newProxy.RemotePort))
			if err != nil {
				resp.Error = fmt.Sprintf("resolve udp addr failed: %v", err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			udpConn, err := net.ListenUDP("udp", addr)
			if err != nil {
				resp.Error = fmt.Sprintf("listen udp port %d failed: %v", newProxy.RemotePort, err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			proxy.UDPConn = udpConn

			// 独立 UDP 数据通道（随机端口），彻底与控制通道解耦
			daddr, err := net.ResolveUDPAddr("udp", ":0")
			if err != nil {
				udpConn.Close()
				resp.Error = fmt.Sprintf("resolve udp data addr failed: %v", err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			udpDataConn, err := net.ListenUDP("udp", daddr)
			if err != nil {
				udpConn.Close()
				resp.Error = fmt.Sprintf("listen udp data port failed: %v", err)
				s.addLog(resp.Error)
				protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
				return
			}
			proxy.UDPDataConn = udpDataConn
			proxy.udpDataPort = udpDataConn.LocalAddr().(*net.UDPAddr).Port
			proxy.sessions = make(map[string]*UDPSession)
			proxy.addrIndex = make(map[string]string)
			proxy.sessionQuit = make(chan struct{})

			go s.handleUDPConnections(proxy)
			go s.handleUDPDataChannel(proxy)
			go s.cleanupUDPSessions(proxy)

	default:
		resp.Error = fmt.Sprintf("unsupported proxy type: %s", newProxy.Type)
		protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
		return
	}

	s.proxies[newProxy.Name] = proxy
	resp.Success = true
	resp.RemotePort = newProxy.RemotePort
	resp.UDPDataPort = proxy.udpDataPort // TCP 时为 0（omitempty 省略），UDP 时为独立数据通道端口
	protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
	s.addLog(fmt.Sprintf("代理 [%s] 创建成功，监听端口 %d", newProxy.Name, newProxy.RemotePort))
}

// acceptTCPConnections 接受TCP连接
func (s *Server) acceptTCPConnections(proxy *Proxy) {
	for {
		userConn, err := proxy.Listener.Accept()
		if err != nil {
			break
		}
		go s.handleTCPUserConnection(proxy, userConn)
	}
}

// handleTCPUserConnection 处理TCP用户连接
func (s *Server) handleTCPUserConnection(proxy *Proxy, userConn net.Conn) {
	defer userConn.Close()
	connID := fmt.Sprintf("%d", time.Now().UnixNano())
	s.addLog(fmt.Sprintf("代理 [%s] 新TCP连接, conn_id=%s", proxy.Name, connID))

	// 通知客户端有新连接，并下发独立数据通道端口
	err := protocol.WriteMessage(proxy.ClientConn, protocol.TypeNewConn, protocol.NewConn{
		ProxyName: proxy.Name,
		ConnID:    connID,
		DataPort:  proxy.DataPort,
	})
	if err != nil {
		s.addLog(fmt.Sprintf("通知客户端失败: %v", err))
		return
	}

	// 等待 client 经独立数据通道连上来（按 connID 关联，与控制通道解耦）
	ch := make(chan net.Conn, 1)
	s.mu.Lock()
	if proxy.DataListener == nil {
		s.mu.Unlock()
		s.addLog(fmt.Sprintf("代理 [%s] 数据通道未就绪", proxy.Name))
		return
	}
	proxy.pending[connID] = ch
	s.mu.Unlock()

	var dataConn net.Conn
	select {
	case dataConn = <-ch:
	case <-time.After(30 * time.Second):
		s.mu.Lock()
		delete(proxy.pending, connID)
		s.mu.Unlock()
		s.addLog(fmt.Sprintf("代理 [%s] 等待数据通道超时 conn_id=%s", proxy.Name, connID))
		return
	}
	defer dataConn.Close()

	// 在独立数据通道上做 HMAC 签名转发（forwardWithAuth 逻辑不变，仅第二参数由控制连接换成数据连接）
	s.forwardWithAuth(userConn, dataConn, connID, proxy)
	s.addLog(fmt.Sprintf("连接 %s 关闭", connID))
}

// forwardWithAuth 带认证的数据转发（使用帧格式,解决TCP分包导致的帧同步丢失）
func (s *Server) forwardWithAuth(userConn, clientConn net.Conn, connID string, proxy *Proxy) {
	errChan := make(chan error, 2)
	bufSize := 32 * 1024

	// user -> client (签名)
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := userConn.Read(buf)
			if n > 0 {
				atomic.AddInt64(&proxy.BytesIn, int64(n))
				signed := s.auth.SignFramed(buf[:n])
				_, writeErr := clientConn.Write(signed)
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

	// client -> user (验证) - 使用 ReadFramed 确保每次读取完整帧
	go func() {
		for {
			data, err := s.auth.ReadFramed(clientConn)
			if err != nil {
				errChan <- err
				return
			}
			atomic.AddInt64(&proxy.BytesOut, int64(len(data)))
			_, writeErr := userConn.Write(data)
			if writeErr != nil {
				errChan <- writeErr
				return
			}
		}
	}()

	<-errChan
	s.addLog(fmt.Sprintf("连接 %s 关闭", connID))
}

// handleUDPConnections 处理公网 UDP 用户流量（与控制通道、client 数据通道完全解耦）。
// 用户明文 UDP 包在此接收，按 userAddr 分配 session，封装成 UDPEnvelope 经独立 UDP 数据通道发往 client。
func (s *Server) handleUDPConnections(proxy *Proxy) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := proxy.UDPConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n == 0 {
			continue
		}

		sid, isNew := s.getOrCreateSession(proxy, addr)
		if isNew {
			// 通知 client 新建 session（握手帧，无负载）
			s.sendUDPToClient(proxy, protocol.UDPEnvelope{Kind: 0x01, SessionID: sid})
		}

		// 转发用户负载（拷贝，避免被后续读覆盖）
		payload := make([]byte, n)
		copy(payload, buf[:n])
		s.sendUDPToClient(proxy, protocol.UDPEnvelope{Kind: 0x02, SessionID: sid, Data: payload})
	}
}

// sendUDPToClient 通过独立 UDP 数据通道把封装好的 envelope 发往 client（带 HMAC 签名）。
// client 数据通道地址未知时先缓存，待 handleUDPDataChannel 收到首包登记地址后 flush。
func (s *Server) sendUDPToClient(proxy *Proxy, env protocol.UDPEnvelope) {
	signed := s.auth.Sign(protocol.MarshalEnvelope(env))
	if len(signed) > 65507 {
		return // 单包过大，丢弃
	}

	proxy.sessionMu.RLock()
	addr := proxy.clientDataAddr
	proxy.sessionMu.RUnlock()

	if addr == nil {
		proxy.sessionMu.Lock()
		if len(proxy.pendingOut) < 1024 {
			proxy.pendingOut = append(proxy.pendingOut, env)
		}
		proxy.sessionMu.Unlock()
		return
	}
	_, _ = proxy.UDPDataConn.WriteToUDP(signed, addr)
}

// handleUDPDataChannel 处理 client 经独立 UDP 数据通道发来的数据（签名验证 + session 复用）。
func (s *Server) handleUDPDataChannel(proxy *Proxy) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := proxy.UDPDataConn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		// 首次收到 client 数据通道包：登记其地址，并 flush 缓存的待发包
		proxy.sessionMu.Lock()
		if proxy.clientDataAddr == nil {
			proxy.clientDataAddr = addr
			pending := proxy.pendingOut
			proxy.pendingOut = nil
			proxy.sessionMu.Unlock()
			for _, env := range pending {
				signed := s.auth.Sign(protocol.MarshalEnvelope(env))
				_, _ = proxy.UDPDataConn.WriteToUDP(signed, addr)
			}
		} else {
			proxy.sessionMu.Unlock()
		}

		data, ok := s.auth.Verify(buf[:n])
		if !ok {
			continue // 签名无效：忽略（可接入 ConnGuard 拉黑）
		}
		env, ok := protocol.UnmarshalEnvelope(data)
		if !ok {
			continue
		}

		switch env.Kind {
		case 0x02: // 后端回包：client -> server -> 公网用户
			proxy.sessionMu.RLock()
			sess, exists := proxy.sessions[env.SessionID]
			proxy.sessionMu.RUnlock()
			if exists && len(env.Data) > 0 {
				_, _ = proxy.UDPConn.WriteToUDP(env.Data, sess.userAddr)
				proxy.sessionMu.Lock()
				if s2, ok := proxy.sessions[env.SessionID]; ok {
					s2.lastActive = time.Now()
				}
				proxy.sessionMu.Unlock()
			}
		case 0x03: // client 通知关闭 session
			proxy.sessionMu.Lock()
			if sess, ok := proxy.sessions[env.SessionID]; ok {
				delete(proxy.sessions, env.SessionID)
				delete(proxy.addrIndex, sess.userAddr.String())
			}
			proxy.sessionMu.Unlock()
		default: // 0x00 hello 等：地址已登记，忽略
		}
	}
}

// getOrCreateSession 按公网用户地址分配/复用 UDP session，返回 sessionID 与是否新建。
func (s *Server) getOrCreateSession(proxy *Proxy, userAddr *net.UDPAddr) (string, bool) {
	proxy.sessionMu.Lock()
	defer proxy.sessionMu.Unlock()

	key := userAddr.String()
	if sid, ok := proxy.addrIndex[key]; ok {
		if sess, ok := proxy.sessions[sid]; ok {
			sess.lastActive = time.Now()
		}
		return sid, false
	}
	sid := fmt.Sprintf("%016x", atomic.AddUint64(&proxy.sessionSeq, 1))
	proxy.sessions[sid] = &UDPSession{userAddr: userAddr, lastActive: time.Now()}
	proxy.addrIndex[key] = sid
	return sid, true
}

// cleanupUDPSessions 定期清理空闲 UDP session。
func (s *Server) cleanupUDPSessions(proxy *Proxy) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-proxy.sessionQuit:
			return
		case <-ticker.C:
			now := time.Now()
			proxy.sessionMu.Lock()
			for sid, sess := range proxy.sessions {
				if now.Sub(sess.lastActive) > 5*time.Minute {
					delete(proxy.sessions, sid)
					delete(proxy.addrIndex, sess.userAddr.String())
				}
			}
			proxy.sessionMu.Unlock()
		}
	}
}

// acceptDataConnections 接受 client 经独立 TCP 数据通道连上来的连接，
// 按首帧 connID 关联到等待中的用户连接（与控制通道解耦）。
func (s *Server) acceptDataConnections(proxy *Proxy) {
	for {
		conn, err := proxy.DataListener.Accept()
		if err != nil {
			break // DataListener 被关闭时退出
		}

		// 读取首帧标识：TypeDataConn + DataConnIdentify{ConnID}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		msg, err := protocol.ReadMessage(conn)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			continue
		}
		if msg.Type != protocol.TypeDataConn {
			conn.Close()
			continue
		}
		idMsg, err := protocol.ParseMessage[protocol.DataConnIdentify](msg)
		if err != nil {
			conn.Close()
			continue
		}
		connID := idMsg.ConnID

		s.mu.Lock()
		ch, ok := proxy.pending[connID]
		if ok {
			delete(proxy.pending, connID)
		}
		s.mu.Unlock()

		if ok {
			ch <- conn
		} else {
			conn.Close() // 无对应等待，关闭
		}
	}
}


// proxyAllowed ACL 校验：代理名正则 + 端口白名单（全部为空时不限制）
func (s *Server) proxyAllowed(name string, port int) bool {
	acl := s.cfg.ProxyACL
	if len(acl.AllowNames) == 0 && len(acl.AllowPorts) == 0 {
		return true
	}
	if len(acl.AllowNames) > 0 {
		ok := false
		for _, pattern := range acl.AllowNames {
			if m, _ := regexp.MatchString(pattern, name); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(acl.AllowPorts) > 0 {
		ok := false
		for _, p := range acl.AllowPorts {
			if p == port {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// mustConnGuard 创建带白名单的连接守卫；白名单格式错误则终止启动，避免运行时才发现
func mustConnGuard(whitelist []string) *security.ConnGuard {
	g, err := security.NewConnGuardWithWhitelist(whitelist)
	if err != nil {
		log.Fatalf("Load conn_guard whitelist failed: %v", err)
	}
	return g
}
