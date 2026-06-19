// Secure Tunnel Server - 带数据包认证的内网穿透服务端
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"nexuslink/pkg/auth"
	"nexuslink/pkg/config"
	"nexuslink/pkg/protocol"
	"nexuslink/pkg/web"
)

var Version = "dev"

var (
	configFile = flag.String("c", "server.yaml", "config file path")
	genToken   = flag.Bool("gen-token", false, "generate a random token")
)

// Proxy 代理信息
type Proxy struct {
	Name       string
	Type       protocol.ProxyType
	RemotePort int
	Listener   net.Listener
	UDPConn    *net.UDPConn
	ClientConn net.Conn
	Active     bool
}

// Server 服务端
type Server struct {
	cfg        *config.ServerConfig
	auth       *auth.Auth
	proxies    map[string]*Proxy
	clientConn net.Conn
	webServer  *web.WebServer
	mu         sync.RWMutex
	startTime  time.Time
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
		})
	}

	clientCount := 0
	if s.clientConn != nil {
		clientCount = 1
	}

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
		startTime: time.Now(),
	}

	log.Printf("NexusLink Server v%s starting...", Version)
	log.Printf("Listening on %s:%d", cfg.BindAddr, cfg.BindPort)

	// 启动Web管理面板（默认启用）
	if cfg.WebEnable || cfg.WebPassword != "" {
		webCfg := &web.WebConfig{
			Addr:         cfg.WebAddr,
			Port:         cfg.WebPort,
			AdminPassword: cfg.WebPassword,
		}
		server.webServer = web.NewWebServer(webCfg, server)
		if err := server.webServer.Start(); err != nil {
			log.Printf("Web panel start failed: %v", err)
		} else {
			log.Printf("Web admin panel: http://%s:%d", cfg.WebAddr, cfg.WebPort)
			log.Printf("Web admin password: %s", cfg.WebPassword)
		}
	}

	server.addLog(fmt.Sprintf("NexusLink Server v%s 启动", Version))
	server.addLog(fmt.Sprintf("监听地址: %s:%d", cfg.BindAddr, cfg.BindPort))

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.BindPort))
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

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
	s.addLog(fmt.Sprintf("新客户端连接: %s", remoteAddr))

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 读取登录消息
	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		s.addLog(fmt.Sprintf("[%s] 读取登录消息失败: %v", remoteAddr, err))
		return
	}

	if msg.Type != protocol.TypeLogin {
		s.addLog(fmt.Sprintf("[%s] 期望登录消息，收到类型: %d", remoteAddr, msg.Type))
		return
	}

	login, err := protocol.ParseMessage[protocol.Login](msg)
	if err != nil {
		s.addLog(fmt.Sprintf("[%s] 解析登录失败: %v", remoteAddr, err))
		return
	}

	// 验证token
	if login.Token != s.cfg.Token {
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
	s.addLog(fmt.Sprintf("[%s] 客户端认证成功", remoteAddr))

	s.mu.Lock()
	s.clientConn = conn
	s.mu.Unlock()

	// 处理后续消息
	s.handleControlMessages(conn)
}

// handleControlMessages 处理控制消息
func (s *Server) handleControlMessages(conn net.Conn) {
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
			s.handleNewProxy(conn, msg)
		case protocol.TypeHeartbeat:
			protocol.WriteMessage(conn, protocol.TypeHeartbeatResp, struct{}{})
		}
	}

	// 清理资源
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, proxy := range s.proxies {
		if proxy.Listener != nil {
			proxy.Listener.Close()
		}
		if proxy.UDPConn != nil {
			proxy.UDPConn.Close()
		}
		delete(s.proxies, name)
		s.addLog(fmt.Sprintf("代理 [%s] 已关闭", name))
	}

	s.clientConn = nil
	s.addLog("客户端断开连接")
}

// handleNewProxy 处理新建代理请求
func (s *Server) handleNewProxy(conn net.Conn, msg *protocol.Message) {
	newProxy, err := protocol.ParseMessage[protocol.NewProxy](msg)
	if err != nil {
		s.addLog(fmt.Sprintf("解析新代理失败: %v", err))
		return
	}

	s.addLog(fmt.Sprintf("创建代理 [%s] 类型=%s 远程端口=%d", newProxy.Name, newProxy.Type, newProxy.RemotePort))

	resp := protocol.NewProxyResp{
		Name:    newProxy.Name,
		Success: false,
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
		go s.handleUDPConnections(proxy)

	default:
		resp.Error = fmt.Sprintf("unsupported proxy type: %s", newProxy.Type)
		protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
		return
	}

	s.proxies[newProxy.Name] = proxy
	resp.Success = true
	resp.RemotePort = newProxy.RemotePort
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

	// 通知客户端有新连接
	err := protocol.WriteMessage(proxy.ClientConn, protocol.TypeNewConn, protocol.NewConn{
		ProxyName: proxy.Name,
		ConnID:    connID,
	})
	if err != nil {
		s.addLog(fmt.Sprintf("通知客户端失败: %v", err))
		return
	}

	// 建立数据通道 - 使用带认证的转发
	go s.forwardWithAuth(userConn, proxy.ClientConn, connID)
}

// forwardWithAuth 带认证的数据转发
func (s *Server) forwardWithAuth(userConn, clientConn net.Conn, connID string) {
	errChan := make(chan error, 2)
	bufSize := 32 * 1024

	// user -> client (签名)
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := userConn.Read(buf)
			if n > 0 {
				signed := s.auth.Sign(buf[:n])
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

	// client -> user (验证)
	go func() {
		buf := make([]byte, bufSize+auth.HeaderSize)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				data, ok := s.auth.Verify(buf[:n])
				if !ok {
					errChan <- fmt.Errorf("invalid signature")
					return
				}
				_, writeErr := userConn.Write(data)
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
	s.addLog(fmt.Sprintf("连接 %s 关闭", connID))
}

// handleUDPConnections 处理UDP连接
func (s *Server) handleUDPConnections(proxy *Proxy) {
	buf := make([]byte, 65535)
	clientMap := make(map[string]*net.UDPAddr)

	for {
		n, addr, err := proxy.UDPConn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		clientMap[addr.String()] = addr

		// 验证并转发到客户端
		data, ok := s.auth.Verify(buf[:n])
		if !ok {
			s.addLog(fmt.Sprintf("来自 %s 的UDP数据包签名无效", addr))
			continue
		}

		// 转发到客户端控制通道(简化实现)
		_, err = proxy.ClientConn.Write(s.auth.Sign(data))
		if err != nil {
			s.addLog(fmt.Sprintf("转发UDP到客户端失败: %v", err))
		}
	}
}
