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
)

const version = "1.0.0"

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
}

// Server 服务端
type Server struct {
	cfg        *config.ServerConfig
	auth       *auth.Auth
	proxies    map[string]*Proxy
	clientConn net.Conn
	mu         sync.RWMutex
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
		cfg:     cfg,
		auth:    auth.NewAuth(cfg.Token),
		proxies: make(map[string]*Proxy),
	}

	log.Printf("Secure Tunnel Server v%s starting...", version)
	log.Printf("Listening on %s:%d", cfg.BindAddr, cfg.BindPort)

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
	log.Printf("New client connection from %s", remoteAddr)

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 读取登录消息
	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		log.Printf("[%s] Read login message failed: %v", remoteAddr, err)
		return
	}

	if msg.Type != protocol.TypeLogin {
		log.Printf("[%s] Expected login message, got type %d", remoteAddr, msg.Type)
		return
	}

	login, err := protocol.ParseMessage[protocol.Login](msg)
	if err != nil {
		log.Printf("[%s] Parse login failed: %v", remoteAddr, err)
		return
	}

	// 验证token
	if login.Token != s.cfg.Token {
		log.Printf("[%s] Invalid token", remoteAddr)
		protocol.WriteMessage(conn, protocol.TypeLoginResp, protocol.LoginResp{
			Success: false,
			Error:   "invalid token",
		})
		return
	}

	// 登录成功
	conn.SetReadDeadline(time.Time{})
	protocol.WriteMessage(conn, protocol.TypeLoginResp, protocol.LoginResp{Success: true})
	log.Printf("[%s] Client authenticated successfully", remoteAddr)

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
				log.Printf("Read control message error: %v", err)
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
		log.Printf("Proxy [%s] closed", name)
	}
	s.clientConn = nil
	log.Println("Client disconnected")
}

// handleNewProxy 处理新建代理请求
func (s *Server) handleNewProxy(conn net.Conn, msg *protocol.Message) {
	newProxy, err := protocol.ParseMessage[protocol.NewProxy](msg)
	if err != nil {
		log.Printf("Parse new proxy failed: %v", err)
		return
	}

	log.Printf("Creating proxy [%s] type=%s remote_port=%d", newProxy.Name, newProxy.Type, newProxy.RemotePort)

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
	}

	switch newProxy.Type {
	case protocol.ProxyTCP:
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", newProxy.RemotePort))
		if err != nil {
			resp.Error = fmt.Sprintf("listen port %d failed: %v", newProxy.RemotePort, err)
			log.Printf(resp.Error)
			protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
			return
		}
		proxy.Listener = ln
		go s.acceptTCPConnections(proxy)

	case protocol.ProxyUDP:
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", newProxy.RemotePort))
		if err != nil {
			resp.Error = fmt.Sprintf("resolve udp addr failed: %v", err)
			log.Printf(resp.Error)
			protocol.WriteMessage(conn, protocol.TypeNewProxyResp, resp)
			return
		}
		udpConn, err := net.ListenUDP("udp", addr)
		if err != nil {
			resp.Error = fmt.Sprintf("listen udp port %d failed: %v", newProxy.RemotePort, err)
			log.Printf(resp.Error)
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
	log.Printf("Proxy [%s] created successfully, listening on port %d", newProxy.Name, newProxy.RemotePort)
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
	log.Printf("New TCP connection on proxy [%s], conn_id=%s", proxy.Name, connID)

	// 通知客户端有新连接
	err := protocol.WriteMessage(proxy.ClientConn, protocol.TypeNewConn, protocol.NewConn{
		ProxyName: proxy.Name,
		ConnID:    connID,
	})
	if err != nil {
		log.Printf("Notify client failed: %v", err)
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
	log.Printf("Connection %s closed", connID)
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
			log.Printf("Invalid UDP packet signature from %s", addr)
			continue
		}

		// 转发到客户端控制通道(简化实现)
		// 实际生产环境需要更复杂的UDP会话管理
		_, err = proxy.ClientConn.Write(s.auth.Sign(data))
		if err != nil {
			log.Printf("Forward UDP to client failed: %v", err)
		}
	}
}
