// Package security 提供连接安全防护
package security

import (
	"log"
	"net"
	"sync"
	"time"
)

// ConnGuard 连接守卫 - 第一防：连接层防护
type ConnGuard struct {
	mu          sync.Mutex
	connCount   map[string]int       // 每个 IP 的当前连接数
	lastConn    map[string]time.Time // 每个 IP 上次连接时间
	blacklist   map[string]time.Time // 黑名单 IP + 封禁时间
	maxConn     int                  // 单 IP 最大连接数
	minInterval time.Duration        // 最小连接间隔
	banDuration time.Duration        // 封禁时长
}

// NewConnGuard 创建连接守卫
func NewConnGuard() *ConnGuard {
	return &ConnGuard{
		connCount:   make(map[string]int),
		lastConn:    make(map[string]time.Time),
		blacklist:   make(map[string]time.Time),
		maxConn:     10,              // 单 IP 最多 10 个连接
		minInterval: 50 * time.Millisecond, // 连接间隔至少 50ms
		banDuration: 1 * time.Hour,   // 封禁 1 小时
	}
}

// Check 检查连接是否允许
// 返回 true 表示允许，false 表示拒绝
func (g *ConnGuard) Check(conn net.Conn) bool {
	ip := getIP(conn)

	g.mu.Lock()
	defer g.mu.Unlock()

	// 1. 检查是否在黑名单
	if banTime, ok := g.blacklist[ip]; ok {
		if time.Since(banTime) < g.banDuration {
			log.Printf("[安全] IP %s 被拒绝（仍在封禁期）", ip)
			return false
		}
		// 封禁到期，移除
		delete(g.blacklist, ip)
		log.Printf("[安全] IP %s 封禁到期，已移除", ip)
	}

	// 2. 检查连接频率
	if last, ok := g.lastConn[ip]; ok {
		if time.Since(last) < g.minInterval {
			log.Printf("[安全] IP %s 被拒绝（连接频率过高）", ip)
			g.ban(ip, "连接频率过高")
			return false
		}
	}

	// 3. 检查连接数
	if g.connCount[ip] >= g.maxConn {
		log.Printf("[安全] IP %s 被拒绝（连接数过多: %d）", ip, g.connCount[ip])
		g.ban(ip, "连接数过多")
		return false
	}

	// 4. 通过检查，记录
	g.lastConn[ip] = time.Now()
	g.connCount[ip]++
	return true
}

// Release 连接断开时调用，释放计数
func (g *ConnGuard) Release(conn net.Conn) {
	ip := getIP(conn)
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.connCount[ip] > 0 {
		g.connCount[ip]--
	}
}

// BanForBadBehavior 因异常行为封禁 IP
func (g *ConnGuard) BanForBadBehavior(conn net.Conn, reason string) {
	ip := getIP(conn)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ban(ip, reason)
}

// BanIP 直接封禁指定 IP
func (g *ConnGuard) BanIP(ip string, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ban(ip, reason)
}

// IsBanned 检查 IP 是否被封禁
func (g *ConnGuard) IsBanned(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if banTime, ok := g.blacklist[ip]; ok {
		return time.Since(banTime) < g.banDuration
	}
	return false
}

// GetStats 获取统计信息
func (g *ConnGuard) GetStats() (blacklistCount int, totalConns int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// 清理过期的黑名单
	now := time.Now()
	for ip, banTime := range g.blacklist {
		if now.Sub(banTime) >= g.banDuration {
			delete(g.blacklist, ip)
		}
	}

	blacklistCount = len(g.blacklist)
	for _, count := range g.connCount {
		totalConns += count
	}
	return
}

// ========== 内部方法 ==========

// ban 封禁 IP（调用方需持有锁）
func (g *ConnGuard) ban(ip string, reason string) {
	g.blacklist[ip] = time.Now()
	log.Printf("[安全] IP %s 被封禁 %v，原因: %s", ip, g.banDuration, reason)
}

// getIP 从连接中提取 IP 地址
func getIP(conn net.Conn) string {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}

	// 兜底：从地址字符串中提取
	addr := conn.RemoteAddr().String()
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
