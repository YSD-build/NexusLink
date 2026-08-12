// Package security 提供连接安全防护
package security

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ConnGuard 连接守卫 - 第一防：连接层防护
type ConnGuard struct {
	mu          sync.Mutex
	connCount   map[string]int       // 每个 IP 的当前连接数
	lastConn    map[string]time.Time // 每个 IP 上次连接时间
	blacklist   map[string]time.Time // 黑名单 IP + 封禁时间
	misbehavior map[string]int       // 每个 IP 连续异常次数（达到阈值才封禁）
	whitelist   []*net.IPNet         // 白名单 CIDR 列表（命中完全 bypass）
	maxConn     int                  // 单 IP 最大连接数
	minInterval time.Duration        // 最小连接间隔
	banDuration time.Duration        // 封禁时长
	banThreshold int                 // 连续异常次数达到该值才封禁
}

// NewConnGuard 创建连接守卫（不带白名单）
// 宽松策略：网络抖动（EOF）/ 单次协议错误不封禁，连续 banThreshold 次异常才封禁
func NewConnGuard() *ConnGuard {
	return &ConnGuard{
		connCount:    make(map[string]int),
		lastConn:     make(map[string]time.Time),
		blacklist:    make(map[string]time.Time),
		misbehavior:  make(map[string]int),
		maxConn:      200,                   // 单 IP 最多 200 个连接（宽松）
		minInterval:  1 * time.Second,       // 连接间隔至少 1s（放宽，避免 NAT 抖动误判）
		banDuration:  1 * time.Minute,       // 封禁 1 分钟（缩短，便于恢复）
		banThreshold: 3,                     // 连续 3 次异常才封禁（容忍偶发抖动）
	}
}

// NewConnGuardWithWhitelist 创建带白名单的连接守卫
// 白名单条目支持两种格式：
//   - 单 IP： "1.2.3.4"    （自动补 /32）
//   - CIDR：   "10.0.0.0/8"
//
// 白名单命中时**完全绕过**所有检测（黑名单 / 频率 / 连接数），不被计数，
// 即使该 IP 在黑名单中也会被放行（白名单优先语义）。
func NewConnGuardWithWhitelist(whitelist []string) (*ConnGuard, error) {
	g := NewConnGuard()
	for _, c := range whitelist {
		entry := strings.TrimSpace(c)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			entry = entry + "/32" // 单 IP 当作 /32 CIDR
		}
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("白名单条目 %q 格式错误: %v", c, err)
		}
		g.whitelist = append(g.whitelist, ipnet)
		log.Printf("[安全] 白名单已注册: %s", ipnet.String())
	}
	return g, nil
}

// Check 检查连接是否允许
// 返回 true 表示允许，false 表示拒绝
// 本地回环地址(127.0.0.1, ::1)跳过频率和连接数限制，避免压测/同机部署时误封
func (g *ConnGuard) Check(conn net.Conn) bool {
	ip := getIP(conn)

	// 白名单优先：命中即直接放行，跳过黑名单/频率/连接数所有检查（也不计数）
	if g.isWhitelisted(ip) {
		return true
	}

	// 本地回环地址跳过限流（但仍记录连接数用于 Release 配对）
	if isLoopback(ip) {
		g.mu.Lock()
		g.lastConn[ip] = time.Now()
		g.connCount[ip]++
		g.mu.Unlock()
		return true
	}

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

	// 2. 检查连接频率（宽松：单次超限仅计数，连续 banThreshold 次才封禁）
	if last, ok := g.lastConn[ip]; ok {
		if time.Since(last) < g.minInterval {
			g.misbehavior[ip]++
			if g.misbehavior[ip] >= g.banThreshold {
				g.ban(ip, "连接频率过高")
				g.misbehavior[ip] = 0
			} else {
				log.Printf("[安全] IP %s 连接频率过高 +1 (%d/%d)，暂不封禁", ip, g.misbehavior[ip], g.banThreshold)
			}
			return false
		}
	}

	// 3. 检查连接数（宽松：单次超限仅计数，连续 banThreshold 次才封禁）
	if g.connCount[ip] >= g.maxConn {
		g.misbehavior[ip]++
		if g.misbehavior[ip] >= g.banThreshold {
			g.ban(ip, "连接数过多")
			g.misbehavior[ip] = 0
		} else {
			log.Printf("[安全] IP %s 连接数过多 +1 (%d/%d)，暂不封禁", ip, g.misbehavior[ip], g.banThreshold)
		}
		return false
	}

	// 4. 通过检查，记录
	g.lastConn[ip] = time.Now()
	g.connCount[ip]++
	return true
}

// isWhitelisted 判断 IP 是否命中白名单
func (g *ConnGuard) isWhitelisted(ipStr string) bool {
	if len(g.whitelist) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range g.whitelist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

// BanForBadBehavior 记录一次异常行为；连续 banThreshold 次异常才真正封禁。
// 单次网络抖动 / EOF 不封禁，仅计数（宽松策略）；白名单 IP 始终免于封禁。
func (g *ConnGuard) BanForBadBehavior(conn net.Conn, reason string) {
	ip := getIP(conn)
	if g.isWhitelisted(ip) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.misbehavior[ip]++
	if g.misbehavior[ip] >= g.banThreshold {
		g.ban(ip, fmt.Sprintf("%s (连续%d次异常)", reason, g.misbehavior[ip]))
		g.misbehavior[ip] = 0 // 已封禁，清零等待下次循环
	} else {
		log.Printf("[安全] IP %s 异常行为 +1 (%d/%d)，暂不封禁", ip, g.misbehavior[ip], g.banThreshold)
	}
}

// ClearMisbehavior 清除指定 IP 的异常计数（登录成功后调用，避免误封正常客户端）
func (g *ConnGuard) ClearMisbehavior(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.misbehavior, ip)
}

// BanIP 直接封禁指定 IP（白名单优先——不会封白名单中的 IP）
func (g *ConnGuard) BanIP(ip string, reason string) {
	if g.isWhitelisted(ip) {
		return
	}
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

// isLoopback 检查 IP 是否为本地回环地址
func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}