package security

import (
	"net"
	"testing"
	"time"
)

// fakeRemoteConn 直接构造一个带 RemoteAddr 的 conn（ConnGuard 通过 RemoteAddr 取 IP）
func fakeRemoteConn(ip string) net.Conn {
	la, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	ra, _ := net.ResolveTCPAddr("tcp", ip+":12345")
	return &fakeConnImpl{la: la, ra: ra}
}

type fakeConnImpl struct {
	la, ra *net.TCPAddr
	net.Conn
}

func (c *fakeConnImpl) LocalAddr() net.Addr  { return c.la }
func (c *fakeConnImpl) RemoteAddr() net.Addr { return c.ra }
func (c *fakeConnImpl) Close() error         { return nil }

func TestNewConnGuardWithWhitelist_BadCIDR(t *testing.T) {
	_, err := NewConnGuardWithWhitelist([]string{"not-an-ip"})
	if err == nil {
		t.Fatal("非法的 CIDR 应该返回错误")
	}
}

func TestNewConnGuardWithWhitelist_Empty(t *testing.T) {
	g, err := NewConnGuardWithWhitelist(nil)
	if err != nil {
		t.Fatalf("空白名单不应报错: %v", err)
	}
	if len(g.whitelist) != 0 {
		t.Fatalf("空白名单应保持空，got %d entries", len(g.whitelist))
	}
}

func TestWhitelist_BypassAllChecks(t *testing.T) {
	g, err := NewConnGuardWithWhitelist([]string{
		"10.0.0.5",       // 单 IP 自动补 /32
		"192.168.1.0/24", // CIDR
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	// 白名单内 IP：即使已封禁也应放行
	g.BanIP("10.0.0.5", "测试封禁")
	if !g.Check(fakeRemoteConn("10.0.0.5")) {
		t.Fatal("白名单 IP 应完全 bypass 黑名单")
	}
	if !g.Check(fakeRemoteConn("192.168.1.50")) {
		t.Fatal("CIDR 内 IP 应放行")
	}

	// 白名单外 IP：封禁后应拒绝
	g.BanIP("8.8.8.8", "测试封禁")
	if g.Check(fakeRemoteConn("8.8.8.8")) {
		t.Fatal("非白名单 IP 封禁后应被拒绝")
	}
}

func TestWhitelist_DoesNotIncrementConnCount(t *testing.T) {
	g, _ := NewConnGuardWithWhitelist([]string{"10.0.0.0/8"})

	// 白名单连接不计入 connCount
	for i := 0; i < 100; i++ {
		if !g.Check(fakeRemoteConn("10.0.0.5")) {
			t.Fatalf("白名单连接第 %d 次应通过", i)
		}
	}
	if got := g.connCount["10.0.0.5"]; got != 0 {
		t.Fatalf("白名单 IP 连接不应计入 connCount，got %d", got)
	}
}

func TestWhitelist_BanIPProtected(t *testing.T) {
	g, _ := NewConnGuardWithWhitelist([]string{"10.0.0.0/8"})

	g.BanIP("10.0.0.5", "尝试封禁白名单")
	if !g.Check(fakeRemoteConn("10.0.0.5")) {
		t.Fatal("白名单 IP 应免于 BanIP")
	}
	if g.IsBanned("10.0.0.5") {
		t.Fatal("白名单 IP 不应进入黑名单")
	}
}
// 宽松策略：单次/两次异常不封禁，连续 3 次才封禁
func TestLooseBanThreshold(t *testing.T) {
	g := NewConnGuard()

	// 前 2 次异常：不封禁
	g.BanForBadBehavior(fakeRemoteConn("8.8.8.8"), "test1")
	if g.IsBanned("8.8.8.8") {
		t.Fatal("第 1 次异常不应封禁")
	}
	g.BanForBadBehavior(fakeRemoteConn("8.8.8.8"), "test2")
	if g.IsBanned("8.8.8.8") {
		t.Fatal("第 2 次异常不应封禁")
	}

	// 第 3 次异常：封禁
	g.BanForBadBehavior(fakeRemoteConn("8.8.8.8"), "test3")
	if !g.IsBanned("8.8.8.8") {
		t.Fatal("第 3 次异常应封禁")
	}
}

// 登录成功清除异常计数后，重新计数（避免历史抖动误封）
func TestClearMisbehaviorResets(t *testing.T) {
	g := NewConnGuard()

	g.BanForBadBehavior(fakeRemoteConn("1.1.1.1"), "e1")
	g.BanForBadBehavior(fakeRemoteConn("1.1.1.1"), "e2")
	if g.IsBanned("1.1.1.1") {
		t.Fatal("2 次异常不应封禁")
	}

	// 模拟登录成功，清计数
	g.ClearMisbehavior("1.1.1.1")

	// 再连续 3 次才应封禁
	g.BanForBadBehavior(fakeRemoteConn("1.1.1.1"), "e3")
	g.BanForBadBehavior(fakeRemoteConn("1.1.1.1"), "e4")
	if g.IsBanned("1.1.1.1") {
		t.Fatal("清计数后前 2 次不应封禁")
	}
	g.BanForBadBehavior(fakeRemoteConn("1.1.1.1"), "e5")
	if !g.IsBanned("1.1.1.1") {
		t.Fatal("清计数后第 3 次应封禁")
	}
}

// 新参数检查：宽松配置生效
func TestLooseParams(t *testing.T) {
	g := NewConnGuard()
	if g.maxConn < 100 {
		t.Fatalf("maxConn 应宽松 >=100，got %d", g.maxConn)
	}
	if g.minInterval < 500*time.Millisecond {
		t.Fatalf("minInterval 应宽松 >=500ms，got %v", g.minInterval)
	}
	if g.banDuration > 2*time.Minute {
		t.Fatalf("banDuration 应 <=2min，got %v", g.banDuration)
	}
	if g.banThreshold != 3 {
		t.Fatalf("banThreshold 应为 3，got %d", g.banThreshold)
	}
}
