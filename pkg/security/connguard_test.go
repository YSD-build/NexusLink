package security

import (
	"net"
	"testing"
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