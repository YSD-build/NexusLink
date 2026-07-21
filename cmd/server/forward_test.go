package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"nexuslink/pkg/auth"
)

// TestForwardWithAuthDropsTamperedPacket 验证数据通道收到被篡改的签名包时，
// forwardWithAuth 会拒绝（不把数据写入用户连接）并关闭连接。这是“数据安全”维度的集成验证。
func TestForwardWithAuthDropsTamperedPacket(t *testing.T) {
	userConn, srvUser := net.Pipe()
	cliConn, srvCli := net.Pipe()
	defer userConn.Close()
	defer cliConn.Close()

	s := &Server{auth: auth.NewAuth("test_token_123")}

	done := make(chan struct{})
	go func() {
		s.forwardWithAuth(srvUser, srvCli, "t1")
		close(done)
	}()

	// 作为“client”发送一个被篡改的签名包（篡改签名首字节）
	good := s.auth.Sign([]byte("secret-data"))
	tampered := make([]byte, len(good))
	copy(tampered, good)
	tampered[0] ^= 0xFF
	_, _ = cliConn.Write(tampered)

	// forwardWithAuth 应因 Verify 失败而退出（篡改被拒绝 -> 连接关闭）
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forwardWithAuth 未在超时内退出（篡改未被拒绝）")
	}

	// 用户侧绝不应收到明文 “secret-data”（允许 EOF/超时，绝不允许明文透传）
	buf := make([]byte, 64)
	userConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _ := userConn.Read(buf)
	if n > 0 && bytes.Contains(buf[:n], []byte("secret-data")) {
		t.Fatalf("篡改数据泄露到用户连接: %q", buf[:n])
	}
}

// TestForwardWithAuthPassesValidPacket 验证合法签名包能正常透传，且用户侧收到明文。
func TestForwardWithAuthPassesValidPacket(t *testing.T) {
	userConn, srvUser := net.Pipe()
	cliConn, srvCli := net.Pipe()
	defer userConn.Close()
	defer cliConn.Close()

	s := &Server{auth: auth.NewAuth("test_token_123")}
	go s.forwardWithAuth(srvUser, srvCli, "t2")

	// client 发送合法签名包
	signed := s.auth.Sign([]byte("hello-pipe"))
	_, _ = cliConn.Write(signed)

	buf := make([]byte, 64)
	userConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := userConn.Read(buf)
	if err != nil {
		t.Fatalf("合法包读取失败: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("hello-pipe")) {
		t.Fatalf("合法包透传错误: %q", buf[:n])
	}
}
