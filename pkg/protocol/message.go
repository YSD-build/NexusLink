// Package protocol 定义客户端与服务端通信的消息协议
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// ========== 协议常量 ==========
const (
	// MagicNumber 协议魔数 "NL" (NexusLink)
	MagicNumber uint16 = 0x4E4C

	// ProtocolVersion 协议版本
	ProtocolVersion uint8 = 1

	// HeaderSize 消息头大小：魔数(2) + 版本(1) + 类型(1) + 长度(4) = 8 字节
	HeaderSize = 8

	// MaxMessageSize 最大消息体大小（10MB）
	MaxMessageSize = 10 * 1024 * 1024
)

// MessageType 消息类型
type MessageType byte

const (
	// TypeLogin 登录请求
	TypeLogin MessageType = 0x01
	// TypeLoginResp 登录响应
	TypeLoginResp MessageType = 0x02
	// TypeNewProxy 新建代理请求
	TypeNewProxy MessageType = 0x03
	// TypeNewProxyResp 新建代理响应
	TypeNewProxyResp MessageType = 0x04
	// TypeNewConn 新连接通知
	TypeNewConn MessageType = 0x05
	// TypeCloseProxy 关闭代理
	TypeCloseProxy MessageType = 0x06
	// TypeHeartbeat 心跳
	TypeHeartbeat MessageType = 0x07
	// TypeHeartbeatResp 心跳响应
	TypeHeartbeatResp MessageType = 0x08
	// TypeDataConn 数据通道标识帧（TCP 独立数据连接首帧）
	TypeDataConn MessageType = 0x09

	// maxValidType 最大合法类型值（用于校验）
	maxValidType MessageType = 0x0F
)

// ProxyType 代理类型
type ProxyType string

const (
	// ProxyTCP TCP代理
	ProxyTCP ProxyType = "tcp"
	// ProxyUDP UDP代理
	ProxyUDP ProxyType = "udp"
)

// Login 登录消息
type Login struct {
	Version string `json:"version"`
	Token   string `json:"token"`
}

// LoginResp 登录响应
type LoginResp struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// NewProxy 新建代理请求
type NewProxy struct {
	Name       string    `json:"name"`
	Type       ProxyType `json:"type"`
	RemotePort int       `json:"remote_port"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  int       `json:"local_port"`
}

// NewProxyResp 新建代理响应
type NewProxyResp struct {
	Name        string `json:"name"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	RemotePort  int    `json:"remote_port,omitempty"`
	UDPDataPort int    `json:"udp_data_port,omitempty"` // UDP 独立数据通道端口（仅 type=udp 时下发）
}

// NewConn 新连接通知（server 通知 client 有新 user 连接，并下发独立数据通道端口）
type NewConn struct {
	ProxyName string `json:"proxy_name"`
	ConnID    string `json:"conn_id"`
	DataPort  int    `json:"data_port"` // 独立 TCP 数据通道端口（server 分配，client 据此 dial）
}

// Message 消息封装
type Message struct {
	Type MessageType
	Data []byte
}

// WriteMessage 写入消息到连接
func WriteMessage(conn net.Conn, msgType MessageType, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// 消息格式: [魔数2字节][版本1字节][类型1字节][长度4字节][payload]
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(header[0:2], MagicNumber)
	header[2] = ProtocolVersion
	header[3] = byte(msgType)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))

	_, err = conn.Write(append(header, payload...))
	return err
}

// ReadMessage 从连接读取消息（带安全校验）
func ReadMessage(conn net.Conn) (*Message, error) {
	// ---------- 第一步：读取消息头 ----------
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// ---------- 第二步：校验魔数（第一道关卡）----------
	magic := binary.BigEndian.Uint16(header[0:2])
	if magic != MagicNumber {
		return nil, fmt.Errorf("协议错误: 非法魔数 0x%04x", magic)
	}

	// ---------- 第三步：校验版本（第二道关卡）----------
	version := header[2]
	if version != ProtocolVersion {
		return nil, fmt.Errorf("协议错误: 不支持的版本 %d", version)
	}

	// ---------- 第四步：校验类型（第三道关卡）----------
	msgType := MessageType(header[3])
	if msgType == 0 || msgType > maxValidType {
		return nil, fmt.Errorf("协议错误: 非法消息类型 %d", msgType)
	}

	// ---------- 第五步：校验长度（最关键！第四道关卡）----------
	length := binary.BigEndian.Uint32(header[4:8])
	if length > MaxMessageSize {
		return nil, fmt.Errorf("协议错误: 消息过大 %d 字节（最大允许 %d）", length, MaxMessageSize)
	}

	// ---------- 第六步：确认安全后，才分配内存 ----------
	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, data); err != nil {
			return nil, err
		}
	}

	return &Message{
		Type: msgType,
		Data: data,
	}, nil
}

// ParseMessage 解析消息数据
func ParseMessage[T any](msg *Message) (*T, error) {
	var result T
	err := json.Unmarshal(msg.Data, &result)
	return &result, err
}

// ========== 数据通道封装 ==========

// DataConnIdentify TCP 独立数据连接首帧：client 连上数据端口后发送，server 据此关联 connID。
// 复用在 protocol 消息帧上（TCP 数据通道是流式连接，可用 WriteMessage/ReadMessage）。
type DataConnIdentify struct {
	ConnID string `json:"conn_id"`
}

// UDPEnvelope UDP 数据通道封装（紧凑二进制，因 UDP datagram 有边界，不复用 ReadMessage 的 io.ReadFull）。
// 线格式: [1字节Kind][2字节sidLen大端][sid][payload]
type UDPEnvelope struct {
	Kind      byte   `json:"k"`            // 0x01=reg 握手, 0x02=data, 0x03=bye
	SessionID string `json:"sid"`         // server 分配的 sessionID
	Data      []byte `json:"d,omitempty"` // 用户原始 UDP 负载
}

// UDPMaxPayload 单包负载上限（签名后整体需 ≤ 65507）
const UDPMaxPayload = 65400

// MarshalEnvelope 序列化 UDPEnvelope 为紧凑二进制
func MarshalEnvelope(e UDPEnvelope) []byte {
	sid := []byte(e.SessionID)
	buf := make([]byte, 0, 1+2+len(sid)+len(e.Data))
	buf = append(buf, e.Kind)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(sid)))
	buf = append(buf, l[:]...)
	buf = append(buf, sid...)
	buf = append(buf, e.Data...)
	return buf
}

// UnmarshalEnvelope 解析紧凑二进制，失败返回 (zero, false)
func UnmarshalEnvelope(b []byte) (UDPEnvelope, bool) {
	if len(b) < 3 {
		return UDPEnvelope{}, false
	}
	kind := b[0]
	sidLen := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+sidLen {
		return UDPEnvelope{}, false
	}
	return UDPEnvelope{
		Kind:      kind,
		SessionID: string(b[3 : 3+sidLen]),
		Data:      b[3+sidLen:],
	}, true
}
