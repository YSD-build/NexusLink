// Package protocol 定义客户端与服务端通信的消息协议
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
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
	Name         string    `json:"name"`
	Type         ProxyType `json:"type"`
	RemotePort   int       `json:"remote_port"`
	LocalAddr    string    `json:"local_addr"`
	LocalPort    int       `json:"local_port"`
}

// NewProxyResp 新建代理响应
type NewProxyResp struct {
	Name       string `json:"name"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

// NewConn 新连接通知
type NewConn struct {
	ProxyName string `json:"proxy_name"`
	ConnID    string `json:"conn_id"`
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
	
	// 消息格式: [1字节类型][4字节长度][payload]
	header := make([]byte, 5)
	header[0] = byte(msgType)
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	
	_, err = conn.Write(append(header, payload...))
	return err
}

// ReadMessage 从连接读取消息
func ReadMessage(conn net.Conn) (*Message, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	
	msgType := MessageType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])
	
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
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
