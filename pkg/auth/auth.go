// Package auth 提供数据包认证和签名验证功能
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"time"
)

const (
	// SignatureSize HMAC-SHA256签名大小(32字节)
	SignatureSize = 32
	// TimestampSize 时间戳大小(8字节)
	TimestampSize = 8
	// HeaderSize 认证头总大小
	HeaderSize = SignatureSize + TimestampSize
	// MaxTimeOffset 允许的最大时间偏移(秒)
	MaxTimeOffset = 300
	// LengthPrefixSize 长度前缀大小(4字节,大端uint32)
	LengthPrefixSize = 4
	// FrameHeaderSize 帧头总大小 = 长度前缀 + 签名 + 时间戳
	FrameHeaderSize = LengthPrefixSize + HeaderSize
)

// Auth 认证器
type Auth struct {
	secret []byte
}

// NewAuth 创建新的认证器
func NewAuth(token string) *Auth {
	return &Auth{
		secret: []byte(token),
	}
}

// Sign 为数据生成签名并添加认证头
// 格式: [32字节签名][8字节时间戳][原始数据]
func (a *Auth) Sign(data []byte) []byte {
	timestamp := uint64(time.Now().Unix())

	// 创建时间戳字节
	tsBytes := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(tsBytes, timestamp)

	// 计算HMAC: HMAC(secret, timestamp + data)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(tsBytes)
	mac.Write(data)
	signature := mac.Sum(nil)

	// 组装: signature + timestamp + data
	result := make([]byte, HeaderSize+len(data))
	copy(result[:SignatureSize], signature)
	copy(result[SignatureSize:HeaderSize], tsBytes)
	copy(result[HeaderSize:], data)

	return result
}

// Verify 验证数据包签名并提取原始数据
func (a *Auth) Verify(signedData []byte) ([]byte, bool) {
	if len(signedData) < HeaderSize {
		return nil, false
	}

	// 提取各部分
	receivedSig := signedData[:SignatureSize]
	tsBytes := signedData[SignatureSize:HeaderSize]
	data := signedData[HeaderSize:]

	// 验证时间戳
	timestamp := binary.BigEndian.Uint64(tsBytes)
	now := uint64(time.Now().Unix())
	if timestamp > now+MaxTimeOffset || timestamp < now-MaxTimeOffset {
		return nil, false
	}

	// 重新计算签名
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(tsBytes)
	mac.Write(data)
	expectedSig := mac.Sum(nil)

	// 安全比较(防止时序攻击)
	if !hmac.Equal(receivedSig, expectedSig) {
		return nil, false
	}

	return data, true
}

// SignFramed 生成带长度前缀的签名帧(用于TCP流式传输)
// 格式: [4字节长度(载荷长度)][32字节签名][8字节时间戳][原始数据]
// 长度字段使接收方能够精确读取一个完整帧,避免TCP分包导致的帧同步丢失
func (a *Auth) SignFramed(data []byte) []byte {
	timestamp := uint64(time.Now().Unix())

	tsBytes := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(tsBytes, timestamp)

	mac := hmac.New(sha256.New, a.secret)
	mac.Write(tsBytes)
	mac.Write(data)
	signature := mac.Sum(nil)

	// 组装: [长度][签名][时间戳][数据]
	dataLen := uint32(len(data))
	result := make([]byte, FrameHeaderSize+len(data))
	binary.BigEndian.PutUint32(result[:LengthPrefixSize], dataLen)
	copy(result[LengthPrefixSize:LengthPrefixSize+SignatureSize], signature)
	copy(result[LengthPrefixSize+SignatureSize:FrameHeaderSize], tsBytes)
	copy(result[FrameHeaderSize:], data)

	return result
}

// VerifyFramed 验证带长度前缀的签名帧并提取原始数据
func (a *Auth) VerifyFramed(frame []byte) ([]byte, bool) {
	if len(frame) < FrameHeaderSize {
		return nil, false
	}

	dataLen := binary.BigEndian.Uint32(frame[:LengthPrefixSize])
	if int(dataLen) > len(frame)-FrameHeaderSize {
		return nil, false
	}

	receivedSig := frame[LengthPrefixSize : LengthPrefixSize+SignatureSize]
	tsBytes := frame[LengthPrefixSize+SignatureSize : FrameHeaderSize]
	data := frame[FrameHeaderSize : FrameHeaderSize+int(dataLen)]

	timestamp := binary.BigEndian.Uint64(tsBytes)
	now := uint64(time.Now().Unix())
	if timestamp > now+MaxTimeOffset || timestamp < now-MaxTimeOffset {
		return nil, false
	}

	mac := hmac.New(sha256.New, a.secret)
	mac.Write(tsBytes)
	mac.Write(data)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(receivedSig, expectedSig) {
		return nil, false
	}

	return data, true
}

// ReadFramed 从流中读取一个完整的签名帧并验证
// 返回验证通过的原始数据和可能的错误
func (a *Auth) ReadFramed(r io.Reader) ([]byte, error) {
	// 读取帧头(长度前缀 + 签名 + 时间戳)
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	dataLen := binary.BigEndian.Uint32(header[:LengthPrefixSize])
	// 防止恶意超大长度
	if dataLen > 16*1024*1024 {
		return nil, io.ErrUnexpectedEOF
	}

	// 读取载荷数据
	data := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	}

	// 组装完整帧用于验证
	frame := make([]byte, FrameHeaderSize+int(dataLen))
	copy(frame[:FrameHeaderSize], header)
	copy(frame[FrameHeaderSize:], data)

	payload, ok := a.VerifyFramed(frame)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return payload, nil
}

// GenerateToken 生成随机token
func GenerateToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i * 5) & 0xFF)
	}
	return hex.EncodeToString(b)
}
