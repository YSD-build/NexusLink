// Package auth 提供数据包认证和签名验证功能
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

// GenerateToken 生成随机token
func GenerateToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i * 5) & 0xFF)
	}
	return hex.EncodeToString(b)
}
