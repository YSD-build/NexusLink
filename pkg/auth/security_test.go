package auth

import (
	"bytes"
	"crypto/hmac"
	"testing"
	"time"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	a := NewAuth("secret-token")
	data := []byte("hello nexuslink")
	signed := a.Sign(data)
	got, ok := a.Verify(signed)
	if !ok {
		t.Fatal("valid signature rejected")
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, data)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	a := NewAuth("secret-token")
	signed := a.Sign([]byte("payload"))
	signed[0] ^= 0xFF // 篡改签名首字节
	if _, ok := a.Verify(signed); ok {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	a := NewAuth("secret-token")
	signed := a.Sign([]byte("payload"))
	signed[HeaderSize] ^= 0xFF // 篡改负载首字节（HeaderSize 之后）
	if _, ok := a.Verify(signed); ok {
		t.Fatal("tampered payload accepted")
	}
}

func TestVerifyRejectsStaleTimestamp(t *testing.T) {
	a := NewAuth("secret-token")
	signed := a.Sign([]byte("payload"))
	// 时间戳改到 1 小时前（超过 MaxTimeOffset=300s）
	old := uint64(time.Now().Unix()) - 3600
	var ts [8]byte
	for i := 0; i < 8; i++ {
		ts[i] = byte(old >> (8 * (7 - i)))
	}
	copy(signed[SignatureSize:SignatureSize+TimestampSize], ts[:])
	if _, ok := a.Verify(signed); ok {
		t.Fatal("stale timestamp accepted")
	}
}

func TestVerifyRejectsFutureTimestamp(t *testing.T) {
	a := NewAuth("secret-token")
	signed := a.Sign([]byte("payload"))
	future := uint64(time.Now().Unix()) + 3600
	var ts [8]byte
	for i := 0; i < 8; i++ {
		ts[i] = byte(future >> (8 * (7 - i)))
	}
	copy(signed[SignatureSize:SignatureSize+TimestampSize], ts[:])
	if _, ok := a.Verify(signed); ok {
		t.Fatal("future timestamp accepted")
	}
}

func TestVerifyRejectsAnySignatureByteTamper(t *testing.T) {
	// 逐字节篡改签名，必须全部被拒（配合 hmac.Equal 恒定时间比较）
	a := NewAuth("secret-token")
	signed := a.Sign([]byte("x"))
	for i := 0; i < SignatureSize; i++ {
		bad := make([]byte, len(signed))
		copy(bad, signed)
		bad[i] ^= 0x01
		if _, ok := a.Verify(bad); ok {
			t.Fatalf("tampered signature byte %d accepted", i)
		}
	}
	_ = hmac.Equal
}
