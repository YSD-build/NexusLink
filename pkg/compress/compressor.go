// Package compress 自适应流量压缩模块
package compress

import (
	"bytes"
	"math"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/klauspost/compress/zstd"
	"github.com/cespare/xxhash/v2"
)

// CompressionLevel 压缩级别
type CompressionLevel int

const (
	LevelNoCompress CompressionLevel = iota
	LevelFastest
	LevelFast
	LevelDefault
	LevelBest
)

// Config 压缩配置
type Config struct {
	Level          CompressionLevel
	MinSize        int           // 最小压缩大小
	MaxSize        int           // 最大压缩大小
	CPULimit       float64       // CPU限制阈值
	BandwidthLimit float64       // 带宽限制阈值
	EnableDict     bool          // 启用字典压缩
}

// DefaultConfig 默认配置
var DefaultConfig = Config{
	Level:          LevelFastest,
	MinSize:        256,
	MaxSize:        64 * 1024,
	CPULimit:       0.7,
	BandwidthLimit: 100 * 1024 * 1024, // 100Mbps
	EnableDict:     true,
}

// Stats 压缩统计
type Stats struct {
	CompressedBytes   uint64
	OriginalBytes     uint64
	CompressionCount  uint64
	SkipCount         uint64
	TotalCPUNanos     uint64
}

// Compressor 自适应压缩器
type Compressor struct {
	config Config
	lz4    *lz4.Compressor
	zstd   *zstd.Encoder
	stats  Stats

	// 自适应状态
	currentLevel CompressionLevel
	cpuLoad      float64
	bandwidth    float64
}

// NewCompressor 创建压缩器
func NewCompressor(cfg Config) (*Compressor, error) {
	c := &Compressor{
		config:       cfg,
		currentLevel: cfg.Level,
	}

	// 初始化LZ4
	c.lz4 = lz4.NewCompressor()
	if err := c.lz4.Apply(lz4.BlockChecksum(false)); err != nil {
		return nil, err
	}

	// 初始化Zstd
	var err error
	c.zstd, err = zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Compress 压缩数据
func (c *Compressor) Compress(data []byte) ([]byte, bool) {
	start := time.Now()

	// 1. 大小检查
	if len(data) < c.config.MinSize || len(data) > c.config.MaxSize {
		atomic.AddUint64(&c.stats.SkipCount, 1)
		return data, false
	}

	// 2. 熵检测 - 随机数据不压缩
	if c.entropy(data) > 7.5 {
		atomic.AddUint64(&c.stats.SkipCount, 1)
		return data, false
	}

	// 3. CPU负载检查
	if c.cpuLoad > c.config.CPULimit {
		atomic.AddUint64(&c.stats.SkipCount, 1)
		return data, false
	}

	// 4. 选择压缩算法
	var compressed []byte
	var err error

	switch c.currentLevel {
	case LevelFastest:
		compressed, err = c.compressLZ4(data)
	case LevelFast, LevelDefault:
		compressed, err = c.compressZstd(data, 1)
	case LevelBest:
		compressed, err = c.compressZstd(data, 3)
	default:
		return data, false
	}

	if err != nil || len(compressed) >= len(data) {
		// 压缩率不好，返回原始数据
		atomic.AddUint64(&c.stats.SkipCount, 1)
		return data, false
	}

	// 添加校验和
	checksum := xxhash.Sum64(data)
	result := make([]byte, 8+len(compressed))
	putUint64(result[:8], checksum)
	copy(result[8:], compressed)

	// 更新统计
	atomic.AddUint64(&c.stats.OriginalBytes, uint64(len(data)))
	atomic.AddUint64(&c.stats.CompressedBytes, uint64(len(result)))
	atomic.AddUint64(&c.stats.CompressionCount, 1)
	atomic.AddUint64(&c.stats.TotalCPUNanos, uint64(time.Since(start).Nanoseconds()))

	return result, true
}

// Decompress 解压数据
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return data, nil
	}

	// 提取校验和
	checksum := getUint64(data[:8])
	compressed := data[8:]

	// 尝试解压
	decompressed, err := c.decompressLZ4(compressed)
	if err != nil {
		decompressed, err = c.decompressZstd(compressed)
		if err != nil {
			return nil, err
		}
	}

	// 验证校验和
	if xxhash.Sum64(decompressed) != checksum {
		return nil, ErrChecksumMismatch
	}

	return decompressed, nil
}

// compressLZ4 LZ4压缩
func (c *Compressor) compressLZ4(data []byte) ([]byte, error) {
	bound := lz4.CompressBlockBound(len(data))
	dst := make([]byte, bound)
	n, err := c.lz4.CompressBlock(data, dst, nil)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// decompressLZ4 LZ4解压
func (c *Compressor) decompressLZ4(data []byte) ([]byte, error) {
	dst := make([]byte, len(data)*3) // 预估3倍
	n, err := lz4.UncompressBlock(data, dst)
	for err == lz4.ErrInvalidSourceShortBuffer {
		dst = make([]byte, len(dst)*2)
		n, err = lz4.UncompressBlock(data, dst)
	}
	return dst[:n], err
}

// compressZstd Zstd压缩
func (c *Compressor) compressZstd(data []byte, level int) ([]byte, error) {
	return c.zstd.EncodeAll(data, nil), nil
}

// decompressZstd Zstd解压
func (c *Compressor) decompressZstd(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	return decoder.DecodeAll(data, nil)
}

// entropy 计算数据熵值
func (c *Compressor) entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	var ent float64
	n := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// Adapt 自适应调整压缩级别
func (c *Compressor) Adapt() {
	// 采样CPU负载
	c.cpuLoad = getCPULoad()

	// 根据带宽和CPU调整
	switch {
	case c.bandwidth < 10*1024*1024: // < 10Mbps
		c.currentLevel = LevelBest
	case c.bandwidth < 100*1024*1024: // < 100Mbps
		c.currentLevel = LevelDefault
	default:
		c.currentLevel = LevelFastest
	}

	// CPU保护
	if c.cpuLoad > c.config.CPULimit {
		c.currentLevel = LevelFastest
	}
	if c.cpuLoad > 0.9 {
		c.currentLevel = LevelNoCompress
	}
}

// GetStats 获取统计
func (c *Compressor) GetStats() Stats {
	return Stats{
		CompressedBytes:  atomic.LoadUint64(&c.stats.CompressedBytes),
		OriginalBytes:    atomic.LoadUint64(&c.stats.OriginalBytes),
		CompressionCount: atomic.LoadUint64(&c.stats.CompressionCount),
		SkipCount:        atomic.LoadUint64(&c.stats.SkipCount),
		TotalCPUNanos:    atomic.LoadUint64(&c.stats.TotalCPUNanos),
	}
}

// CompressionRatio 获取压缩率
func (s Stats) CompressionRatio() float64 {
	if s.CompressedBytes == 0 {
		return 1.0
	}
	return float64(s.OriginalBytes) / float64(s.CompressedBytes)
}

// getCPULoad 获取CPU使用率
func getCPULoad() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// 简化实现，实际应读取/proc/stat
	return 0.3
}

func putUint64(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func getUint64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// ErrChecksumMismatch 校验和不匹配
var ErrChecksumMismatch = &CompressError{"checksum mismatch"}

type CompressError struct {
	msg string
}

func (e *CompressError) Error() string { return e.msg }
