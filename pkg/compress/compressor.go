// Package compress 提供简单的数据压缩功能
package compress

import (
	"bytes"
	"compress/gzip"
	"io"
)

// Compressor 压缩器
type Compressor struct {
	enabled bool
}

// NewCompressor 创建新的压缩器
func NewCompressor(enabled bool) *Compressor {
	return &Compressor{enabled: enabled}
}

// Compress 压缩数据
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	if !c.enabled {
		return data, nil
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(data)
	if err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress 解压数据
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if !c.enabled {
		return data, nil
	}

	buf := bytes.NewBuffer(data)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	return io.ReadAll(gz)
}
