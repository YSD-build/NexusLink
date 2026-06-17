// Package pool 高性能内存池实现
package pool

import (
	"sync"
	"sync/atomic"
)

const (
	// Buffer sizes - 分级内存池
	Size4K   = 4 * 1024
	Size16K  = 16 * 1024
	Size64K  = 64 * 1024
	Size256K = 256 * 1024

	// Cache line size for alignment
	CacheLineSize = 64
)

// Buffer 缓存行对齐的缓冲区
type Buffer struct {
	Data []byte
	_    [CacheLineSize]byte // Padding to avoid false sharing
}

// Pool 分级内存池
type Pool struct {
	pool4K   sync.Pool
	pool16K  sync.Pool
	pool64K  sync.Pool
	pool256K sync.Pool

	// 统计
	hit4K   uint64
	hit16K  uint64
	hit64K  uint64
	hit256K uint64
	miss    uint64
}

var defaultPool = &Pool{
	pool4K: sync.Pool{
		New: func() interface{} {
			b := make([]byte, Size4K)
			return &Buffer{Data: b}
		},
	},
	pool16K: sync.Pool{
		New: func() interface{} {
			b := make([]byte, Size16K)
			return &Buffer{Data: b}
		},
	},
	pool64K: sync.Pool{
		New: func() interface{} {
			b := make([]byte, Size64K)
			return &Buffer{Data: b}
		},
	},
	pool256K: sync.Pool{
		New: func() interface{} {
			b := make([]byte, Size256K)
			return &Buffer{Data: b}
		},
	},
}

// DefaultPool 返回默认内存池
func DefaultPool() *Pool {
	return defaultPool
}

// Get 获取合适大小的缓冲区
func (p *Pool) Get(size int) *Buffer {
	switch {
	case size <= Size4K:
		atomic.AddUint64(&p.hit4K, 1)
		return p.pool4K.Get().(*Buffer)
	case size <= Size16K:
		atomic.AddUint64(&p.hit16K, 1)
		return p.pool16K.Get().(*Buffer)
	case size <= Size64K:
		atomic.AddUint64(&p.hit64K, 1)
		return p.pool64K.Get().(*Buffer)
	default:
		atomic.AddUint64(&p.hit256K, 1)
		return p.pool256K.Get().(*Buffer)
	}
}

// Put 归还缓冲区
func (p *Pool) Put(buf *Buffer) {
	capacity := cap(buf.Data)
	switch {
	case capacity <= Size4K:
		p.pool4K.Put(buf)
	case capacity <= Size16K:
		p.pool16K.Put(buf)
	case capacity <= Size64K:
		p.pool64K.Put(buf)
	default:
		p.pool256K.Put(buf)
	}
}

// Warmup 预热内存池
func (p *Pool) Warmup(count int) {
	// 预分配缓冲区
	bufs4K := make([]*Buffer, count)
	bufs16K := make([]*Buffer, count)
	bufs64K := make([]*Buffer, count/2)
	bufs256K := make([]*Buffer, count/4)

	for i := 0; i < count; i++ {
		bufs4K[i] = p.Get(Size4K)
		bufs16K[i] = p.Get(Size16K)
	}
	for i := 0; i < count/2; i++ {
		bufs64K[i] = p.Get(Size64K)
	}
	for i := 0; i < count/4; i++ {
		bufs256K[i] = p.Get(Size256K)
	}

	// 归还
	for i := 0; i < count; i++ {
		p.Put(bufs4K[i])
		p.Put(bufs16K[i])
	}
	for i := 0; i < count/2; i++ {
		p.Put(bufs64K[i])
	}
	for i := 0; i < count/4; i++ {
		p.Put(bufs256K[i])
	}
}

// Stats 返回内存池统计
func (p *Pool) Stats() map[string]uint64 {
	return map[string]uint64{
		"hit_4k":   atomic.LoadUint64(&p.hit4K),
		"hit_16k":  atomic.LoadUint64(&p.hit16K),
		"hit_64k":  atomic.LoadUint64(&p.hit64K),
		"hit_256k": atomic.LoadUint64(&p.hit256K),
		"miss":     atomic.LoadUint64(&p.miss),
	}
}
