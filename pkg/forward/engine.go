// Package forward 高性能转发引擎 - epoll事件驱动
package forward

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"nexuslink/pkg/auth"
	"nexuslink/pkg/compress"
	"nexuslink/pkg/pool"
	"golang.org/x/sys/unix"
)

const (
	// MaxEvents epoll最大事件数
	MaxEvents = 1024
	// ReadBufferSize 读缓冲区大小
	ReadBufferSize = 32 * 1024
	// BatchTimeout 批处理超时
	BatchTimeout = 1 * time.Millisecond
)

// ConnState 连接状态
type ConnState int

const (
	StateNew ConnState = iota
	StateReading
	StateWriting
	StateClosed
)

// ForwardConn 转发连接
type ForwardConn struct {
	fd         int
	conn       net.Conn
	peer       *ForwardConn
	state      ConnState
	auth       *auth.FastAuth
	compressor *compress.Compressor
	readBuf    []byte
	writeBuf   [][]byte
	writeIdx   int
	lastActive int64
}

// Engine 转发引擎
type Engine struct {
	epollFd     int
	conns       map[int]*ForwardConn
	connLock    sync.RWMutex
	bufferPool  *pool.Pool
	workerCount int
	workers     []*Worker
	stats       Stats
	running     int32
}

// Worker 工作协程
type Worker struct {
	id         int
	engine     *Engine
	taskQueue  chan *ForwardConn
	processed  uint64
}

// Stats 引擎统计
type Stats struct {
	TotalConnections uint64
	ActiveConnections uint64
	BytesForwarded    uint64
	PacketsForwarded  uint64
}

// NewEngine 创建转发引擎
func NewEngine(workerCount int) (*Engine, error) {
	// 创建epoll实例
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		epollFd:     epollFd,
		conns:       make(map[int]*ForwardConn),
		bufferPool:  pool.DefaultPool(),
		workerCount: workerCount,
		workers:     make([]*Worker, workerCount),
	}

	// 预热内存池
	e.bufferPool.Warmup(1000)

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		e.workers[i] = &Worker{
			id:        i,
			engine:    e,
			taskQueue: make(chan *ForwardConn, 1024),
		}
		go e.workers[i].run()
	}

	atomic.StoreInt32(&e.running, 1)
	go e.epollLoop()

	return e, nil
}

// AddConnection 添加连接到引擎
func (e *Engine) AddConnection(conn net.Conn, peer *ForwardConn, authenticator *auth.FastAuth, comp *compress.Compressor) (*ForwardConn, error) {
	// 获取文件描述符
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, ErrNotTCPConn
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, err
	}
	fd := int(file.Fd())
	file.Close()

	// 设置非阻塞
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	// 禁用Nagle
	unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	fc := &ForwardConn{
		fd:         fd,
		conn:       conn,
		peer:       peer,
		state:      StateReading,
		auth:       authenticator,
		compressor: comp,
		readBuf:    e.bufferPool.Get(ReadBufferSize).Data,
		lastActive: time.Now().UnixNano(),
	}

	// 注册到epoll
	event := unix.EpollEvent{
		Events: unix.EPOLLIN | unix.EPOLLOUT | unix.EPOLLET,
		Fd:     int32(fd),
	}
	if err := unix.EpollCtl(e.epollFd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		return nil, err
	}

	e.connLock.Lock()
	e.conns[fd] = fc
	e.connLock.Unlock()

	atomic.AddUint64(&e.stats.TotalConnections, 1)
	atomic.AddUint64(&e.stats.ActiveConnections, 1)

	return fc, nil
}

// epollLoop epoll事件循环
func (e *Engine) epollLoop() {
	events := make([]unix.EpollEvent, MaxEvents)

	for atomic.LoadInt32(&e.running) == 1 {
		n, err := unix.EpollWait(e.epollFd, events, int(BatchTimeout.Milliseconds()))
		if err != nil && err != unix.EINTR {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// 批量处理事件
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			e.connLock.RLock()
			fc, ok := e.conns[fd]
			e.connLock.RUnlock()

			if !ok {
				continue
			}

			// 分发到worker
			workerID := fd % e.workerCount
			e.workers[workerID].taskQueue <- fc
		}
	}
}

// run Worker处理循环
func (w *Worker) run() {
	// 设置CPU亲和性
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	batch := make([]*ForwardConn, 0, 64)

	for {
		select {
		case fc := <-w.taskQueue:
			batch = append(batch, fc)

			// 收集一批
		collect:
			for len(batch) < 64 {
				select {
				case fc := <-w.taskQueue:
					batch = append(batch, fc)
				default:
					break collect
				}
			}

			// 处理批量
			for _, fc := range batch {
				w.processConn(fc)
			}
			batch = batch[:0]
			atomic.AddUint64(&w.processed, uint64(len(batch)))
		}
	}
}

// processConn 处理连接事件
func (w *Worker) processConn(fc *ForwardConn) {
	// 读事件
	if fc.state == StateReading {
		w.doRead(fc)
	}

	// 写事件
	if fc.state == StateWriting {
		w.doWrite(fc)
	}
}

// doRead 读取并转发数据
func (w *Worker) doRead(fc *ForwardConn) {
	for {
		n, err := unix.Read(fc.fd, fc.readBuf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break // 没有更多数据
			}
			// 连接关闭
			w.engine.closeConn(fc)
			return
		}

		if n == 0 {
			w.engine.closeConn(fc)
			return
		}

		data := fc.readBuf[:n]

		// 1. 认证验证
		if fc.auth != nil {
			verified, ok := fc.auth.Verify(data)
			if !ok {
				w.engine.closeConn(fc)
				return
			}
			data = verified
		}

		// 2. 解压
		if fc.compressor != nil {
			decompressed, err := fc.compressor.Decompress(data)
			if err != nil {
				continue
			}
			data = decompressed
		}

		// 3. 转发到对端
		if fc.peer != nil {
			// 对端签名
			if fc.peer.auth != nil {
				data = fc.peer.auth.Sign(data)
			}
			// 对端压缩
			if fc.peer.compressor != nil {
				if compressed, ok := fc.peer.compressor.Compress(data); ok {
					data = compressed
				}
			}
			// 写入对端
			fc.peer.writeBuf = append(fc.peer.writeBuf, data)
			fc.peer.state = StateWriting
		}

		atomic.AddUint64(&w.engine.stats.BytesForwarded, uint64(n))
		atomic.AddUint64(&w.engine.stats.PacketsForwarded, 1)
	}

	fc.lastActive = time.Now().UnixNano()
}

// doWrite 批量写入数据
func (w *Worker) doWrite(fc *ForwardConn) {
	for fc.writeIdx < len(fc.writeBuf) {
		data := fc.writeBuf[fc.writeIdx]
		n, err := unix.Write(fc.fd, data)

		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break // 写缓冲区满
			}
			w.engine.closeConn(fc)
			return
		}

		if n < len(data) {
			// 部分写入，剩余下次写
			fc.writeBuf[fc.writeIdx] = data[n:]
			break
		}

		// 完整写入
		fc.writeIdx++
	}

	// 所有数据写完
	if fc.writeIdx >= len(fc.writeBuf) {
		fc.writeBuf = fc.writeBuf[:0]
		fc.writeIdx = 0
		fc.state = StateReading
	}
}

// closeConn 关闭连接
func (e *Engine) closeConn(fc *ForwardConn) {
	e.connLock.Lock()
	delete(e.conns, fc.fd)
	e.connLock.Unlock()

	unix.EpollCtl(e.epollFd, unix.EPOLL_CTL_DEL, fc.fd, nil)
	unix.Close(fc.fd)
	fc.conn.Close()

	// 归还缓冲区
	e.bufferPool.Put(&pool.Buffer{Data: fc.readBuf})

	atomic.AddUint64(&e.stats.ActiveConnections, ^uint64(0))
}

// GetStats 获取统计
func (e *Engine) GetStats() Stats {
	return Stats{
		TotalConnections:  atomic.LoadUint64(&e.stats.TotalConnections),
		ActiveConnections: atomic.LoadUint64(&e.stats.ActiveConnections),
		BytesForwarded:    atomic.LoadUint64(&e.stats.BytesForwarded),
		PacketsForwarded:  atomic.LoadUint64(&e.stats.PacketsForwarded),
	}
}

// Close 关闭引擎
func (e *Engine) Close() {
	atomic.StoreInt32(&e.running, 0)
	unix.Close(e.epollFd)
}

// ErrNotTCPConn 非TCP连接错误
var ErrNotTCPConn = &ForwardError{"not a TCP connection"}

type ForwardError struct {
	msg string
}

func (e *ForwardError) Error() string { return e.msg }
