// Package store 提供内嵌 SQLite 持久化存储（多租户数据仓库）。
// 使用 modernc.org/sqlite（纯 Go 实现，无 CGO，跨平台可编译）。
//
// 数据表：
//   - clients : 托管客户端凭据（token / 配额 / 流量累计 / 状态）
//   - api_keys: 开放 API 密钥
//   - settings: 键值设置（主 token、Web 密码等）
package store

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 内嵌数据库封装
type Store struct {
	db *sql.DB
	mu sync.Mutex // 串行化写操作（SQLite 单写者）
}

// Client 托管客户端记录
type Client struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Token           string    `json:"token"`
	MaxTunnels      int       `json:"max_tunnels"`
	MaxTrafficBytes int64     `json:"max_traffic_bytes"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
	Status          string    `json:"status"` // active | disabled
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// APIKey API 密钥记录
type APIKey struct {
	Key       string    `json:"key"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// Open 打开（或创建）数据库并初始化表结构
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// SQLite 并发写优化：WAL + busy timeout
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		return nil, fmt.Errorf("init pragma: %w", err)
	}
	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initSchema() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			token TEXT NOT NULL UNIQUE,
			max_tunnels INTEGER NOT NULL DEFAULT 0,
			max_traffic_bytes INTEGER NOT NULL DEFAULT 0,
			bytes_in INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			key TEXT PRIMARY KEY,
			note TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proxies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'tcp',
			remote_port INTEGER NOT NULL,
			local_addr TEXT NOT NULL DEFAULT '127.0.0.1',
			local_port INTEGER NOT NULL,
			client_name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			UNIQUE(client_name, name)
		)`,
	}
	for _, q := range schema {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

func now() string { return time.Now().Format(time.RFC3339) }

// ==================== Clients ====================

// ListClients 列出所有客户端
func (s *Store) ListClients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT id,name,token,max_tunnels,max_traffic_bytes,bytes_in,bytes_out,status,created_at,updated_at FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var created, updated string
		if err := rows.Scan(&c.ID, &c.Name, &c.Token, &c.MaxTunnels, &c.MaxTrafficBytes,
			&c.BytesIn, &c.BytesOut, &c.Status, &created, &updated); err != nil {
			return nil, err
		}
		c.CreatedAt, _ = time.Parse(time.RFC3339, created)
		c.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetClient 按名称查询客户端
func (s *Store) GetClient(name string) (Client, bool, error) {
	var c Client
	var created, updated string
	err := s.db.QueryRow(`SELECT id,name,token,max_tunnels,max_traffic_bytes,bytes_in,bytes_out,status,created_at,updated_at FROM clients WHERE name=?`, name).
		Scan(&c.ID, &c.Name, &c.Token, &c.MaxTunnels, &c.MaxTrafficBytes, &c.BytesIn, &c.BytesOut, &c.Status, &created, &updated)
	if err == sql.ErrNoRows {
		return Client{}, false, nil
	}
	if err != nil {
		return Client{}, false, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return c, true, nil
}

// GetClientByToken 按 token 查询客户端（登录认证用）
func (s *Store) GetClientByToken(token string) (Client, bool, error) {
	var c Client
	var created, updated string
	err := s.db.QueryRow(`SELECT id,name,token,max_tunnels,max_traffic_bytes,bytes_in,bytes_out,status,created_at,updated_at FROM clients WHERE token=? AND status='active'`, token).
		Scan(&c.ID, &c.Name, &c.Token, &c.MaxTunnels, &c.MaxTrafficBytes, &c.BytesIn, &c.BytesOut, &c.Status, &created, &updated)
	if err == sql.ErrNoRows {
		return Client{}, false, nil
	}
	if err != nil {
		return Client{}, false, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return c, true, nil
}

// AddClient 新增客户端
func (s *Store) AddClient(name, token string, maxTunnels int, maxTrafficBytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO clients (name,token,max_tunnels,max_traffic_bytes,status,created_at,updated_at) VALUES (?,?,?,?,'active',?,?)`,
		name, token, maxTunnels, maxTrafficBytes, now(), now())
	return err
}

// DeleteClient 删除客户端
func (s *Store) DeleteClient(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM clients WHERE name=?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateClientQuota 更新客户端配额
func (s *Store) UpdateClientQuota(name string, maxTunnels int, maxTrafficBytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE clients SET max_tunnels=?, max_traffic_bytes=?, updated_at=? WHERE name=?`,
		maxTunnels, maxTrafficBytes, now(), name)
	return err
}

// AddTraffic 累加客户端流量
func (s *Store) AddTraffic(name string, bytesIn, bytesOut int64) error {
	if bytesIn == 0 && bytesOut == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE clients SET bytes_in=bytes_in+?, bytes_out=bytes_out+?, updated_at=? WHERE name=?`,
		bytesIn, bytesOut, now(), name)
	return err
}

// ==================== API Keys ====================

// ListAPIKeys 列出所有 API 密钥
func (s *Store) ListAPIKeys() ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT key,note,created_at FROM api_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var created string
		if err := rows.Scan(&k.Key, &k.Note, &created); err != nil {
			return nil, err
		}
		k.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, k)
	}
	return out, rows.Err()
}

// AddAPIKey 新增 API 密钥
func (s *Store) AddAPIKey(key, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO api_keys (key,note,created_at) VALUES (?,?,?)`, key, note, now())
	return err
}

// DeleteAPIKey 删除 API 密钥
func (s *Store) DeleteAPIKey(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM api_keys WHERE key=?`, key)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// HasAPIKey 检查 API 密钥是否存在（鉴权用）
func (s *Store) HasAPIKey(key string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM api_keys WHERE key=?`, key).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ==================== Proxies（隧道，服务端 DB 驱动） ====================

// Proxy 隧道记录（DB 持久化）
type Proxy struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePort int    `json:"remote_port"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	ClientName string `json:"client_name"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

// CreateProxy 新增隧道（同一客户端的隧道名唯一）
func (s *Store) CreateProxy(p Proxy) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`INSERT INTO proxies (name,type,remote_port,local_addr,local_port,client_name,enabled,created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		p.Name, p.Type, p.RemotePort, p.LocalAddr, p.LocalPort, p.ClientName, boolInt(p.Enabled), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListProxies 列出全部隧道
func (s *Store) ListProxies() ([]Proxy, error) {
	rows, err := s.db.Query(`SELECT id,name,type,remote_port,local_addr,local_port,client_name,enabled,created_at FROM proxies ORDER BY client_name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxies(rows)
}

// ListProxiesByClient 列出指定客户端的启用隧道（客户端同步注册用）
func (s *Store) ListProxiesByClient(clientName string) ([]Proxy, error) {
	rows, err := s.db.Query(`SELECT id,name,type,remote_port,local_addr,local_port,client_name,enabled,created_at FROM proxies WHERE client_name=? AND enabled=1 ORDER BY id`, clientName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxies(rows)
}

// GetProxy 按名称查询隧道（跨客户端）
func (s *Store) GetProxy(name string) (Proxy, bool, error) {
	row := s.db.QueryRow(`SELECT id,name,type,remote_port,local_addr,local_port,client_name,enabled,created_at FROM proxies WHERE name=?`, name)
	p, err := scanProxy(row)
	if err == sql.ErrNoRows {
		return Proxy{}, false, nil
	}
	if err != nil {
		return Proxy{}, false, err
	}
	return p, true, nil
}

// DeleteProxy 删除隧道
func (s *Store) DeleteProxy(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM proxies WHERE name=?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateProxy 更新隧道（按 name 更新可编辑字段；name 本身不可改）
func (s *Store) UpdateProxy(name, typ string, remotePort, localPort int, localAddr string, enabled bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE proxies SET type=?, remote_port=?, local_addr=?, local_port=?, enabled=? WHERE name=?`,
		typ, remotePort, localAddr, localPort, boolInt(enabled), name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetProxyEnabled 启用/停用隧道
func (s *Store) SetProxyEnabled(name string, enabled bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE proxies SET enabled=? WHERE name=?`, boolInt(enabled), name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type proxyScanner interface{ Scan(dest ...any) error }

func scanProxy(row proxyScanner) (Proxy, error) {
	var p Proxy
	var enabled int
	var created string
	if err := row.Scan(&p.ID, &p.Name, &p.Type, &p.RemotePort, &p.LocalAddr, &p.LocalPort, &p.ClientName, &enabled, &created); err != nil {
		return Proxy{}, err
	}
	p.Enabled = enabled == 1
	p.CreatedAt = created
	return p, nil
}

func scanProxies(rows *sql.Rows) ([]Proxy, error) {
	var out []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ==================== Settings ====================

// GetSetting 读取设置
func (s *Store) GetSetting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting 写入设置
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO settings (key,value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
