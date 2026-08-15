// Package config 配置文件解析
package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	BindAddr    string `yaml:"bind_addr"`
	BindPort    int    `yaml:"bind_port"`
	Token       string `yaml:"token"`
	Clients     []ManagedClient `yaml:"clients"` // 多客户端凭据（可选，配置后按 token 识别客户端身份）
	APIKeys     []string `yaml:"api_keys"`       // 开放 API Key（/api/v1/* 用 X-API-Key 鉴权）
	WebEnable   bool   `yaml:"web_enable"`
	WebAddr     string `yaml:"web_addr"`
	WebPort     int    `yaml:"web_port"`
	WebPassword string `yaml:"web_password"`
	WebTrustProxy bool   `yaml:"web_trust_proxy"` // 仅当部署在可信反向代理后才设 true，才用 X-Forwarded-For 取客户端IP
	WebTLSCert    string `yaml:"web_tls_cert"`   // Web 面板 HTTPS 证书（可选，配置即启用 HTTPS）
	WebTLSKey     string `yaml:"web_tls_key"`
	BindTLSCert   string `yaml:"bind_tls_cert"`  // 隧道 TLS 证书（可选，配置即启用；UDP 数据通道仍为明文）
	BindTLSKey    string `yaml:"bind_tls_key"`
	ProxyACL      ProxyACL `yaml:"proxy_acl"`   // 代理创建访问控制
	Whitelist     []string `yaml:"whitelist"`    // 连接守卫白名单（单 IP 或 CIDR），命中后完全 bypass 检测
}

// ManagedClient 托管客户端凭据（v0.5.0 多租户）
// 配置后：该 token 的客户端登录时被识别为对应客户端身份，可独立计量流量 / 配额管理。
// 未配置 clients 时保持单 token 兼容行为（所有客户端共享主 token）。
type ManagedClient struct {
	Name            string `yaml:"name"`               // 客户端名称（唯一标识）
	Token           string `yaml:"token"`              // 该客户端专属登录 token
	MaxTunnels      int    `yaml:"max_tunnels"`        // 最大隧道数（0=不限）
	MaxTrafficBytes int64  `yaml:"max_traffic_bytes"`  // 流量上限字节（0=不限）
}

// ProxyACL 代理创建访问控制（全部为空时不限制）
type ProxyACL struct {
	AllowNames []string `yaml:"allow_names"` // 代理名正则，匹配才允许
	AllowPorts []int    `yaml:"allow_ports"` // 允许的远程端口，空=不限
}

// ProxyConfig 单个代理配置
type ProxyConfig struct {
	Type      string `yaml:"type"` // tcp or udp
	Port      int    `yaml:"port"` // 远程端口
	LocalAddr string `yaml:"localaddr"`
	LocalPort int    `yaml:"localport"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerIP    string                 `yaml:"server_ip"`
	ServerPort  int                    `yaml:"server_port"`
	Token       string                 `yaml:"token"`
	TLSEnable   bool                   `yaml:"tls_enable"`   // 使用 TLS 连接服务端
	TLSCA       string                 `yaml:"tls_ca"`       // 服务端 CA 证书路径（可选）
	TLSInsecure bool                   `yaml:"tls_insecure"` // 跳过证书校验（自签证书场景）
	Proxies     map[string]ProxyConfig `yaml:"proxies"`
}

// LoadServerConfig 加载服务端配置
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 从环境变量覆盖 WebPassword（如未显式设置）
	if cfg.WebPassword == "" {
		if envPwd := os.Getenv("NEXUSLINK_WEB_PASSWORD"); envPwd != "" {
			cfg.WebPassword = envPwd
		} else {
			cfg.WebPassword = "admin123"
		}
	}

	// 设置默认值
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0"
	}
	if cfg.BindPort == 0 {
		cfg.BindPort = 7000
	}
	// Web面板默认值
	if cfg.WebAddr == "" {
		cfg.WebAddr = "127.0.0.1"
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 7001
	}

	return &cfg, nil
}

// LoadClientConfig 加载并校验客户端配置
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 设置默认值
	if cfg.ServerIP == "" {
		cfg.ServerIP = "127.0.0.1"
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 7000
	}

	// 校验：server_ip 不能是保留地址（除非是本地测试）
	if cfg.ServerIP == "127.0.0.1" || cfg.ServerIP == "::1" {
		// 本地测试允许，不报错
	} else {
		// 尝试解析 server_ip（防止配置错误的域名/地址）
		if _, err := net.ResolveTCPAddr("tcp", cfg.ServerIP+":"+fmt.Sprint(cfg.ServerPort)); err != nil {
			return nil, fmt.Errorf("invalid server_ip '%s': %w", cfg.ServerIP, err)
		}
	}

	// 校验：proxy 端口不能与 server_port 重复
	for name, p := range cfg.Proxies {
		if p.Port == cfg.ServerPort {
			return nil, fmt.Errorf("proxy '%s' port (%d) conflicts with server port (%d)", name, p.Port, cfg.ServerPort)
		}
	}

	return &cfg, nil
}

// DefaultServerConfig 生成默认服务端配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		BindAddr: "0.0.0.0",
		BindPort: 7000,
		Token:    "change_me_to_secure_token",
	}
}

// DefaultClientConfig 生成默认客户端配置
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerIP:   "1.1.1.1",
		ServerPort: 7000,
		Token:      "your_token_here",
		Proxies: map[string]ProxyConfig{
			"mc": {
				Type:      "tcp",
				Port:      25565,
				LocalAddr: "127.0.0.1",
				LocalPort: 25565,
			},
		},
	}
}
