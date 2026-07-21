// Package config 配置文件解析
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	BindAddr    string `yaml:"bind_addr"`
	BindPort    int    `yaml:"bind_port"`
	Token       string `yaml:"token"`
	WebEnable   bool   `yaml:"web_enable"`
	WebAddr     string `yaml:"web_addr"`
	WebPort     int    `yaml:"web_port"`
	WebPassword   string `yaml:"web_password"`
	WebTrustProxy bool   `yaml:"web_trust_proxy"` // 仅当部署在可信反向代理后才设 true，才用 X-Forwarded-For 取客户端IP
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
	ServerIP   string                 `yaml:"server_ip"`
	ServerPort int                    `yaml:"server_port"`
	Token      string                 `yaml:"token"`
	Proxies    map[string]ProxyConfig `yaml:"proxies"`
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
	if cfg.WebPassword == "" {
		cfg.WebPassword = "admin123"
	}

	return &cfg, nil
}

// LoadClientConfig 加载客户端配置
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
