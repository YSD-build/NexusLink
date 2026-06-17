// Package config 配置文件解析
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	BindAddr string `yaml:"bind_addr"`
	BindPort int    `yaml:"bind_port"`
	Token    string `yaml:"token"`
}

// ProxyConfig 单个代理配置
type ProxyConfig struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"` // tcp or udp
	RemotePort int    `yaml:"remote_port"`
	LocalAddr  string `yaml:"local_addr"`
	LocalPort  int    `yaml:"local_port"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerAddr string         `yaml:"server_addr"`
	ServerPort int            `yaml:"server_port"`
	Token      string         `yaml:"token"`
	Proxies    []ProxyConfig  `yaml:"proxies"`
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
	if cfg.ServerAddr == "" {
		cfg.ServerAddr = "127.0.0.1"
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
		ServerAddr: "127.0.0.1",
		ServerPort: 7000,
		Token:      "change_me_to_secure_token",
		Proxies: []ProxyConfig{
			{
				Name:       "ssh",
				Type:       "tcp",
				RemotePort: 6000,
				LocalAddr:  "127.0.0.1",
				LocalPort:  22,
			},
		},
	}
}
