package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	ListenAddr    string              `yaml:"listen_addr"`
	LogLevel      string              `yaml:"log_level"`
	Tunnel        TunnelConfig        `yaml:"tunnel"`
	MITM          MITMConfig          `yaml:"mitm"`
	UpstreamProxy UpstreamProxyConfig `yaml:"upstream_proxy"`
}

type TunnelConfig struct {
	ServerAddr          string          `yaml:"server_addr"`
	ClientKey           string          `yaml:"client_key"`
	ServerPubKey        string          `yaml:"server_pub_key"`
	ReconnectDelayMS    int             `yaml:"reconnect_delay_ms"`
	MaxReconnectDelayMS int             `yaml:"max_reconnect_delay_ms"`
	TLS                 TunnelTLSConfig `yaml:"tls"`
}

// TunnelTLSConfig はトンネルサーバーへの WebSocket 接続の TLS 設定。
// enabled: true で wss:// を使用する。公的 CA 署名のサーバーなら enabled だけでよい。
// 自己署名 CA の場合は ca_cert を、開発用には insecure を併用する。
type TunnelTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`  // wss:// を使うかどうか
	CACert   string `yaml:"ca_cert"`  // サーバー証明書の検証に使う CA 証明書パス（空 = システム CA）
	Insecure bool   `yaml:"insecure"` // 開発用: TLS 証明書検証をスキップ
}

// ローカルHTTPS傍受用のCA証明書設定
type MITMConfig struct {
	CACert   string `yaml:"ca_cert"`
	CAKey    string `yaml:"ca_key"`
	RedisURL string `yaml:"redis_url"`
}

// 上流HTTPプロキシへの接続設定
type UpstreamProxyConfig struct {
	HTTPURL  string `yaml:"http_url"`  // HTTP時に使うプロキシ URL
	HTTPSURL string `yaml:"https_url"` // HTTPS時に使うプロキシ URL
	CACert   string `yaml:"ca_cert"`   // プロキシへのTLS接続に使うカスタムCA証明書パス
	Insecure bool   `yaml:"insecure"`  // プロキシへのTLS証明書検証をスキップ（開発用）
}

type ServerConfig struct {
	ListenAddr    string              `yaml:"listen_addr"`
	LogLevel      string              `yaml:"log_level"`
	AllowedHosts  []string            `yaml:"allowed_hosts"`
	Keys          ServerKeysConfig    `yaml:"keys"`
	TLS           ServerTLSConfig     `yaml:"tls"`
	UpstreamTLS   UpstreamTLSConfig   `yaml:"upstream_tls"`
	UpstreamProxy UpstreamProxyConfig `yaml:"upstream_proxy"`
	Timeouts      ServerTimeoutConfig `yaml:"timeouts"`
}

// UpstreamTLS はプロキシサーバーが上流ターゲットへ TLS 接続する際の設定。
// テスト環境で自己署名証明書を使うターゲットに接続する場合に insecure を使う。
type UpstreamTLSConfig struct {
	Insecure bool `yaml:"insecure"`
}

type ServerKeysConfig struct {
	ServerKey      string `yaml:"server_key"`
	AuthorizedKeys string `yaml:"authorized_keys"`
}

// ServerTLSConfig はクライアントからの WebSocket 接続を wss:// で受ける場合の証明書設定。
// 空の場合は ws://（非 TLS）で動作する。
type ServerTLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ServerTimeoutConfig struct {
	DialMS       int `yaml:"dial_ms"`
	ResponseMS   int `yaml:"response_ms"`
	StreamIdleMS int `yaml:"stream_idle_ms"`
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	setClientDefaults(&cfg)
	return &cfg, validateClient(&cfg)
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	setServerDefaults(&cfg)
	return &cfg, validateServer(&cfg)
}

func setClientDefaults(c *ClientConfig) {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8080"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Tunnel.ClientKey == "" {
		c.Tunnel.ClientKey = "./data/client.key"
	}
	if c.Tunnel.ServerPubKey == "" {
		c.Tunnel.ServerPubKey = "./data/server.pub"
	}
	if c.Tunnel.ReconnectDelayMS == 0 {
		c.Tunnel.ReconnectDelayMS = 1000
	}
	if c.Tunnel.MaxReconnectDelayMS == 0 {
		c.Tunnel.MaxReconnectDelayMS = 30000
	}
	if c.MITM.CACert == "" {
		c.MITM.CACert = "./data/ca.crt"
	}
	if c.MITM.CAKey == "" {
		c.MITM.CAKey = "./data/ca.key"
	}
}

func setServerDefaults(c *ServerConfig) {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:9443"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Keys.ServerKey == "" {
		c.Keys.ServerKey = "./data/server.key"
	}
	if c.Keys.AuthorizedKeys == "" {
		c.Keys.AuthorizedKeys = "./data/authorized_keys"
	}
	if c.Timeouts.DialMS == 0 {
		c.Timeouts.DialMS = 10000
	}
	if c.Timeouts.ResponseMS == 0 {
		c.Timeouts.ResponseMS = 30000
	}
	if c.Timeouts.StreamIdleMS == 0 {
		c.Timeouts.StreamIdleMS = 90000
	}
}

func validateClient(c *ClientConfig) error {
	if c.Tunnel.ServerAddr == "" {
		return fmt.Errorf("tunnel.server_addr is required")
	}
	if c.MITM.RedisURL == "" {
		return fmt.Errorf("mitm.redis_url is required")
	}
	return nil
}

func validateServer(c *ServerConfig) error {
	return nil
}
