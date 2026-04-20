package relay

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/proxytunnel"
)

// dialViaProxy は HTTP CONNECT でプロキシを経由して target へ接続する。
// useTLS が true の場合は HTTPSURL、false の場合は HTTPURL のプロキシを使用する。
// トンネル確立後、useTLS が true なら TLS ハンドシェイクを行う。
func dialViaProxy(target string, useTLS bool, cfg *config.ServerConfig, timeout time.Duration) (net.Conn, error) {
	rawURL := cfg.UpstreamProxy.HTTPURL
	if useTLS {
		rawURL = cfg.UpstreamProxy.HTTPSURL
	}
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy url: %w", err)
	}

	dial := func() (net.Conn, error) {
		proxyAddr := proxyURL.Host
		if proxyURL.Port() == "" {
			if proxyURL.Scheme == "https" {
				proxyAddr = proxyURL.Hostname() + ":443"
			} else {
				proxyAddr = proxyURL.Hostname() + ":80"
			}
		}
		if proxyURL.Scheme == "https" {
			proxyCfg, err := buildProxyTLSConfig(cfg, proxyURL.Hostname())
			if err != nil {
				return nil, err
			}
			return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", proxyAddr, proxyCfg)
		}
		return net.DialTimeout("tcp", proxyAddr, timeout)
	}

	conn, err := proxytunnel.Dial(dial, target, proxyURL)
	if err != nil {
		return nil, err
	}

	if useTLS {
		hostname, _, _ := net.SplitHostPort(target)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: cfg.UpstreamTLS.Insecure, //nolint:gosec
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake with upstream: %w", err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

// buildProxyTLSConfig はプロキシへの TLS 接続用の設定を組み立てる。
func buildProxyTLSConfig(cfg *config.ServerConfig, serverName string) (*tls.Config, error) {
	p := cfg.UpstreamProxy
	tlsCfg := &tls.Config{ServerName: serverName}
	if p.Insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}
	if p.CACert != "" {
		pem, err := os.ReadFile(p.CACert)
		if err != nil {
			return nil, fmt.Errorf("read proxy CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs in %s", p.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
