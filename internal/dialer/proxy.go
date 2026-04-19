package dialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/httpconnect"
)

const proxyDialTimeout = 10 * time.Second

func connectTunnelDialer(cfg *config.ClientConfig, proxyRawURL string) func(context.Context, string, string) (net.Conn, error) {
	proxyURL, err := url.Parse(proxyRawURL)
	if err != nil {
		return func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, fmt.Errorf("invalid upstream proxy url: %w", err)
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dial := func() (net.Conn, error) { return dialProxy(cfg, proxyURL) }
		return httpconnect.ConnectViaProxy(dial, cfg.Tunnel.ServerAddr, proxyURL)
	}
}

func dialProxy(cfg *config.ClientConfig, proxyURL *url.URL) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyAddr = proxyURL.Hostname() + ":443"
		} else {
			proxyAddr = proxyURL.Hostname() + ":80"
		}
	}
	if proxyURL.Scheme == "https" {
		p := cfg.UpstreamProxy
		proxyCfg, err := buildTLSConfig(tlsOptions{insecure: p.Insecure, caCert: p.CACert, serverName: proxyURL.Hostname()})
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(&net.Dialer{Timeout: proxyDialTimeout}, "tcp", proxyAddr, proxyCfg)
	}
	return net.DialTimeout("tcp", proxyAddr, proxyDialTimeout)
}
