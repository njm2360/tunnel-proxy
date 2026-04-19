package dialer

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"encrypt-proxy/internal/config"

	"github.com/coder/websocket"
)

func DialTunnel(cfg *config.ClientConfig) (net.Conn, error) {
	useTLS := cfg.Tunnel.TLS.Enabled
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	wsURL := scheme + "://" + cfg.Tunnel.ServerAddr
	ctx := context.Background()

	t := cfg.Tunnel.TLS
	tlsCfg, err := buildTLSConfig(tlsOptions{insecure: t.Insecure, caCert: t.CACert})
	if err != nil {
		return nil, fmt.Errorf("build TLS config: %w", err)
	}

	// スキームに応じてプロキシURLを選択
	proxyRawURL := cfg.UpstreamProxy.HTTPURL
	if useTLS {
		proxyRawURL = cfg.UpstreamProxy.HTTPSURL
	}

	opts := &websocket.DialOptions{}
	if proxyRawURL != "" {
		// 上流プロキシあり: CONNECT経由でWebSocketを張る。
		// DialContextを差し替えることで透過的にプロキシ越えを実現する
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				DialContext:     connectTunnelDialer(cfg, proxyRawURL),
				TLSClientConfig: tlsCfg,
			},
		}
	} else if useTLS {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}

	c, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	// WebSocketコネクションをnet.Connインターフェースに変換する
	// 上位層（tunnel パッケージ）はWebSocketを意識せずRead/Writeできる
	return websocket.NetConn(ctx, c, websocket.MessageBinary), nil
}
