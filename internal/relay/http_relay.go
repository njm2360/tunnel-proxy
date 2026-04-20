package relay

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/tunnel"

	"github.com/xtaci/smux"
)

// handleHTTP は HTTP/HTTPS ストリームを宛先へ中継する。
// 1本の smux ストリームで Keep-Alive を活かしてリクエストをループ処理する。
func handleHTTP(stream *smux.Stream, hdr tunnel.StreamHeader, cfg *config.ServerConfig, dialTimeout, responseTimeout, idleTimeout time.Duration) {
	upstream, err := dialUpstream(hdr, cfg, dialTimeout)
	if err != nil {
		slog.Warn("dial upstream", "target", hdr.HostPort, "err", err)
		writeErrorResponse(stream, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	streamReader := bufio.NewReaderSize(stream, 64*1024)
	upstreamReader := bufio.NewReaderSize(upstream, 64*1024)

	for {
		stream.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(streamReader)
		stream.SetReadDeadline(time.Time{})
		if err != nil {
			if err != io.EOF {
				slog.Debug("read request from stream", "err", err)
			}
			return
		}

		// http.ReadRequest は RequestURI を生のパスとして読むため、
		// upstream への転送前に URL 形式（Host + Scheme 付き）へ変換する。
		req.RequestURI = ""
		if req.URL.Host == "" {
			req.URL.Host = hdr.HostPort
		}
		if hdr.Type == tunnel.StreamHTTPS {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}

		if err := req.Write(upstream); err != nil {
			slog.Error("write request to upstream", "err", err)
			return
		}

		upstream.SetReadDeadline(time.Now().Add(responseTimeout))
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			slog.Error("read response from upstream", "err", err)
			return
		}

		if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			// SSE はボディが無限ストリームのためデッドラインを外してから送信し、ループを抜ける。
			upstream.SetReadDeadline(time.Time{})
			resp.Write(stream) //nolint:errcheck
			resp.Body.Close()
			return
		}

		if err := resp.Write(stream); err != nil {
			slog.Debug("write response to stream", "err", err)
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		// Connection: close または HTTP/1.0 の場合は Keep-Alive しない。
		if resp.Close || req.Close {
			return
		}
	}
}

// dialUpstream は StreamHeader の種別に応じて宛先へ TCP/TLS 接続する。
// allowed_hosts が設定されている場合は許可リスト外の宛先を拒否する。
// upstream_proxy が設定されている場合は HTTP CONNECT 経由で接続する。
func dialUpstream(hdr tunnel.StreamHeader, cfg *config.ServerConfig, timeout time.Duration) (net.Conn, error) {
	if !isHostAllowed(hdr.HostPort, cfg.AllowedHosts) {
		return nil, fmt.Errorf("host not allowed: %s", hdr.HostPort)
	}

	useTLS := hdr.Type == tunnel.StreamHTTPS || hdr.Type == tunnel.StreamWSS
	target := hdr.HostPort
	if !strings.Contains(target, ":") {
		if useTLS {
			target = target + ":443"
		} else {
			target = target + ":80"
		}
	}

	proxyURL := cfg.UpstreamProxy.HTTPURL
	if useTLS {
		proxyURL = cfg.UpstreamProxy.HTTPSURL
	}
	if proxyURL != "" {
		return dialViaProxy(target, useTLS, cfg, timeout)
	}

	if useTLS {
		hostname, _, _ := net.SplitHostPort(target)
		return tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp",
			target,
			&tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: cfg.UpstreamTLS.Insecure,
			},
		)
	}
	return net.DialTimeout("tcp", target, timeout)
}

// writeErrorResponse は smux ストリームに最小限の HTTP エラーレスポンスを書く。
// dial 失敗など上流に接続できない場合にクライアントへエラーを伝えるために使う。
func writeErrorResponse(stream *smux.Stream, code int) {
	resp := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Length": {"0"}},
		Body:       http.NoBody,
	}
	resp.Write(stream) //nolint:errcheck
}

// isHostAllowed は宛先ホストが許可リストに含まれるか確認する。
// allowed が空のときは全宛先を許可する
func isHostAllowed(hostPort string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	for _, a := range allowed {
		if strings.ToLower(a) == host {
			return true
		}
	}
	return false
}
