package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"encrypt-proxy/internal/iobridge"
	"encrypt-proxy/internal/tunnel"

	"github.com/xtaci/smux"
)

func deleteProxyHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
}

// writeResponseToConn はレスポンスをクライアント接続へ書き出す。
// SSE の場合は resp.Write がボディを閉じてしまうため、
// ヘッダーとボディを分けて手動でストリーミングする。
func writeResponseToConn(conn net.Conn, resp *http.Response, isSSE bool) error {
	if isSSE {
		fmt.Fprintf(conn, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		resp.Header.Write(conn) //nolint:errcheck
		fmt.Fprintf(conn, "\r\n")
		io.Copy(conn, resp.Body) //nolint:errcheck
		return nil
	}
	return resp.Write(conn)
}

// handleRequestLoop は conn 上の HTTP リクエストを Keep-Alive でループ処理する。
// TLS パスと平文パスの両方から呼ばれ、conn の型で HTTP/HTTPS を自動判定する。
// initial が非 nil の場合、最初のイテレーションでそのリクエストを使用する（呼び出し元がすでにパース済みの場合）。
func handleRequestLoop(reader *bufio.Reader, conn net.Conn, session *smux.Session, hostPort string, initial *http.Request) {
	_, isTLS := conn.(*tls.Conn)
	plainType, wsType := tunnel.StreamHTTP, tunnel.StreamWS
	if isTLS {
		plainType, wsType = tunnel.StreamHTTPS, tunnel.StreamWSS
	}

	req := initial
	for {
		if req == nil {
			var err error
			req, err = http.ReadRequest(reader)
			if err != nil {
				if err != io.EOF {
					slog.Debug("read request", "err", err)
				}
				return
			}
		}

		isWS := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
		streamType := plainType
		if isWS {
			streamType = wsType
		}

		stream, err := session.OpenStream()
		if err != nil {
			slog.Error("open stream", "err", err)
			return
		}

		hdr := tunnel.StreamHeader{Type: streamType, HostPort: hostPort}
		if err := tunnel.WriteStreamHeader(stream, hdr); err != nil {
			stream.Close()
			slog.Error("write stream header", "err", err)
			return
		}

		deleteProxyHeaders(req.Header)

		if err := req.Write(stream); err != nil {
			stream.Close()
			slog.Error("write request to stream", "err", err)
			return
		}

		if isWS {
			resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 64*1024), req)
			if err != nil {
				stream.Close()
				return
			}
			resp.Write(conn) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode == http.StatusSwitchingProtocols {
				iobridge.Bridge(conn, stream)
			}
			stream.Close()
			return
		}

		resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 64*1024), req)
		if err != nil {
			stream.Close()
			slog.Error("read response from stream", "err", err)
			return
		}

		isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
		writeErr := writeResponseToConn(conn, resp, isSSE)
		resp.Body.Close()
		stream.Close()

		if writeErr != nil {
			return
		}
		if resp.Close || req.Close || isSSE {
			return
		}
		req = nil
	}
}
