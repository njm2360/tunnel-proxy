package proxy

import (
	"bufio"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"encrypt-proxy/internal/cert"
	"github.com/xtaci/smux"
)

// Handler はブラウザからのリクエストを暗号化トンネル経由でサーバーへ転送する
// HTTP プロキシハンドラー。
//
// session は atomic.Pointer で保持するため、リスナーを止めずに
// 再接続後の新しいセッションへ切り替えられる（ホットスワップ）。
type Handler struct {
	session   atomic.Pointer[smux.Session] // ホットスワップ可能なトンネルセッション
	certCache *cert.Cache                  // HTTPS MITM 用のリーフ証明書キャッシュ
}

// NewHandler は smux セッションと証明書キャッシュを受け取りハンドラーを生成する。
func NewHandler(session *smux.Session, certCache *cert.Cache) *Handler {
	h := &Handler{certCache: certCache}
	h.session.Store(session)
	return h
}

// UpdateSession はトンネルセッションをアトミックに差し替える。
// 再接続後に呼ぶことで、プロキシリスナーを再起動せずに新セッションへ切り替わる。
// 切り替え前に処理中のリクエストは旧セッションを使い続け、安全に完了する。
func (h *Handler) UpdateSession(session *smux.Session) {
	h.session.Store(session)
}

// Serve は指定アドレスでローカル HTTP プロキシサーバーを起動する。
func Serve(addr string, handler *Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("local proxy listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handler.handleConn(conn)
	}
}

func (h *Handler) handleConn(rawConn net.Conn) {
	defer rawConn.Close()
	reader := bufio.NewReaderSize(rawConn, 64*1024)

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	session := h.session.Load()

	if req.Method == http.MethodConnect {
		rawConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) //nolint:errcheck
		hostPort := normalizeHostPort(req.Host, "443")

		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		firstByte, peekErr := reader.Peek(1)
		rawConn.SetReadDeadline(time.Time{}) //nolint:errcheck

		isTLS := peekErr == nil && len(firstByte) > 0 && firstByte[0] == 0x16
		if !isTLS {
			handleRequestLoop(reader, rawConn, session, hostPort, nil)
			return
		}

		tlsCfg := h.certCache.TLSConfig()
		tlsConn := tls.Server(&bufReaderConn{Conn: rawConn, r: reader}, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			slog.Error("MITM TLS handshake", "host", req.Host, "err", err)
			return
		}
		defer tlsConn.Close()
		tlsReader := bufio.NewReaderSize(tlsConn, 64*1024)
		handleRequestLoop(tlsReader, tlsConn, session, hostPort, nil)
	} else {
		hostPort := normalizeHostPort(req.Host, "80")
		handleRequestLoop(reader, rawConn, session, hostPort, req)
	}
}

func normalizeHostPort(host, defaultPort string) string {
	if !strings.Contains(host, ":") {
		return host + ":" + defaultPort
	}
	return host
}

type bufReaderConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufReaderConn) Read(p []byte) (int, error) { return c.r.Read(p) }
