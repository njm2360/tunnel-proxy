package relay

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/tunnel"

	"github.com/xtaci/smux"
)

func Serve(session *smux.Session, cfg *config.ServerConfig) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if !session.IsClosed() && !isConnReset(err) {
				slog.Error("accept stream", "err", err)
			} else {
				slog.Debug("accept stream closed", "err", err)
			}
			return
		}
		go handleStream(stream, cfg)
	}
}

func isConnReset(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr *net.OpError
	return errors.As(err, &netErr)
}

func handleStream(stream *smux.Stream, cfg *config.ServerConfig) {
	defer stream.Close()

	hdr, err := tunnel.ReadStreamHeader(stream)
	if err != nil {
		slog.Error("read stream header", "err", err)
		return
	}

	dialTimeout := time.Duration(cfg.Timeouts.DialMS) * time.Millisecond
	responseTimeout := time.Duration(cfg.Timeouts.ResponseMS) * time.Millisecond
	idleTimeout := time.Duration(cfg.Timeouts.StreamIdleMS) * time.Millisecond

	switch hdr.Type {
	case tunnel.StreamHTTP, tunnel.StreamHTTPS:
		handleHTTP(stream, hdr, cfg, dialTimeout, responseTimeout, idleTimeout)
	case tunnel.StreamWS, tunnel.StreamWSS:
		handleWebSocket(stream, hdr, cfg, dialTimeout)
	default:
		slog.Warn("unknown stream type", "type", hdr.Type)
	}
}
