package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/relay"
	"encrypt-proxy/internal/tunnel"

	"github.com/coder/websocket"
)

func main() {
	cfgPath := flag.String("config", "config/server.yaml", "path to server config file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	setupLogger(cfg.LogLevel)

	serverIdentity, err := tunnel.LoadServerIdentity(cfg.Keys.ServerKey)
	if err != nil {
		slog.Error("load/create server identity", "err", err)
		os.Exit(1)
	}

	authorizedKeys, err := tunnel.LoadAuthorizedKeys(cfg.Keys.AuthorizedKeys)
	if err != nil {
		slog.Error("load authorized_keys", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`)) //nolint:errcheck
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			slog.Debug("websocket accept", "err", err)
			return
		}
		conn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		go handleConn(conn, serverIdentity, authorizedKeys, cfg)
	})

	slog.Info("tunnel server listening", "addr", cfg.ListenAddr)
	var serveErr error
	if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
		slog.Info("TLS enabled", "cert", cfg.TLS.Cert, "key", cfg.TLS.Key)
		serveErr = http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLS.Cert, cfg.TLS.Key, mux)
	} else {
		serveErr = http.ListenAndServe(cfg.ListenAddr, mux)
	}
	if serveErr != nil {
		slog.Error("listen", "err", serveErr)
		os.Exit(1)
	}
}

func handleConn(conn net.Conn, identity tunnel.ServerIdentity, authorizedKeys tunnel.AuthorizedKeys, cfg *config.ServerConfig) {
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	enc, err := tunnel.ServerHandshake(conn, identity, authorizedKeys)
	conn.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		slog.Debug("tunnel handshake rejected", "remote", conn.RemoteAddr(), "err", err)
		conn.Close()
		return
	}
	slog.Info("new tunnel connection", "remote", conn.RemoteAddr())

	session, err := tunnel.NewServerSession(enc)
	if err != nil {
		slog.Error("new server session", "err", err)
		enc.Close()
		return
	}
	defer session.Close()

	relay.Serve(session, cfg)
	slog.Info("tunnel connection closed", "remote", conn.RemoteAddr())
}

func setupLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
