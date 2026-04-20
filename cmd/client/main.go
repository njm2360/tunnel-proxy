package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"log/slog"
	"math"
	"os"
	"time"

	"encrypt-proxy/internal/cert"
	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/dialer"
	"encrypt-proxy/internal/proxy"
	"encrypt-proxy/internal/tunnel"

	"github.com/redis/go-redis/v9"
	"github.com/xtaci/smux"
)

func main() {
	cfgPath := flag.String("config", "config/client.yaml", "path to client config file")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	setupLogger(cfg.LogLevel)

	serverPubKey, err := tunnel.LoadServerPubKey(cfg.Tunnel.ServerPubKey)
	if err != nil {
		slog.Error("load server pubkey", "err", err)
		os.Exit(1)
	}

	clientIdentity, err := tunnel.LoadClientIdentity(cfg.Tunnel.ClientKey)
	if err != nil {
		slog.Error("load client identity", "err", err)
		os.Exit(1)
	}

	ca, err := cert.LoadOrCreate(cfg.MITM.CACert, cfg.MITM.CAKey)
	if err != nil {
		slog.Error("load/create CA", "err", err)
		os.Exit(1)
	}

	opt, err := redis.ParseURL(cfg.MITM.RedisURL)
	if err != nil {
		slog.Error("parse redis URL", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("redis unavailable", "err", err)
		os.Exit(1)
	}
	defer rdb.Close()

	certCache := cert.NewCache(ca, rdb)

	session := connectWithRetry(cfg, serverPubKey, clientIdentity)
	slog.Info("tunnel established", "server", cfg.Tunnel.ServerAddr)

	handler := proxy.NewHandler(session, certCache)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxy.Serve(cfg.ListenAddr, handler)
	}()

	for {
		select {
		case err := <-proxyErr:
			slog.Error("proxy server error", "err", err)
			return
		case <-session.CloseChan():
			slog.Warn("tunnel disconnected, reconnecting...")
			session = connectWithRetry(cfg, serverPubKey, clientIdentity)
			handler.UpdateSession(session)
			slog.Info("tunnel re-established", "server", cfg.Tunnel.ServerAddr)
		}
	}
}

func connectWithRetry(cfg *config.ClientConfig, serverPubKey ed25519.PublicKey, identity tunnel.ClientIdentity) *smux.Session {
	delay := time.Duration(cfg.Tunnel.ReconnectDelayMS) * time.Millisecond
	maxDelay := time.Duration(cfg.Tunnel.MaxReconnectDelayMS) * time.Millisecond

	for {
		session, err := connect(cfg, serverPubKey, identity)
		if err == nil {
			return session
		}
		slog.Error("connect to server", "err", err, "retry_in", delay)
		time.Sleep(delay)
		delay = time.Duration(math.Min(float64(delay*2), float64(maxDelay)))
	}
}

func connect(cfg *config.ClientConfig, serverPubKey ed25519.PublicKey, identity tunnel.ClientIdentity) (*smux.Session, error) {
	conn, err := dialer.DialTunnel(cfg)
	if err != nil {
		return nil, err
	}

	enc, err := tunnel.ClientHandshake(conn, serverPubKey, identity)
	if err != nil {
		conn.Close()
		if errors.Is(err, tunnel.ErrAuthRejected) {
			slog.Error("authentication rejected by server, check authorized_keys")
			os.Exit(1)
		}
		if errors.Is(err, tunnel.ErrServerAuthFailed) {
			slog.Error("server authentication failed, check server.pub or possible MITM")
			os.Exit(1)
		}
		return nil, err
	}

	session, err := tunnel.NewClient(enc)
	if err != nil {
		enc.Close()
		return nil, err
	}
	return session, nil
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
