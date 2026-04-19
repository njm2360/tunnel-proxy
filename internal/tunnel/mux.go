package tunnel

import (
	"net"
	"time"

	"github.com/xtaci/smux"
)

func smuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	cfg.MaxFrameSize = 32 * 1024
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	return cfg
}

func NewClientSession(conn net.Conn) (*smux.Session, error) {
	return smux.Client(conn, smuxConfig())
}

func NewServerSession(conn net.Conn) (*smux.Session, error) {
	return smux.Server(conn, smuxConfig())
}
