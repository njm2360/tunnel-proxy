package tunnel

import (
	"bytes"
	"net"
	"time"
)

// EncryptedConn は net.Conn をフレーム単位の AES-256-GCM 暗号化でラップする。
type EncryptedConn struct {
	raw     net.Conn
	enc     *aead
	dec     *aead
	readBuf bytes.Buffer
}

func (c *EncryptedConn) Write(p []byte) (int, error) {
	if err := writeFrame(c.raw, c.enc, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *EncryptedConn) Read(p []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		plaintext, err := readFrame(c.raw, c.dec)
		if err != nil {
			return 0, err
		}
		c.readBuf.Write(plaintext)
	}
	return c.readBuf.Read(p)
}

func (c *EncryptedConn) Close() error                       { return c.raw.Close() }
func (c *EncryptedConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *EncryptedConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *EncryptedConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *EncryptedConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *EncryptedConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
