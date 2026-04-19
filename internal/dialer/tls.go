package dialer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type tlsOptions struct {
	insecure   bool
	caCert     string
	serverName string // 空文字の場合は設定しない
}

func buildTLSConfig(opt tlsOptions) (*tls.Config, error) {
	if !opt.insecure && opt.caCert == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{ServerName: opt.serverName}
	if opt.insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if opt.caCert != "" {
		pool, err := loadCACertPool(opt.caCert)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func loadCACertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certs in %s", path)
	}
	return pool, nil
}
