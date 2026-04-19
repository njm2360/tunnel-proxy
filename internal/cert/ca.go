package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CA はローカル MITM 用の CA 証明書と秘密鍵を保持する。
// クライアントプロキシが HTTPS を傍受するとき、この CA でリーフ証明書を動的に発行する。
// ブラウザに信頼させるにはこの CA をシステムの信頼ストアへ登録する必要がある。
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey
}

// LoadOrCreate はディスク上の CA ファイルを読み込む。
// ファイルが存在しない場合は新規生成してディスクに保存する。
// 初回起動時のみ生成が走り、以後は既存ファイルを再利用する。
func LoadOrCreate(certPath, keyPath string) (*CA, error) {
	certPEM, errCert := os.ReadFile(certPath)
	keyPEM, errKey := os.ReadFile(keyPath)

	if errCert == nil && errKey == nil {
		return parsePEM(certPEM, keyPEM)
	}

	return generate(certPath, keyPath)
}

// parsePEM は PEM エンコードされた証明書と秘密鍵をパースする。
// 秘密鍵は PKCS#8 形式で保存されているため ParsePKCS8PrivateKey を使う。
// PKCS#8 はアルゴリズム情報を含む汎用フォーマットで、ECDSA/RSA どちらも格納できる。
func parsePEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in key file")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	// PKCS#8 は any 型で返るため ECDSA へキャストして確認する。
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA")
	}
	return &CA{Cert: cert, CertPEM: certPEM, Key: key}, nil
}

func generate(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Encrypt-Proxy Local CA",
			Organization: []string{"Encrypt-Proxy"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// 自己署名
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 秘密鍵を PKCS#8 形式で保存する。
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// パーミッション 0600: 所有者のみ読み書き可能。秘密鍵の漏洩を防ぐ。
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	parsed, _ := x509.ParseCertificate(certDER)

	fmt.Println("=== CA証明書を生成しました ===")
	fmt.Printf("証明書ファイル: %s\n\n", certPath)

	return &CA{Cert: parsed, CertPEM: certPEM, Key: key}, nil
}
