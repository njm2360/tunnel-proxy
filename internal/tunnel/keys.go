package tunnel

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ClientIdentity はクライアントの Ed25519 鍵ペアを保持する。
type ClientIdentity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// ServerIdentity はサーバーの Ed25519 鍵ペアを保持する。
type ServerIdentity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// AuthorizedKeys は接続を許可するクライアント公開鍵のセット。
// キーは base64 エンコードされた 32B Ed25519 公開鍵。
type AuthorizedKeys map[string]struct{}

// Contains は pubKey が許可リストに含まれるか確認する。
func (ak AuthorizedKeys) Contains(pubKey ed25519.PublicKey) bool {
	_, ok := ak[base64.StdEncoding.EncodeToString(pubKey)]
	return ok
}

// LoadAuthorizedKeys は authorized_keys ファイルを読み込む。
// フォーマット: 1行1キー（base64エンコード32B）、# はコメント、空行は無視。
func LoadAuthorizedKeys(path string) (AuthorizedKeys, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AuthorizedKeys{}, nil
		}
		return nil, fmt.Errorf("open authorized_keys: %w", err)
	}
	defer f.Close()

	ak := make(AuthorizedKeys)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("authorized_keys line %d: invalid base64: %w", lineNum, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authorized_keys line %d: expected %d bytes, got %d", lineNum, ed25519.PublicKeySize, len(raw))
		}
		ak[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read authorized_keys: %w", err)
	}
	return ak, nil
}

// LoadServerIdentity はサーバーの Ed25519 鍵ペアをファイルから読み込む。
// keyPath が存在しない場合はエラーを返す。鍵生成は keygen コマンドで行う。
func LoadServerIdentity(keyPath string) (ServerIdentity, error) {
	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		return ServerIdentity{}, fmt.Errorf("load server key: %w", err)
	}
	return ServerIdentity{
		PublicKey:  priv.Public().(ed25519.PublicKey),
		PrivateKey: priv,
	}, nil
}

// LoadClientIdentity はクライアントの Ed25519 鍵ペアをファイルから読み込む。
// keyPath が存在しない場合はエラーを返す。鍵生成は keygen コマンドで行う。
func LoadClientIdentity(keyPath string) (ClientIdentity, error) {
	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("load client key: %w", err)
	}
	return ClientIdentity{
		PublicKey:  priv.Public().(ed25519.PublicKey),
		PrivateKey: priv,
	}, nil
}

// LoadServerPubKey はファイルから base64 エンコードされたサーバー公開鍵を読み込む。
func LoadServerPubKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server pubkey file: %w", err)
	}
	line := strings.TrimSpace(string(data))
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("decode server pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("server pubkey: expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// GenerateAndSaveKeypair は Ed25519 鍵ペアを生成して保存する。
// basePath.key に PKCS#8 PEM 秘密鍵（0600）、basePath.pub に base64 公開鍵（0644）を書き出す。
func GenerateAndSaveKeypair(basePath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

	// 秘密鍵を PKCS#8 PEM で保存
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(basePath+".key", privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// 公開鍵を base64 で保存
	pubB64 := base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(basePath+".pub", []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}
	return ed, nil
}
