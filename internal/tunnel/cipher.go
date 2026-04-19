package tunnel

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// 方向別 HKDF ドメイン分離ラベル。
// 先頭16Bはこのプロトコル固有の固定ラベル、末尾1Bで方向（0x01=C→S, 0x02=S→C）を区別する。
// 同一 DH 共有シークレットから独立した2本の鍵を導出するためのドメイン分離。
var hkdfDomainLabel = []byte{0x8d, 0x2e, 0x71, 0x53, 0xc4, 0x0f, 0xba, 0x96, 0x1a, 0xe7, 0x5d, 0x38, 0x29, 0xf0, 0x6c, 0x41}

var (
	infoC2S = append(append([]byte{}, hkdfDomainLabel...), 0x01)
	infoS2C = append(append([]byte{}, hkdfDomainLabel...), 0x02)
)

// ComputeSessionID は両エフェメラル公開鍵と両saltのSHA-256ハッシュを返す。
func ComputeSessionID(clientEphPub, serverEphPub []byte, clientSalt, serverSalt [4]byte) []byte {
	h := sha256.New()
	h.Write(clientEphPub)
	h.Write(serverEphPub)
	h.Write(clientSalt[:])
	h.Write(serverSalt[:])
	return h.Sum(nil)
}

// deriveSessionKeys は X25519 DH 共有シークレットと sessionID から
// HKDF-SHA256 で方向別に独立した2本のセッション鍵を導出する。
// c2sKey は client→server 暗号化、s2cKey は server→client 暗号化に使う。
func deriveSessionKeys(dhShared, sessionID []byte) (c2sKey, s2cKey []byte, err error) {
	c2sKey = make([]byte, 32)
	s2cKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, dhShared, sessionID, infoC2S), c2sKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf c2s key: %w", err)
	}
	if _, err = io.ReadFull(hkdf.New(sha256.New, dhShared, sessionID, infoS2C), s2cKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf s2c key: %w", err)
	}
	return
}

