package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// aead は AEAD 暗号器とステートフルなノンスをまとめた構造体。
// ノンス = 先頭4B（自salt固定）+ 後ろ8B（送信ごとに1増加するカウンター）。
type aead struct {
	c     cipher.AEAD
	nonce [12]byte // salt(4) || counter(8)
	count uint64
}

func newAEAD(c cipher.AEAD, salt [4]byte) *aead {
	a := &aead{c: c}
	copy(a.nonce[:4], salt[:])
	return a
}

func (a *aead) nextNonce() []byte {
	binary.BigEndian.PutUint64(a.nonce[4:], a.count)
	a.count++
	return a.nonce[:]
}

func (a *aead) Seal(plaintext []byte) []byte {
	return a.c.Seal(nil, a.nextNonce(), plaintext, nil)
}

func (a *aead) Open(ciphertext []byte) ([]byte, error) {
	return a.c.Open(nil, a.nextNonce(), ciphertext, nil)
}

func newAES256GCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
