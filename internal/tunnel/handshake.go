package tunnel

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
)

// ErrAuthRejected はサーバーがクライアントの認証を拒否したことを示す永続的なエラー。
// リトライしても解決しないため、呼び出し元は即座に終了すべき。
var ErrAuthRejected = errors.New("authentication rejected by server")

// ErrServerAuthFailed はサーバーの Ed25519 署名検証に失敗したことを示す永続的なエラー。
// server.pub の設定ミスか MITM の可能性があり、リトライしても解決しない。
var ErrServerAuthFailed = errors.New("server authentication failed: wrong server pubkey or MITM")

func ClientHandshake(conn net.Conn, serverPubKey ed25519.PublicKey, identity ClientIdentity) (*EncryptedConn, error) {
	clientSalt, err := randomSalt()
	if err != nil {
		return nil, fmt.Errorf("gen salt: %w", err)
	}

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen X25519 key: %w", err)
	}
	clientEphPub := priv.PublicKey().Bytes()

	// Phase 1 送信: [32B client pubkey][4B client salt][32B stealth MAC]
	stealthMAC := computeStealthMAC(serverPubKey, clientEphPub, clientSalt)
	msg := make([]byte, 0, 68)
	msg = append(msg, clientEphPub...)
	msg = append(msg, clientSalt[:]...)
	msg = append(msg, stealthMAC...)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("send handshake: %w", err)
	}

	// Phase 1 受信: [32B server pubkey][4B server salt]
	var serverMsg [36]byte
	if _, err := io.ReadFull(conn, serverMsg[:]); err != nil {
		return nil, fmt.Errorf("recv server handshake: %w", err)
	}
	serverEphPub := serverMsg[:32]
	var serverSalt [4]byte
	copy(serverSalt[:], serverMsg[32:])

	sessionID, c2sKey, s2cKey, err := performKeyExchange(priv, serverEphPub, clientEphPub, serverEphPub, clientSalt, serverSalt)
	if err != nil {
		return nil, err
	}

	enc, dec, err := setupAEADs(c2sKey, s2cKey, clientSalt, serverSalt)
	if err != nil {
		return nil, err
	}

	// Phase 2 受信: サーバーのEd25519署名を検証
	serverSigFrame, err := readFrame(conn, dec)
	if err != nil {
		return nil, fmt.Errorf("recv server sig: %w", err)
	}
	if err := verifyServerSig(serverSigFrame, serverPubKey, sessionID); err != nil {
		return nil, ErrServerAuthFailed
	}

	// Phase 2 送信: クライアント公開鍵（32B）+ クライアント署名（64B）
	clientSig := ed25519.Sign(identity.PrivateKey, sessionID)
	payload := make([]byte, 0, ed25519.PublicKeySize+ed25519.SignatureSize)
	payload = append(payload, identity.PublicKey...)
	payload = append(payload, clientSig...)
	if err := writeFrame(conn, enc, payload); err != nil {
		return nil, fmt.Errorf("send client auth: %w", err)
	}

	// Phase 3 受信: サーバーからの認証 ACK を待つ
	// ACK が来ない（接続が閉じられた）場合はサーバーが認証を拒否したことを示す
	if _, err := readFrame(conn, dec); err != nil {
		return nil, ErrAuthRejected
	}

	return &EncryptedConn{raw: conn, enc: enc, dec: dec}, nil
}

func ServerHandshake(conn net.Conn, identity ServerIdentity, authorizedKeys AuthorizedKeys) (*EncryptedConn, error) {
	// Phase 1 受信: [32B client pubkey][4B client salt][32B stealth MAC]
	var clientMsg [68]byte
	if _, err := io.ReadFull(conn, clientMsg[:]); err != nil {
		return nil, fmt.Errorf("recv client handshake: %w", err)
	}
	clientEphPub := clientMsg[:32]
	var clientSalt [4]byte
	copy(clientSalt[:], clientMsg[32:36])
	receivedMAC := clientMsg[36:68]

	// MAC 検証: server.pub を知らない第三者からの接続を無応答で弾く
	expectedMAC := computeStealthMAC(identity.PublicKey, clientEphPub, clientSalt)
	if !hmac.Equal(expectedMAC, receivedMAC) {
		return nil, fmt.Errorf("invalid MAC")
	}

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen X25519 key: %w", err)
	}
	serverEphPub := priv.PublicKey().Bytes()

	serverSalt, err := randomSalt()
	if err != nil {
		return nil, fmt.Errorf("gen salt: %w", err)
	}

	// Phase 1 送信: [32B server pubkey][4B server salt]
	if _, err := conn.Write(buildEphemeralMsg(serverEphPub, serverSalt)); err != nil {
		return nil, fmt.Errorf("send server handshake: %w", err)
	}

	sessionID, c2sKey, s2cKey, err := performKeyExchange(priv, clientEphPub, clientEphPub, serverEphPub, clientSalt, serverSalt)
	if err != nil {
		return nil, err
	}

	enc, dec, err := setupAEADs(s2cKey, c2sKey, serverSalt, clientSalt)
	if err != nil {
		return nil, err
	}

	// Phase 2 送信: サーバー署名をクライアントに送信して身元検証
	serverSig := ed25519.Sign(identity.PrivateKey, sessionID)
	if err := writeFrame(conn, enc, serverSig); err != nil {
		return nil, fmt.Errorf("send server sig: %w", err)
	}

	// Phase 2 受信: クライアント公開鍵（32B）+ クライアント署名（64B）を検証する
	clientAuthFrame, err := readFrame(conn, dec)
	if err != nil {
		return nil, fmt.Errorf("recv client auth: %w", err)
	}
	if err := verifyClientAuth(clientAuthFrame, sessionID, authorizedKeys); err != nil {
		return nil, err
	}

	// Phase 3 送信: 認証成功の ACK をクライアントへ送信
	if err := writeFrame(conn, enc, []byte{0x01}); err != nil {
		return nil, fmt.Errorf("send auth ack: %w", err)
	}

	return &EncryptedConn{raw: conn, enc: enc, dec: dec}, nil
}

func buildEphemeralMsg(pubKey []byte, salt [4]byte) []byte {
	msg := make([]byte, 0, 36)
	msg = append(msg, pubKey...)
	msg = append(msg, salt[:]...)
	return msg
}

// performKeyExchange はピアの公開鍵でECDH演算を行い、セッションIDとセッション鍵を導出する。
// peerPubBytes はピア側のエフェメラル公開鍵。clientEphPub/serverEphPub は常にクライアント・サーバー順で渡す。
func performKeyExchange(priv *ecdh.PrivateKey, peerPubBytes, clientEphPub, serverEphPub []byte, clientSalt, serverSalt [4]byte) (sessionID, c2sKey, s2cKey []byte, err error) {
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse peer pubkey: %w", err)
	}
	dhShared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("X25519: %w", err)
	}
	sessionID = ComputeSessionID(clientEphPub, serverEphPub, clientSalt, serverSalt)
	c2sKey, s2cKey, err = deriveSessionKeys(dhShared, sessionID)
	return
}

func setupAEADs(encKey, decKey []byte, encSalt, decSalt [4]byte) (*aead, *aead, error) {
	encCipher, err := newAES256GCM(encKey)
	if err != nil {
		return nil, nil, err
	}
	decCipher, err := newAES256GCM(decKey)
	if err != nil {
		return nil, nil, err
	}
	return newAEAD(encCipher, encSalt), newAEAD(decCipher, decSalt), nil
}

func verifyServerSig(frame []byte, serverPubKey ed25519.PublicKey, sessionID []byte) error {
	if len(frame) != ed25519.SignatureSize {
		return fmt.Errorf("server sig: expected %d bytes, got %d", ed25519.SignatureSize, len(frame))
	}
	if !ed25519.Verify(serverPubKey, sessionID, frame) {
		return fmt.Errorf("server authentication failed")
	}
	return nil
}

func verifyClientAuth(frame []byte, sessionID []byte, authorizedKeys AuthorizedKeys) error {
	expectedSize := ed25519.PublicKeySize + ed25519.SignatureSize
	if len(frame) != expectedSize {
		return fmt.Errorf("client auth: expected %d bytes, got %d", expectedSize, len(frame))
	}
	clientIdentityPub := ed25519.PublicKey(frame[:ed25519.PublicKeySize])
	clientSig := frame[ed25519.PublicKeySize:]
	if !ed25519.Verify(clientIdentityPub, sessionID, clientSig) {
		return fmt.Errorf("client signature verification failed")
	}
	if !authorizedKeys.Contains(clientIdentityPub) {
		return fmt.Errorf("client public key not in authorized_keys")
	}
	return nil
}

func randomSalt() ([4]byte, error) {
	var s [4]byte
	if _, err := rand.Read(s[:]); err != nil {
		return s, err
	}
	return s, nil
}

func computeStealthMAC(serverPubKey, ephPub []byte, salt [4]byte) []byte {
	mac := hmac.New(sha256.New, serverPubKey)
	mac.Write(ephPub)
	mac.Write(salt[:])
	return mac.Sum(nil)
}
