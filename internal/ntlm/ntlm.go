// Package ntlm implements NTLMv2 proxy authentication (MS-NLMP).
// Only the client-side Negotiate/Authenticate messages are implemented.
package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// negotiateFlags は Type1/Type3 共通のフラグセット。
// Version フィールドは含めないため 0x02000000 は除く。
const negotiateFlags = uint32(0x00000001 | // UNICODE
	0x00000002 | // OEM
	0x00000004 | // REQUEST_TARGET
	0x00000200 | // NTLM
	0x00008000 | // ALWAYS_SIGN
	0x00080000 | // EXTENDED_SESSION_SECURITY
	0x00800000 | // TARGET_INFO
	0x20000000 | // 128-bit
	0x80000000) // 56-bit

var ntlmSig = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// NewNegotiateMessage builds an NTLM Type 1 Negotiate message.
func NewNegotiateMessage() []byte {
	msg := make([]byte, 32)
	copy(msg[:], ntlmSig[:])
	binary.LittleEndian.PutUint32(msg[8:], 1)               // MessageType = 1
	binary.LittleEndian.PutUint32(msg[12:], negotiateFlags)
	// DomainNameFields および WorkstationFields: 長さ 0、オフセット 32
	binary.LittleEndian.PutUint32(msg[20:], 32)
	binary.LittleEndian.PutUint32(msg[28:], 32)
	return msg
}

// ProcessChallenge builds an NTLM Type 3 Authenticate message
// in response to the server's Type 2 Challenge message.
func ProcessChallenge(challengeMsg []byte, username, password string) ([]byte, error) {
	if len(challengeMsg) < 48 {
		return nil, fmt.Errorf("ntlm: challenge too short (%d bytes)", len(challengeMsg))
	}

	serverChallenge := challengeMsg[24:32]

	// TargetInfo: security buffer at offset 40 (len uint16, maxlen uint16, offset uint32)
	tiLen := int(binary.LittleEndian.Uint16(challengeMsg[40:]))
	tiOff := int(binary.LittleEndian.Uint32(challengeMsg[44:]))
	var targetInfo []byte
	if tiOff+tiLen <= len(challengeMsg) {
		targetInfo = challengeMsg[tiOff : tiOff+tiLen]
	}

	domain, user := splitUser(username)
	ntResp, lmResp, err := computeResponses(serverChallenge, targetInfo, user, domain, password)
	if err != nil {
		return nil, err
	}

	domBytes := utf16LE(domain)
	userBytes := utf16LE(user)

	// Type 3 固定ヘッダー 64 バイト（Version/MIC フィールドなし）
	const hdrLen = 64
	off := uint32(hdrLen)
	msg := make([]byte, hdrLen+len(lmResp)+len(ntResp)+len(domBytes)+len(userBytes))

	copy(msg[:], ntlmSig[:])
	binary.LittleEndian.PutUint32(msg[8:], 3) // MessageType = 3

	putSecBuf(msg[12:], uint16(len(lmResp)), off)
	off += uint32(len(lmResp))
	putSecBuf(msg[20:], uint16(len(ntResp)), off)
	off += uint32(len(ntResp))
	putSecBuf(msg[28:], uint16(len(domBytes)), off)
	off += uint32(len(domBytes))
	putSecBuf(msg[36:], uint16(len(userBytes)), off)
	off += uint32(len(userBytes))
	putSecBuf(msg[44:], 0, off) // Workstation（空）
	putSecBuf(msg[52:], 0, off) // EncryptedRandomSessionKey（空）
	binary.LittleEndian.PutUint32(msg[60:], negotiateFlags)

	pos := hdrLen
	pos += copy(msg[pos:], lmResp)
	pos += copy(msg[pos:], ntResp)
	pos += copy(msg[pos:], domBytes)
	copy(msg[pos:], userBytes)

	return msg, nil
}

// computeResponses computes NTLMv2 NT and LM responses.
func computeResponses(serverChallenge, targetInfo []byte, username, domain, password string) (ntResp, lmResp []byte, err error) {
	// NT hash = MD4(UTF-16LE(password))
	ntHash := md4Sum(utf16LE(password))

	// NTLMv2 hash = HMAC-MD5(NT hash, UTF-16LE(uppercase(username) + domain))
	ntlmv2Hash := hmacMD5(ntHash[:], utf16LE(strings.ToUpper(username)+domain))

	clientChallenge := make([]byte, 8)
	if _, err = rand.Read(clientChallenge); err != nil {
		return nil, nil, fmt.Errorf("ntlm: client challenge: %w", err)
	}

	ts := winTime(time.Now().UTC())
	blob := buildBlob(ts, clientChallenge, targetInfo)

	// NTProofStr = HMAC-MD5(NTLMv2 hash, serverChallenge || blob)
	ntProofStr := hmacMD5(ntlmv2Hash, serverChallenge, blob)
	ntResp = append(ntProofStr, blob...)

	// LMv2: HMAC-MD5(NTLMv2 hash, serverChallenge || clientChallenge) || clientChallenge
	lmResp = append(hmacMD5(ntlmv2Hash, serverChallenge, clientChallenge), clientChallenge...)
	return
}

// buildBlob builds the NTLMv2 client challenge blob (MS-NLMP 2.2.2.7).
func buildBlob(ts uint64, clientChallenge, targetInfo []byte) []byte {
	b := make([]byte, 0, 28+len(targetInfo)+4)
	b = append(b, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // RespType, HiRespType, Reserved1, Reserved2
	b = binary.LittleEndian.AppendUint64(b, ts)
	b = append(b, clientChallenge...)
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Reserved3
	b = append(b, targetInfo...)
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Terminator
	return b
}

// winTime converts t to Windows FILETIME (100ns ticks since 1601-01-01 UTC).
func winTime(t time.Time) uint64 {
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return uint64(t.Sub(epoch).Nanoseconds() / 100)
}

func hmacMD5(key []byte, data ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// splitUser splits "DOMAIN\user" or "user@DOMAIN" into (domain, user).
func splitUser(username string) (domain, user string) {
	if i := strings.IndexByte(username, '\\'); i >= 0 {
		return username[:i], username[i+1:]
	}
	if i := strings.IndexByte(username, '@'); i >= 0 {
		return username[i+1:], username[:i]
	}
	return "", username
}

// putSecBuf writes an NTLM security buffer (len, maxlen, offset) into dst.
func putSecBuf(dst []byte, length uint16, offset uint32) {
	binary.LittleEndian.PutUint16(dst[0:], length)
	binary.LittleEndian.PutUint16(dst[2:], length)
	binary.LittleEndian.PutUint32(dst[4:], offset)
}
