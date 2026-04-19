package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

// smux ストリームの用途を示す1Bの種別コード。
// サーバー側はこの値を見て TLS ダイヤルするか否かを判断する。
const (
	StreamHTTP  byte = 0x01
	StreamHTTPS byte = 0x02
	StreamWS    byte = 0x03
	StreamWSS   byte = 0x04
)

// StreamHeader は smux ストリーム開通直後に送る宛先情報。
// CONNECT トンネルと同様に「どこへ繋ぐか」をストリームの先頭で宣言する。
type StreamHeader struct {
	Type     byte
	HostPort string
}

// WriteStreamHeader は [1B 種別][2B ホスト長][ホスト:ポート] の形式で書き込む。
// ホスト長を2Bで表現するため最大 65535B だが、isHostAllowed で 512B 以下に制限される。
func WriteStreamHeader(w io.Writer, h StreamHeader) error {
	hp := []byte(h.HostPort)
	buf := make([]byte, 1+2+len(hp))
	buf[0] = h.Type
	binary.BigEndian.PutUint16(buf[1:], uint16(len(hp)))
	copy(buf[3:], hp)
	_, err := w.Write(buf)
	return err
}

// ReadStreamHeader は WriteStreamHeader の逆操作。
// ホスト長が 0 または 512 超の場合は不正なヘッダーとして拒否する。
// 512B 上限は DNS ラベル長の現実的な最大値に基づく簡易サニティチェック。
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return StreamHeader{}, fmt.Errorf("read stream header: %w", err)
	}
	streamType := hdr[0]
	hpLen := binary.BigEndian.Uint16(hdr[1:])
	if hpLen == 0 || hpLen > 512 {
		return StreamHeader{}, fmt.Errorf("invalid host:port length: %d", hpLen)
	}
	hp := make([]byte, hpLen)
	if _, err := io.ReadFull(r, hp); err != nil {
		return StreamHeader{}, fmt.Errorf("read host:port: %w", err)
	}
	return StreamHeader{Type: streamType, HostPort: string(hp)}, nil
}
