package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxFramePayload = 4 * 1024 * 1024 // 4 MiB

// writeFrame は plaintext を AEAD 暗号化し、[4B 長さ][暗号文] の形式で書き込む。
// 長さフィールドは暗号文のバイト数（認証タグ16Bを含む）をビッグエンディアンで示す。
func writeFrame(w io.Writer, enc *aead, plaintext []byte) error {
	ct := enc.Seal(plaintext)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(ct)
	return err
}

// readFrame は [4B 長さ][暗号文] を読み取り、AEAD 復号・認証タグ検証を行って平文を返す。
// 認証タグが合わない場合（改ざん・ノンスずれ）は Open がエラーを返す。
// ノンスはカウンターベースのため、フレームの欠落や順序入れ替えも検知できる。
func readFrame(r io.Reader, dec *aead) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFramePayload {
		return nil, fmt.Errorf("frame too large: %d bytes", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, err
	}
	return dec.Open(ct)
}
