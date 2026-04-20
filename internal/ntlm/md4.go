package ntlm

import (
	"encoding/binary"
	"math/bits"
)

// md4Sum computes the MD4 hash of msg (RFC 1320).
func md4Sum(msg []byte) [16]byte {
	orig := uint64(len(msg)) * 8
	padded := make([]byte, len(msg), len(msg)+72)
	copy(padded, msg)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.LittleEndian.AppendUint64(padded, orig)

	a, b, c, d := uint32(0x67452301), uint32(0xEFCDAB89), uint32(0x98BADCFE), uint32(0x10325476)

	for i := 0; i < len(padded); i += 64 {
		var x [16]uint32
		for j := range x {
			x[j] = binary.LittleEndian.Uint32(padded[i+j*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1: F(b,c,d) = (b&c)|(^b&d)
		for _, op := range [16][2]int{
			{0, 3}, {1, 7}, {2, 11}, {3, 19},
			{4, 3}, {5, 7}, {6, 11}, {7, 19},
			{8, 3}, {9, 7}, {10, 11}, {11, 19},
			{12, 3}, {13, 7}, {14, 11}, {15, 19},
		} {
			a = bits.RotateLeft32(a+b&c|^b&d+x[op[0]], op[1])
			a, b, c, d = d, a, b, c
		}
		// Round 2: G(b,c,d) = (b&c)|(b&d)|(c&d), constant 0x5A827999
		for _, op := range [16][2]int{
			{0, 3}, {4, 5}, {8, 9}, {12, 13},
			{1, 3}, {5, 5}, {9, 9}, {13, 13},
			{2, 3}, {6, 5}, {10, 9}, {14, 13},
			{3, 3}, {7, 5}, {11, 9}, {15, 13},
		} {
			a = bits.RotateLeft32(a+b&c|b&d|c&d+x[op[0]]+0x5A827999, op[1])
			a, b, c, d = d, a, b, c
		}
		// Round 3: H(b,c,d) = b^c^d, constant 0x6ED9EBA1
		for _, op := range [16][2]int{
			{0, 3}, {8, 9}, {4, 11}, {12, 15},
			{2, 3}, {10, 9}, {6, 11}, {14, 15},
			{1, 3}, {9, 9}, {5, 11}, {13, 15},
			{3, 3}, {11, 9}, {7, 11}, {15, 15},
		} {
			a = bits.RotateLeft32(a+b^c^d+x[op[0]]+0x6ED9EBA1, op[1])
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}
