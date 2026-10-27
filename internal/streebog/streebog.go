// Package streebog implements the educational GOST R 34.11-2012 256-bit hash.
package streebog

import "encoding/binary"

// Sum256 returns the digest in conventional byte-stream order.
func Sum256(data []byte) [32]byte {
	var h, n, sum [64]byte
	for i := range h {
		h[i] = 1
	}
	for len(data) >= 64 {
		var m [64]byte
		for i := 0; i < 64; i++ {
			m[63-i] = data[i]
		}
		h = compress(h, n, m)
		n = add(n, number(512))
		sum = add(sum, m)
		data = data[64:]
	}
	var m [64]byte
	for i, b := range data {
		m[63-i] = b
	}
	m[63-len(data)] = 1
	h = compress(h, n, m)
	n = add(n, number(uint64(len(data))*8))
	sum = add(sum, m)
	h = compress(h, [64]byte{}, n)
	h = compress(h, [64]byte{}, sum)
	var digest [32]byte
	for i := range digest {
		digest[i] = h[31-i]
	}
	return digest
}

// Internally vectors use the RFC notation: most significant octet first.
// Conversion at the input/output boundary preserves the conventional API.
func number(v uint64) (out [64]byte) { binary.BigEndian.PutUint64(out[56:], v); return }
func add(a, b [64]byte) (out [64]byte) {
	carry := uint16(0)
	for i := 63; i >= 0; i-- {
		carry = uint16(a[i]) + uint16(b[i]) + (carry >> 8)
		out[i] = byte(carry)
	}
	return
}
func xor(a, b [64]byte) (out [64]byte) {
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return
}
func lps(in [64]byte) (out [64]byte) {
	var perm [64]byte
	for i := range perm {
		perm[i] = pi[in[(i%8)*8+i/8]]
	}
	for off := 0; off < 64; off += 8 {
		var v uint64
		for j := 0; j < 8; j++ {
			for bit := 0; bit < 8; bit++ {
				if perm[off+j]&(1<<uint(7-bit)) != 0 {
					v ^= matrix[8*j+bit]
				}
			}
		}
		binary.BigEndian.PutUint64(out[off:off+8], v)
	}
	return
}
func compress(h, n, m [64]byte) [64]byte {
	k := lps(xor(h, n))
	state := xor(k, m)
	for _, c := range constants {
		state = lps(state)
		k = lps(xor(k, c))
		state = xor(state, k)
	}
	return xor(xor(state, h), m)
}
