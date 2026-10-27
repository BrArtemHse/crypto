package blockchain

import (
	"errors"
	"strings"
	"unicode/utf8"

	"cryptolabs/internal/streebog"
)

// PRNG is the deterministic hash-counter generator required by the assignment.
// It is not safe for real keys: its seed is the student's public name.
type PRNG struct {
	seed      [32]byte
	counter   [32]byte
	buffered  []byte
	exhausted bool
}

func NewPRNG(name string) (*PRNG, error) {
	if strings.TrimSpace(name) == "" || len(name) > 64 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return nil, errors.New("name must be valid UTF-8, 1..64 bytes, nonblank, without NUL")
	}
	var seed [64]byte
	copy(seed[:], []byte(name))
	return &PRNG{seed: streebog.Sum256(seed[:])}, nil
}

func (r *PRNG) Read(out []byte) (int, error) {
	written := 0
	for written < len(out) {
		if len(r.buffered) == 0 {
			if r.exhausted {
				return written, errors.New("PRNG counter exhausted")
			}
			carry := byte(1)
			for i := 31; i >= 0 && carry != 0; i-- {
				r.counter[i]++
				if r.counter[i] != 0 {
					carry = 0
				}
			}
			if carry != 0 {
				r.exhausted = true
				return written, errors.New("PRNG counter exhausted")
			}
			var input [64]byte
			copy(input[:32], r.seed[:])
			copy(input[32:], r.counter[:])
			digest := streebog.Sum256(input[:])
			r.buffered = append([]byte(nil), digest[:]...)
		}
		n := copy(out[written:], r.buffered)
		written += n
		r.buffered = r.buffered[n:]
	}
	return written, nil
}
