// Package aes128 implements the AES-128 rounds for educational use.
// It is not hardened against timing or other side-channel attacks.
package aes128

import "errors"

const BlockSize = 16

type Cipher struct{ roundKey [176]byte }

var sbox, inverseSbox = makeSboxes()

// multiply operates in GF(2^8) modulo x^8+x^4+x^3+x+1.
func multiply(a, b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			result ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return result
}

func rotate(x byte, n uint) byte { return x<<n | x>>(8-n) }

func makeSboxes() ([256]byte, [256]byte) {
	var s, inv [256]byte
	for i := 0; i < 256; i++ {
		// x^254 is the multiplicative inverse for nonzero x; 0 maps to 0.
		x, power, base := byte(1), 254, byte(i)
		for power > 0 {
			if power&1 != 0 {
				x = multiply(x, base)
			}
			base = multiply(base, base)
			power >>= 1
		}
		s[i] = x ^ rotate(x, 1) ^ rotate(x, 2) ^ rotate(x, 3) ^ rotate(x, 4) ^ 0x63
		inv[s[i]] = byte(i)
	}
	return s, inv
}

func New(key []byte) (*Cipher, error) {
	if len(key) != 16 {
		return nil, errors.New("AES-128 требует ключ ровно 16 байт")
	}
	c := new(Cipher)
	copy(c.roundKey[:16], key)
	rcon := byte(1)
	for i := 16; i < 176; i += 4 {
		var temp [4]byte
		copy(temp[:], c.roundKey[i-4:i])
		if i%16 == 0 {
			temp = [4]byte{sbox[temp[1]] ^ rcon, sbox[temp[2]], sbox[temp[3]], sbox[temp[0]]}
			rcon = multiply(rcon, 2)
		}
		for j := 0; j < 4; j++ {
			c.roundKey[i+j] = c.roundKey[i+j-16] ^ temp[j]
		}
	}
	return c, nil
}

func (c *Cipher) addKey(state *[16]byte, round int) {
	for i := range state {
		state[i] ^= c.roundKey[16*round+i]
	}
}

func shiftRows(state *[16]byte, inverse bool) {
	old := *state
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			source := (col + row) % 4
			if inverse {
				source = (col - row + 4) % 4
			}
			state[row+4*col] = old[row+4*source]
		}
	}
}

func mixColumns(state *[16]byte, inverse bool) {
	matrix := [4]byte{2, 3, 1, 1}
	if inverse {
		matrix = [4]byte{14, 11, 13, 9}
	}
	for col := 0; col < 4; col++ {
		var old [4]byte
		copy(old[:], state[4*col:4*col+4])
		for row := 0; row < 4; row++ {
			state[4*col+row] = 0
			for j := 0; j < 4; j++ {
				state[4*col+row] ^= multiply(old[j], matrix[(j-row+4)%4])
			}
		}
	}
}

func (c *Cipher) EncryptBlock(dst, src []byte) error {
	if c == nil || len(src) != 16 || len(dst) != 16 {
		return errors.New("AES: блок должен иметь 16 байт")
	}
	var state [16]byte
	copy(state[:], src)
	c.addKey(&state, 0)
	for round := 1; round <= 10; round++ {
		for i := range state {
			state[i] = sbox[state[i]]
		}
		shiftRows(&state, false)
		if round != 10 {
			mixColumns(&state, false)
		}
		c.addKey(&state, round)
	}
	copy(dst, state[:])
	return nil
}

func (c *Cipher) DecryptBlock(dst, src []byte) error {
	if c == nil || len(src) != 16 || len(dst) != 16 {
		return errors.New("AES: блок должен иметь 16 байт")
	}
	var state [16]byte
	copy(state[:], src)
	c.addKey(&state, 10)
	for round := 9; round >= 0; round-- {
		shiftRows(&state, true)
		for i := range state {
			state[i] = inverseSbox[state[i]]
		}
		c.addKey(&state, round)
		if round != 0 {
			mixColumns(&state, true)
		}
	}
	copy(dst, state[:])
	return nil
}
