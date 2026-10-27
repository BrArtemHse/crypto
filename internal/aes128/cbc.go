package aes128

import (
	"bytes"
	"errors"
	"io"
)

const magic = "AES128C1"

// EncryptCBC returns magic || IV || CBC(PKCS#7(plaintext)).
// This container has no authentication tag.
func EncryptCBC(key, plaintext []byte, random io.Reader) ([]byte, error) {
	c, err := New(key)
	if err != nil {
		return nil, err
	}
	if random == nil {
		return nil, errors.New("не задан источник случайного IV")
	}
	if len(plaintext) > int(^uint(0)>>1)-40 {
		return nil, errors.New("слишком большой файл")
	}
	padding := 16 - len(plaintext)%16
	out := make([]byte, 24+len(plaintext)+padding)
	copy(out, magic)
	if _, err := io.ReadFull(random, out[8:24]); err != nil {
		return nil, err
	}
	padded := out[24:]
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	previous := out[8:24]
	for i := 24; i < len(out); i += 16 {
		block := out[i : i+16]
		for j := range block {
			block[j] ^= previous[j]
		}
		_ = c.EncryptBlock(block, block)
		previous = block
	}
	return out, nil
}

func DecryptCBC(key, container []byte) ([]byte, error) {
	c, err := New(key)
	if err != nil {
		return nil, err
	}
	if len(container) < 40 || !bytes.Equal(container[:8], []byte(magic)) || (len(container)-24)%16 != 0 {
		return nil, errors.New("неверный заголовок или длина контейнера AES")
	}
	out := make([]byte, len(container)-24)
	previous := container[8:24]
	for i := 24; i < len(container); i += 16 {
		block := out[i-24 : i-8]
		_ = c.DecryptBlock(block, container[i:i+16])
		for j := range block {
			block[j] ^= previous[j]
		}
		previous = container[i : i+16]
	}
	padding := int(out[len(out)-1])
	if padding < 1 || padding > 16 {
		return nil, errors.New("неверное дополнение PKCS#7")
	}
	for _, b := range out[len(out)-padding:] {
		if int(b) != padding {
			return nil, errors.New("неверное дополнение PKCS#7")
		}
	}
	return out[:len(out)-padding], nil
}
