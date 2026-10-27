package aes128

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestCBCContainer(t *testing.T) {
	key := make([]byte, 16)
	for _, data := range [][]byte{nil, {0}, {0, 0, 255, 0}, []byte("Привет, AES"), make([]byte, 16), make([]byte, 47)} {
		iv := bytes.Repeat([]byte{0x42}, 16)
		got, err := EncryptCBC(key, data, bytes.NewReader(iv))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := DecryptCBC(key, got)
		if err != nil || !bytes.Equal(plain, data) {
			t.Fatalf("roundtrip %x %v", plain, err)
		}
		oracle, _ := aes.NewCipher(key)
		padding := 16 - len(data)%16
		padded := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(padding)}, padding)...)
		want := make([]byte, len(padded))
		cipher.NewCBCEncrypter(oracle, iv).CryptBlocks(want, padded)
		if !bytes.Equal(got[24:], want) {
			t.Fatalf("CBC oracle mismatch %x", got)
		}
		for _, bad := range [][]byte{got[:len(got)-1], got[:23], append(append([]byte{}, got...), 0)} {
			if _, err := DecryptCBC(key, bad); err == nil {
				t.Fatal("malformed accepted")
			}
		}
	}
	c, _ := EncryptCBC(key, nil, bytes.NewReader(make([]byte, 16)))
	c[23] ^= 0x10 // change last padded plaintext byte from 16 to 0 through IV.
	if _, err := DecryptCBC(key, c); err == nil {
		t.Fatal("invalid padding accepted")
	}
	if _, err := EncryptCBC(key, nil, bytes.NewReader(nil)); err == nil {
		t.Fatal("missing random data accepted")
	}
}
