package aes128

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// FIPS 197 Appendix B/C catches state layout and key schedule errors independently.
func TestFIPS197(t *testing.T) {
	key := unhex("000102030405060708090a0b0c0d0e0f")
	in := unhex("00112233445566778899aabbccddeeff")
	want := unhex("69c4e0d86a7b0430d8cdb78070b4c55a")
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	if err := c.EncryptBlock(out, in); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("got %x want %x", out, want)
	}
	if err := c.DecryptBlock(out, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("decrypt got %x", out)
	}
}

func TestAgainstStandardAES(t *testing.T) {
	for k := 0; k < 40; k++ {
		key, in := make([]byte, 16), make([]byte, 16)
		for i := range key {
			key[i] = byte(k*19 + i)
			in[i] = byte(i*7 + k)
		}
		own, _ := New(key)
		oracle, _ := aes.NewCipher(key)
		got, want := make([]byte, 16), make([]byte, 16)
		_ = own.EncryptBlock(got, in)
		oracle.Encrypt(want, in)
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d", k)
		}
		_ = own.DecryptBlock(got, want)
		if !bytes.Equal(got, in) {
			t.Fatalf("inverse %d", k)
		}
	}
	if _, err := New(make([]byte, 15)); err == nil {
		t.Fatal("bad key accepted")
	}
	c, _ := New(make([]byte, 16))
	if c.EncryptBlock(make([]byte, 15), make([]byte, 16)) == nil {
		t.Fatal("short dst accepted")
	}
}
