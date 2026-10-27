package rsalab

import (
	"bytes"
	"math/big"
	"testing"
)

func TestNumericalRSA(t *testing.T) {
	k, err := FromPrimes(big.NewInt(61), big.NewInt(53), big.NewInt(17))
	if err != nil {
		t.Fatal(err)
	}
	if k.N.String() != "3233" || k.D.String() != "2753" {
		t.Fatalf("key: %v", k)
	}
	c, err := EncryptNumber(&k.PublicKey, big.NewInt(65))
	if err != nil || c.String() != "2790" {
		t.Fatalf("%v %v", c, err)
	}
	m, err := DecryptNumber(k, c)
	if err != nil || m.Int64() != 65 {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := EncryptNumber(&k.PublicKey, k.N); err == nil {
		t.Fatal("m >= n accepted")
	}
	for _, tc := range [][5]int64{{11, 13, 7, 103, 81}, {17, 19, 5, 173, 264}} {
		key, err := FromPrimes(big.NewInt(tc[0]), big.NewInt(tc[1]), big.NewInt(tc[2]))
		if err != nil {
			t.Fatal(err)
		}
		c, err := EncryptNumber(&key.PublicKey, big.NewInt(42))
		if err != nil {
			t.Fatal(err)
		}
		if key.D.Int64() != tc[3] || c.Int64() != tc[4] {
			t.Fatalf("example: d=%v c=%v", key.D, c)
		}
		m, err := DecryptNumber(key, c)
		if err != nil || m.Int64() != 42 {
			t.Fatal("example roundtrip", err)
		}
	}
	if _, err := FromPrimes(big.NewInt(9), big.NewInt(11), big.NewInt(7)); err == nil {
		t.Fatal("composite accepted")
	}
	if _, err := FromPrimes(big.NewInt(11), big.NewInt(11), big.NewInt(7)); err == nil {
		t.Fatal("equal primes accepted")
	}
	if _, err := EncryptNumber(nil, big.NewInt(0)); err == nil {
		t.Fatal("nil key accepted")
	}
	if _, err := DecryptNumber(k, big.NewInt(-1)); err == nil {
		t.Fatal("negative c accepted")
	}
}

func TestBinaryContainer(t *testing.T) {
	k, _ := FromPrimes(big.NewInt(61), big.NewInt(53), big.NewInt(17))
	for _, data := range [][]byte{nil, {0}, {0, 0, 255, 0, 42}, []byte("Криптография UTF-8")} {
		c, err := Encrypt(&k.PublicKey, data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(k, c)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("roundtrip %x %v", got, err)
		}
		for _, bad := range [][]byte{c[:len(c)-1], append(append([]byte{}, c...), 0), {1, 2, 3}} {
			if _, err := Decrypt(k, bad); err == nil {
				t.Fatalf("malformed accepted: %x", bad)
			}
		}
	}
	c, _ := Encrypt(&k.PublicKey, []byte{42})
	c[len(c)-2] = 255
	c[len(c)-1] = 255
	if _, err := Decrypt(k, c); err == nil {
		t.Fatal("out-of-range block accepted")
	}
	c, _ = Encrypt(&k.PublicKey, []byte{42})
	for i := 12; i < 20; i++ {
		c[i] = 255
	}
	if _, err := Decrypt(k, c); err == nil {
		t.Fatal("huge forged length accepted")
	}
	c, _ = Encrypt(&k.PublicKey, []byte{42})
	c[8] = 255
	if _, err := Decrypt(k, c); err == nil {
		t.Fatal("forged block size accepted")
	}
	c, _ = Encrypt(&k.PublicKey, []byte{42})
	wide, _ := EncryptNumber(&k.PublicKey, big.NewInt(256))
	wide.FillBytes(c[20:])
	if _, err := Decrypt(k, c); err == nil {
		t.Fatal("oversized recovered block accepted")
	}
}

func TestJSONKeys(t *testing.T) {
	k, _ := FromPrimes(big.NewInt(61), big.NewInt(53), big.NewInt(17))
	b, err := MarshalPrivate(k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePrivate(b)
	if err != nil || got.D.Cmp(k.D) != 0 {
		t.Fatal(err)
	}
	pub, _ := MarshalPublic(&k.PublicKey)
	if _, err := ParsePublic(pub); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `{"version":1,"n":"3233","e":"17","d":"1","p":"61","q":"53"}`, `{"version":1,"n":"-5","e":"3"}`, `{"version":1,"n":"3233","e":"17","other":0}`, string(pub) + `{}`} {
		if _, err := ParsePrivate([]byte(bad)); err == nil {
			t.Fatal("bad private key accepted", bad)
		}
	}
	if _, err := ParsePublic([]byte(`{"version":1,"n":"3233","e":"17","other":0}`)); err == nil {
		t.Fatal("unknown public field accepted")
	}
	for _, bad := range []string{`{}`, `{"version":1,"n":"3233","e":"1"}`, `{"version":1,"n":"-3233","e":"17"}`, `{"version":2,"n":"3233","e":"17"}`, string(pub) + `{}`} {
		if _, err := ParsePublic([]byte(bad)); err == nil {
			t.Fatal("bad public key accepted", bad)
		}
	}
}

func TestFermatAndGeneratedKeys(t *testing.T) {
	k, steps, err := Fermat(big.NewInt(3233), big.NewInt(17), 10)
	if err != nil || k.P.Int64() != 53 || k.Q.Int64() != 61 || steps != 1 {
		t.Fatalf("%v %d %v", k, steps, err)
	}
	if _, _, err := Fermat(big.NewInt(303), big.NewInt(7), 1); err == nil {
		t.Fatal("iteration limit ignored")
	}
	if _, _, err := Fermat(big.NewInt(16), big.NewInt(3), 10); err == nil {
		t.Fatal("even n accepted")
	}
	generated, err := Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	if generated.N.BitLen() != 256 {
		t.Fatal("incorrect generated bit length")
	}
	c, err := Encrypt(&generated.PublicKey, []byte{0, 0, 1, 255})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(generated, c)
	if err != nil || !bytes.Equal(got, []byte{0, 0, 1, 255}) {
		t.Fatal("generated key roundtrip", err)
	}
}

func TestDuplicateJSONKeyRejected(t *testing.T) {
	if _, err := ParsePublic([]byte(`{"version":1,"n":"3233","n":"3233","e":"17"}`)); err == nil {
		t.Fatal("duplicate field accepted")
	}
}
