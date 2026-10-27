package gostsign

import (
	"bytes"
	"cryptolabs/internal/ec"
	"math/big"
	"testing"
)

func hx(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return n
}
func TestRFC7091Arithmetic(t *testing.T) {
	s := TestScheme()
	d := hx("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	e := hx("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	k := hx("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3")
	pub, err := s.Public(d)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(hx("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")) != 0 || pub.Y.Cmp(hx("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")) != 0 {
		t.Fatalf("public %x %x", pub.X, pub.Y)
	}
	sig, err := s.signE(e, d, k)
	if err != nil {
		t.Fatal(err)
	}
	want := append(hx("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493").FillBytes(make([]byte, 32)), hx("1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40").FillBytes(make([]byte, 32))...)
	if !bytes.Equal(sig, want) {
		t.Fatalf("signature %x", sig)
	}
	if !s.verifyE(e, pub, sig) {
		t.Fatal("RFC verification failed")
	}
}

func TestSignVerifyAndRejections(t *testing.T) {
	s := TestScheme()
	d, pub, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("\x00\xffПодпись файла\x00")
	sig, err := s.Sign(data, d)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Verify(data, pub, sig) {
		t.Fatal("round trip")
	}
	if s.Verify(append(data, 1), pub, sig) {
		t.Fatal("changed data accepted")
	}
	_, other, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if s.Verify(data, other, sig) {
		t.Fatal("wrong key accepted")
	}
	for _, bad := range [][]byte{nil, sig[:63], make([]byte, 64), append(s.Q.FillBytes(make([]byte, 32)), sig[32:]...), append(sig[:32:32], s.Q.FillBytes(make([]byte, 32))...)} {
		if s.Verify(data, pub, bad) {
			t.Fatal("invalid signature accepted")
		}
	}
	for _, bad := range []ec.Point{{Inf: true}, {}, {X: big.NewInt(0), Y: big.NewInt(0)}, {X: new(big.Int).Add(pub.X, s.C.P), Y: pub.Y}} {
		if s.ValidatePublic(bad) == nil {
			t.Fatal("invalid public key accepted")
		}
	}
	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Set(s.Q)} {
		if _, err := s.Public(bad); err == nil {
			t.Fatal("bad private key accepted")
		}
	}
}

func TestRejectWrongSubgroup(t *testing.T) {
	c, err := ec.New(big.NewInt(17), big.NewInt(0), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	s := &Scheme{C: c, Q: big.NewInt(3), G: ec.Point{X: big.NewInt(0), Y: big.NewInt(1)}}
	if err := s.ValidatePublic(ec.Point{X: big.NewInt(1), Y: big.NewInt(6)}); err == nil {
		t.Fatal("point outside order-3 subgroup accepted")
	}
}

func TestZeroEAndDigestByteOrder(t *testing.T) {
	s := TestScheme()
	pub, _ := s.Public(big.NewInt(2))
	sig, err := s.signE(big.NewInt(0), big.NewInt(2), big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	if !s.verifyE(big.NewInt(0), pub, sig) || !s.verifyE(big.NewInt(1), pub, sig) {
		t.Fatal("e=0 must become 1")
	}
	// The hash octets are interpreted as a little-endian integer before mod q.
	b := make([]byte, 32)
	b[0] = 1
	b[31] = 2
	want := new(big.Int).Add(big.NewInt(1), new(big.Int).Lsh(big.NewInt(2), 248))
	want.Mod(want, s.Q)
	if s.digestE(b).Cmp(want) != 0 {
		t.Fatal("digest byte order")
	}
}

func TestZeroSignatureComponentsRequireRetry(t *testing.T) {
	s := TestScheme()
	// With d=k=1, r=x(G)=2. Thus e=q-2 makes s=(2+e) mod q=0.
	e := new(big.Int).Sub(s.Q, big.NewInt(2))
	if _, err := s.signE(e, big.NewInt(1), big.NewInt(1)); err != errRetry {
		t.Fatalf("zero s must request a new nonce: %v", err)
	}
	c, err := ec.New(big.NewInt(17), big.NewInt(0), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	small := &Scheme{C: c, Q: big.NewInt(3), G: ec.Point{X: big.NewInt(0), Y: big.NewInt(1)}}
	if _, err := small.signE(big.NewInt(1), big.NewInt(1), big.NewInt(1)); err != errRetry {
		t.Fatalf("zero r must request a new nonce: %v", err)
	}
}
