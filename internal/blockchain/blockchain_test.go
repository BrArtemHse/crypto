package blockchain

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cryptolabs/internal/streebog"
)

func TestPRNGFormulaAndChunking(t *testing.T) {
	a, err := NewPRNG("Иванов Иван")
	if err != nil {
		t.Fatal(err)
	}
	var seed [64]byte
	copy(seed[:], []byte("Иванов Иван"))
	h0 := streebog.Sum256(seed[:])
	input := make([]byte, 64)
	copy(input, h0[:])
	input[63] = 1
	want := streebog.Sum256(input)
	first := make([]byte, 32)
	if _, err = a.Read(first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, want[:]) {
		t.Fatalf("first block: %x != %x", first, want)
	}
	b, _ := NewPRNG("Иванов Иван")
	whole := make([]byte, 97)
	b.Read(whole)
	c, _ := NewPRNG("Иванов Иван")
	parts := make([]byte, 97)
	c.Read(parts[:7])
	c.Read(parts[7:33])
	c.Read(parts[33:])
	if !bytes.Equal(whole, parts) {
		t.Fatal("read chunking repeats or discards bytes")
	}
	if _, err := NewPRNG(""); err == nil {
		t.Fatal("empty seed accepted")
	}
	if _, err := NewPRNG(string(bytes.Repeat([]byte("я"), 33))); err == nil {
		t.Fatal("oversized UTF-8 seed accepted")
	}
}

func TestA3ParametersAndSchnorr(t *testing.T) {
	p, q, g := Parameters()
	if p.BitLen() != 512 || q.BitLen() != 256 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		t.Fatal("invalid A.3 primes")
	}
	if new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), q).Sign() != 0 || new(big.Int).Exp(g, q, p).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("wrong subgroup parameters")
	}
	x := big.NewInt(123456)
	k := big.NewInt(98765)
	pub := new(big.Int).Exp(g, x, p)
	sig, err := SignWithNonce([]byte("transaction"), x, k)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature([]byte("transaction"), pub, sig) {
		t.Fatal("signature rejected")
	}
	if VerifySignature([]byte("changed"), pub, sig) {
		t.Fatal("changed message accepted")
	}
	if VerifySignature([]byte("transaction"), big.NewInt(1), sig) {
		t.Fatal("identity key accepted")
	}
	bad := sig
	bad.S = new(big.Int).Set(q)
	if VerifySignature([]byte("transaction"), pub, bad) {
		t.Fatal("s=q accepted")
	}
	if _, err := SignWithNonce(nil, x, big.NewInt(0)); err == nil {
		t.Fatal("zero nonce accepted")
	}
}

// The published exponentiation result also checks the exact A.3 generator,
// rather than only checking that some valid subgroup generator was selected.
func TestA3PublishedExponentiationAndChallengeEncoding(t *testing.T) {
	parse := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatal("invalid fixture")
		}
		return n
	}
	x := parse("3036314538303830343630454235324435324234314132373832433138443046")
	k := parse("90f3a564439242f5186ebb224c8e223811b7105c64e4f5390807e6362df4c72a")
	wantR := parse("47681c974373b0653c6ca965c8f86127d07a7e02e311846e97a8c1263f8a76afff0ad18802643b5c6c9987750c6b045898e4ad8cfc68981776ba82163adbc988")
	msg := []byte{0, 255, 1, 0}
	sig, err := SignWithNonce(msg, x, k)
	if err != nil {
		t.Fatal(err)
	}
	if sig.R.Cmp(wantR) != 0 {
		t.Fatalf("GOST A.3 R mismatch: %x", sig.R)
	}
	p, q, g := Parameters()
	pub := new(big.Int).Exp(g, x, p)
	encoded := append(wantR.FillBytes(make([]byte, 64)), pub.FillBytes(make([]byte, 64))...)
	digest := streebog.Sum256(append(encoded, msg...))
	e := new(big.Int).SetBytes(digest[:])
	wantS := new(big.Int).Mul(e, x)
	wantS.Add(wantS, k).Mod(wantS, q)
	if sig.S.Cmp(wantS) != 0 {
		t.Fatal("challenge must hash fixed-width R || public key || message")
	}
}

func TestPRNGCounterExhaustion(t *testing.T) {
	rng, err := NewPRNG("Name")
	if err != nil {
		t.Fatal(err)
	}
	for i := range rng.counter {
		rng.counter[i] = 255
	}
	if _, err = rng.Read(make([]byte, 1)); err == nil {
		t.Fatal("counter wrapped and reused initial stream")
	}
}

func TestGenerateRejectsAmbiguousTimestamp(t *testing.T) {
	if _, err := Generate("Name", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("century ambiguity accepted")
	}
}

func TestMerkleOddDuplication(t *testing.T) {
	a := streebog.Sum256([]byte("a"))
	b := streebog.Sum256([]byte("b"))
	c := streebog.Sum256([]byte("c"))
	join := func(x, y [32]byte) [32]byte { return streebog.Sum256(append(append([]byte{}, x[:]...), y[:]...)) }
	want := join(join(a, b), join(c, c))
	got, err := MerkleRoot([][32]byte{a, b, c})
	if err != nil || got != want {
		t.Fatalf("odd tree: %x %v", got, err)
	}
	one, err := MerkleRoot([][32]byte{a})
	if err != nil || one != a {
		t.Fatal("one leaf changed")
	}
	if _, err := MerkleRoot(nil); err == nil {
		t.Fatal("empty tree accepted")
	}
	d := streebog.Sum256([]byte("d"))
	e := streebog.Sum256([]byte("e"))
	// Five leaves: H(H(H(a,b),H(c,d)), H(H(e,e),H(e,e))).
	left := join(join(a, b), join(c, d))
	right := join(join(e, e), join(e, e))
	five, err := MerkleRoot([][32]byte{a, b, c, d, e})
	if err != nil || five != join(left, right) {
		t.Fatalf("five-leaf tree: %x %v", five, err)
	}
}

func TestGeneratePersistVerifyAndTamper(t *testing.T) {
	when := time.Date(2026, 10, 27, 12, 0, 0, 0, time.FixedZone("MSK", 3*3600))
	block, err := Generate("Иванов Иван", when)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Transactions) != 5 {
		t.Fatal("wrong transaction count")
	}
	nonces := map[string]bool{}
	for _, tx := range block.Transactions {
		if len(tx.Data) != 200 || len(tx.Signature) != 96 {
			t.Fatal("wrong record size")
		}
		r := hex.EncodeToString(tx.Signature[:64])
		if nonces[r] {
			t.Fatal("repeated nonce")
		}
		nonces[r] = true
	}
	if !bytes.Contains(block.Transactions[0].Data, []byte("Иванов Иван")) {
		t.Fatal("name not embedded")
	}
	header, err := hex.DecodeString(block.Header)
	if err != nil || len(header) != 76 {
		t.Fatal("wrong header")
	}
	for _, v := range header[:4] {
		if v == 0 {
			t.Fatal("zero size byte")
		}
	}
	if !bytes.Equal(header[68:72], []byte{12, 27, 10, 26}) {
		t.Fatal("wrong timestamp")
	}
	hash := streebog.Sum256(header)
	if hash[0]&0xf8 != 0 || hex.EncodeToString(hash[:]) != block.Hash {
		t.Fatal("invalid proof of work")
	}
	dir := filepath.Join(t.TempDir(), "block")
	if err = block.Save(dir); err != nil {
		t.Fatal(err)
	}
	if err = VerifyDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err = block.Save(dir); err == nil {
		t.Fatal("output overwrite allowed")
	}
	txpath := filepath.Join(dir, "tx01.bin")
	original, _ := os.ReadFile(txpath)
	changed := append([]byte{}, original...)
	changed[199] ^= 1
	os.WriteFile(txpath, changed, 0600)
	if err = VerifyDirectory(dir); err == nil {
		t.Fatal("modified transaction accepted")
	}
	os.WriteFile(txpath, original, 0600)
	sigpath := filepath.Join(dir, "tx01.sig")
	signature, _ := os.ReadFile(sigpath)
	changed = append([]byte{}, signature...)
	changed[95] ^= 1
	os.WriteFile(sigpath, changed, 0600)
	if err = VerifyDirectory(dir); err == nil {
		t.Fatal("modified signature accepted")
	}
	os.WriteFile(sigpath, signature, 0600)
	manifestPath := filepath.Join(dir, "block.json")
	manifest, _ := os.ReadFile(manifestPath)
	changed = bytes.Replace(manifest, []byte(block.Hash), bytes.Repeat([]byte("0"), 64), 1)
	os.WriteFile(manifestPath, changed, 0600)
	if err = VerifyDirectory(dir); err == nil {
		t.Fatal("modified claimed hash accepted")
	}
	changedHeader := append([]byte(nil), header...)
	changedHeader[4] ^= 1
	changed = bytes.Replace(manifest, []byte(block.Header), []byte(hex.EncodeToString(changedHeader)), 1)
	if err = os.WriteFile(manifestPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyDirectory(dir); err == nil {
		t.Fatal("modified header accepted")
	}
}
