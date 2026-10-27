package blockchain

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"cryptolabs/internal/streebog"
)

// Parameters returns fresh copies of p,q,a from GOST R 34.10-94, A.3.
// The constants were transcribed row-wise from the printed standard, page 12.
func Parameters() (p, q, g *big.Int) {
	parse := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 16)
		if !ok {
			panic("invalid built-in group constant")
		}
		return v
	}
	p = parse("ee8172ae8996608fb69359b89eb82a69854510e2977a4d63bc97322ce5dc3386ea0a12b343e9190f23177539845839786bb0c345d165976ef2195ec9b1c379e3")
	q = parse("98915e7ec8265edfcda31e88f24809ddb064bdc7285dd50d7289f0ac6f49dd2d")
	g = parse("9e96031500c8774a869582d4afde2127afad2538b4b6270a6f7c8837b50d50f206755984a49e509304d648be2ab5aab18ebe2cd46ac3d8495b142aa6ce23e21c")
	return
}

func validateGroup() error {
	p, q, g := Parameters()
	if !p.ProbablyPrime(32) || !q.ProbablyPrime(32) || new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), q).Sign() != 0 || !member(g, p, q) {
		return errors.New("invalid built-in A.3 parameters")
	}
	return nil
}

type Signature struct{ R, S *big.Int }

func member(v, p, q *big.Int) bool {
	return v != nil && v.Cmp(big.NewInt(1)) > 0 && v.Cmp(p) < 0 && new(big.Int).Exp(v, q, p).Cmp(big.NewInt(1)) == 0
}

func challenge(r, public *big.Int, message []byte) *big.Int {
	input := make([]byte, 128, len(message)+128)
	r.FillBytes(input[:64])
	public.FillBytes(input[64:128])
	input = append(input, message...)
	h := streebog.Sum256(input)
	_, q, _ := Parameters()
	return new(big.Int).Mod(new(big.Int).SetBytes(h[:]), q)
}

func SignWithNonce(message []byte, x, k *big.Int) (Signature, error) {
	p, q, g := Parameters()
	if x == nil || k == nil || x.Sign() <= 0 || x.Cmp(q) >= 0 || k.Sign() <= 0 || k.Cmp(q) >= 0 {
		return Signature{}, errors.New("key and nonce must be in 1..q-1")
	}
	public := new(big.Int).Exp(g, x, p)
	r := new(big.Int).Exp(g, k, p)
	e := challenge(r, public, message)
	s := new(big.Int).Mul(e, x)
	s.Add(s, k).Mod(s, q)
	return Signature{r, s}, nil
}

func VerifySignature(message []byte, public *big.Int, sig Signature) bool {
	p, q, g := Parameters()
	if !member(public, p, q) || !member(sig.R, p, q) || sig.S == nil || sig.S.Sign() < 0 || sig.S.Cmp(q) >= 0 {
		return false
	}
	e := challenge(sig.R, public, message)
	left := new(big.Int).Exp(g, sig.S, p)
	right := new(big.Int).Exp(public, e, p)
	right.Mul(right, sig.R).Mod(right, p)
	return left.Cmp(right) == 0
}

func randomScalar(source io.Reader, q *big.Int) (*big.Int, error) {
	data := make([]byte, (q.BitLen()+7)/8)
	for {
		if _, err := io.ReadFull(source, data); err != nil {
			return nil, fmt.Errorf("read scalar: %w", err)
		}
		data[0] &= byte(0xff >> uint(len(data)*8-q.BitLen()))
		x := new(big.Int).SetBytes(data)
		if x.Sign() > 0 && x.Cmp(q) < 0 {
			return x, nil
		}
	}
}

func encodeSignature(sig Signature) []byte {
	data := make([]byte, 96)
	sig.R.FillBytes(data[:64])
	sig.S.FillBytes(data[64:])
	return data
}

func decodeSignature(data []byte) (Signature, error) {
	if len(data) != 96 {
		return Signature{}, errors.New("signature must be exactly 96 bytes")
	}
	return Signature{new(big.Int).SetBytes(data[:64]), new(big.Int).SetBytes(data[64:])}, nil
}
