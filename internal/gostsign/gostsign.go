// Package gostsign implements educational GOST R 34.10-2012 signatures.
package gostsign

import (
	"crypto/rand"
	"errors"
	"math/big"

	"cryptolabs/internal/ec"
	"cryptolabs/internal/streebog"
)

// Scheme contains the curve, prime subgroup order and its base point.
// Parameters must be established and trusted, not supplied by a signed file.
type Scheme struct {
	C *ec.Curve
	Q *big.Int
	G ec.Point
}

// TestScheme constructs the 256-bit test parameters in RFC 7091 section 7.
// The RFC explicitly recommends this curve only for testing implementations.
func TestScheme() *Scheme {
	num := func(h string) *big.Int {
		n, ok := new(big.Int).SetString(h, 16)
		if !ok {
			panic("invalid RFC parameter")
		}
		return n
	}
	c, err := ec.New(num("8000000000000000000000000000000000000000000000000000000000000431"), big.NewInt(7), num("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"))
	if err != nil {
		panic(err)
	}
	return &Scheme{C: c, Q: num("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"), G: ec.Point{X: big.NewInt(2), Y: num("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8")}}
}
func (s *Scheme) validScalar(n *big.Int) bool { return n != nil && n.Sign() > 0 && n.Cmp(s.Q) < 0 }
func (s *Scheme) Public(d *big.Int) (ec.Point, error) {
	if !s.validScalar(d) {
		return ec.Point{}, errors.New("секретный ключ вне диапазона 1..q-1")
	}
	return s.C.Mul(s.G, d), nil
}
func (s *Scheme) randomScalar() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, s.Q)
		if err != nil {
			return nil, err
		}
		if n.Sign() != 0 {
			return n, nil
		}
	}
}
func (s *Scheme) GenerateKey() (*big.Int, ec.Point, error) {
	d, err := s.randomScalar()
	if err != nil {
		return nil, ec.Point{}, err
	}
	p, err := s.Public(d)
	return d, p, err
}
func (s *Scheme) ValidatePublic(p ec.Point) error {
	if p.Inf || p.X == nil || p.Y == nil || !s.C.OnCurve(p) {
		return errors.New("открытая точка не принадлежит кривой")
	}
	if !s.C.Mul(p, s.Q).Inf {
		return errors.New("открытая точка не принадлежит подгруппе q")
	}
	return nil
}
func (s *Scheme) normalizedE(e *big.Int) *big.Int {
	n := new(big.Int).Mod(new(big.Int).Set(e), s.Q)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n
}
func (s *Scheme) digestE(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return s.normalizedE(new(big.Int).SetBytes(rev))
}

var errRetry = errors.New("нулевое r или s: требуется новое k")

func (s *Scheme) signE(e, d, k *big.Int) ([]byte, error) {
	if e == nil || !s.validScalar(d) || !s.validScalar(k) {
		return nil, errors.New("неверные параметры подписи")
	}
	c := s.C.Mul(s.G, k)
	if c.Inf {
		return nil, errRetry
	}
	r := new(big.Int).Mod(c.X, s.Q)
	n := new(big.Int).Mul(r, d)
	n.Add(n, new(big.Int).Mul(k, s.normalizedE(e)))
	n.Mod(n, s.Q)
	if r.Sign() == 0 || n.Sign() == 0 {
		return nil, errRetry
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	n.FillBytes(sig[32:])
	return sig, nil
}
func (s *Scheme) Sign(data []byte, d *big.Int) ([]byte, error) {
	if !s.validScalar(d) {
		return nil, errors.New("неверный секретный ключ")
	}
	digest := streebog.Sum256(data)
	e := s.digestE(digest[:])
	for {
		k, err := s.randomScalar()
		if err != nil {
			return nil, err
		}
		sig, err := s.signE(e, d, k)
		if errors.Is(err, errRetry) {
			continue
		}
		return sig, err
	}
}
func (s *Scheme) verifyE(e *big.Int, p ec.Point, sig []byte) bool {
	if e == nil || len(sig) != 64 || s.ValidatePublic(p) != nil {
		return false
	}
	r, n := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !s.validScalar(r) || !s.validScalar(n) {
		return false
	}
	v := new(big.Int).ModInverse(s.normalizedE(e), s.Q)
	if v == nil {
		return false
	}
	z1 := new(big.Int).Mul(n, v)
	z1.Mod(z1, s.Q)
	z2 := new(big.Int).Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, s.Q)
	c := s.C.Add(s.C.Mul(s.G, z1), s.C.Mul(p, z2))
	return !c.Inf && new(big.Int).Mod(c.X, s.Q).Cmp(r) == 0
}
func (s *Scheme) Verify(data []byte, p ec.Point, sig []byte) bool {
	digest := streebog.Sum256(data)
	return s.verifyE(s.digestE(digest[:]), p, sig)
}
