// Package rsalab implements textbook RSA and bounded Fermat factorization.
// The deterministic file encoding is for study, not for protecting secrets.
package rsalab

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type PublicKey struct{ N, E *big.Int }
type PrivateKey struct {
	PublicKey
	D, P, Q *big.Int
}

var one = big.NewInt(1)

func validatePublic(k *PublicKey) error {
	if k == nil || k.N == nil || k.E == nil || k.N.BitLen() > 8192 || k.N.Cmp(big.NewInt(9)) < 0 || k.N.Bit(0) == 0 || k.E.Cmp(one) <= 0 || k.E.Cmp(k.N) >= 0 || k.E.Bit(0) == 0 {
		return errors.New("неверный открытый ключ RSA (нечётные n и e, 1<e<n, n до 8192 бит)")
	}
	return nil
}

func FromPrimes(p, q, e *big.Int) (*PrivateKey, error) {
	if p == nil || q == nil || e == nil || p.BitLen()+q.BitLen() > 8193 || p.Cmp(big.NewInt(3)) < 0 || q.Cmp(big.NewInt(3)) < 0 || p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, errors.New("p и q должны быть различными нечётными простыми (модуль до 8192 бит)")
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	pub := PublicKey{n, new(big.Int).Set(e)}
	if err := validatePublic(&pub); err != nil {
		return nil, err
	}
	if e.Cmp(phi) >= 0 {
		return nil, errors.New("требуется e<φ(n)")
	}
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("e не взаимно просто с φ(n)")
	}
	return &PrivateKey{pub, d, new(big.Int).Set(p), new(big.Int).Set(q)}, nil
}

func validatePrivate(k *PrivateKey) error {
	if k == nil || k.D == nil {
		return errors.New("неверный закрытый ключ RSA")
	}
	expected, err := FromPrimes(k.P, k.Q, k.E)
	if err != nil {
		return err
	}
	if k.N == nil || k.N.Cmp(expected.N) != 0 || k.D.Cmp(expected.D) != 0 {
		return errors.New("n или d не соответствует p,q,e")
	}
	return nil
}

func Generate(bits int) (*PrivateKey, error) {
	if bits < 32 || bits > 8192 {
		return nil, errors.New("размер RSA должен быть от 32 до 8192 бит")
	}
	for {
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, bits-bits/2)
		if err != nil {
			return nil, err
		}
		if new(big.Int).Mul(p, q).BitLen() != bits {
			continue
		}
		k, err := FromPrimes(p, q, big.NewInt(65537))
		if err == nil {
			return k, nil
		}
	}
}

func EncryptNumber(k *PublicKey, m *big.Int) (*big.Int, error) {
	if err := validatePublic(k); err != nil {
		return nil, err
	}
	if m == nil || m.Sign() < 0 || m.Cmp(k.N) >= 0 {
		return nil, errors.New("требуется 0≤m<n")
	}
	return new(big.Int).Exp(m, k.E, k.N), nil
}

func DecryptNumber(k *PrivateKey, c *big.Int) (*big.Int, error) {
	if err := validatePrivate(k); err != nil {
		return nil, err
	}
	if c == nil || c.Sign() < 0 || c.Cmp(k.N) >= 0 {
		return nil, errors.New("требуется 0≤c<n")
	}
	return new(big.Int).Exp(c, k.D, k.N), nil
}

// Fermat tests at most limit candidates A, including ceil(sqrt(n)).
func Fermat(n, e *big.Int, limit uint64) (*PrivateKey, uint64, error) {
	if err := validatePublic(&PublicKey{n, e}); err != nil {
		return nil, 0, err
	}
	if limit == 0 || limit > 10000000 {
		return nil, 0, errors.New("предел атаки должен быть от 1 до 10000000")
	}
	a := new(big.Int).Sqrt(n)
	square := new(big.Int).Mul(a, a)
	if square.Cmp(n) < 0 {
		a.Add(a, one)
	}
	for steps := uint64(1); steps <= limit; steps++ {
		delta := new(big.Int).Sub(new(big.Int).Mul(a, a), n)
		b := new(big.Int).Sqrt(delta)
		if new(big.Int).Mul(b, b).Cmp(delta) == 0 {
			p, q := new(big.Int).Sub(a, b), new(big.Int).Add(a, b)
			k, err := FromPrimes(p, q, e)
			if err != nil {
				return nil, steps, fmt.Errorf("найдено разложение, несовместимое с RSA: %w", err)
			}
			return k, steps, nil
		}
		a.Add(a, one)
	}
	return nil, limit, errors.New("предел итераций Ферма исчерпан")
}
