// Package ec implements affine arithmetic on short Weierstrass curves.
// Arithmetic methods require points on the curve; OnCurve validates external input.
// The implementation is educational and is not constant-time.
package ec

import (
	"errors"
	"fmt"
	"math/big"
)

type Point struct {
	X, Y *big.Int
	Inf  bool
}
type Curve struct{ P, A, B *big.Int }

func New(p, a, b *big.Int) (*Curve, error) {
	if p == nil || a == nil || b == nil || p.Cmp(big.NewInt(3)) <= 0 || !p.ProbablyPrime(32) {
		return nil, errors.New("p должно быть простым числом больше 3; a и b обязательны")
	}
	c := &Curve{P: new(big.Int).Set(p), A: new(big.Int).Mod(a, p), B: new(big.Int).Mod(b, p)}
	disc := new(big.Int).Exp(c.A, big.NewInt(3), p)
	disc.Mul(disc, big.NewInt(4))
	v := new(big.Int).Mul(c.B, c.B)
	v.Mul(v, big.NewInt(27))
	disc.Add(disc, v)
	disc.Mod(disc, p)
	if disc.Sign() == 0 {
		return nil, errors.New("вырожденная кривая: 4a^3+27b^2=0")
	}
	return c, nil
}
func copyPoint(p Point) Point {
	if p.Inf {
		return Point{Inf: true}
	}
	return Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}
func (c *Curve) OnCurve(p Point) bool {
	if p.Inf {
		return true
	}
	if p.X == nil || p.Y == nil || p.X.Sign() < 0 || p.Y.Sign() < 0 || p.X.Cmp(c.P) >= 0 || p.Y.Cmp(c.P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(p.Y, p.Y)
	lhs.Mod(lhs, c.P)
	rhs := new(big.Int).Exp(p.X, big.NewInt(3), c.P)
	rhs.Add(rhs, new(big.Int).Mul(c.A, p.X))
	rhs.Add(rhs, c.B)
	rhs.Mod(rhs, c.P)
	return lhs.Cmp(rhs) == 0
}
func (c *Curve) Neg(p Point) Point {
	if p.Inf {
		return Point{Inf: true}
	}
	return Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Mod(new(big.Int).Neg(p.Y), c.P)}
}
func (c *Curve) Add(p, q Point) Point {
	if p.Inf {
		return copyPoint(q)
	}
	if q.Inf {
		return copyPoint(p)
	}
	var numerator, denominator *big.Int
	if p.X.Cmp(q.X) == 0 {
		sum := new(big.Int).Add(p.Y, q.Y)
		sum.Mod(sum, c.P)
		if sum.Sign() == 0 {
			return Point{Inf: true}
		}
		numerator = new(big.Int).Mul(p.X, p.X)
		numerator.Mul(numerator, big.NewInt(3))
		numerator.Add(numerator, c.A)
		denominator = new(big.Int).Lsh(p.Y, 1)
	} else {
		numerator = new(big.Int).Sub(q.Y, p.Y)
		denominator = new(big.Int).Sub(q.X, p.X)
	}
	inverse := new(big.Int).ModInverse(denominator, c.P)
	// For valid points on a nonsingular prime-field curve, the inverse exists here.
	if inverse == nil {
		return Point{Inf: true}
	}
	slope := new(big.Int).Mul(numerator, inverse)
	slope.Mod(slope, c.P)
	x := new(big.Int).Mul(slope, slope)
	x.Sub(x, p.X)
	x.Sub(x, q.X)
	x.Mod(x, c.P)
	y := new(big.Int).Sub(p.X, x)
	y.Mul(y, slope)
	y.Sub(y, p.Y)
	y.Mod(y, c.P)
	return Point{X: x, Y: y}
}
func (c *Curve) Mul(p Point, k *big.Int) Point {
	if k == nil || k.Sign() == 0 || p.Inf {
		return Point{Inf: true}
	}
	n := new(big.Int).Abs(k)
	base := copyPoint(p)
	if k.Sign() < 0 {
		base = c.Neg(base)
	}
	result := Point{Inf: true}
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			result = c.Add(result, base)
		}
		base = c.Add(base, base)
	}
	return result
}

const MaxEnumerateP = 4096

// Points enumerates the whole group, including infinity, for bounded small p.
func (c *Curve) Points() ([]Point, error) {
	if !c.P.IsInt64() || c.P.Int64() > MaxEnumerateP {
		return nil, fmt.Errorf("точный перебор ограничен p <= %d", MaxEnumerateP)
	}
	p := int(c.P.Int64())
	roots := make([][]int, p)
	for y := 0; y < p; y++ {
		roots[y*y%p] = append(roots[y*y%p], y)
	}
	points := []Point{{Inf: true}}
	a, b := int(c.A.Int64()), int(c.B.Int64())
	for x := 0; x < p; x++ {
		rhs := (x*x%p*x + a*x + b) % p
		for _, y := range roots[rhs] {
			points = append(points, Point{X: big.NewInt(int64(x)), Y: big.NewInt(int64(y))})
		}
	}
	return points, nil
}

type PrimeSubgroup struct {
	Order     int
	Generator Point
	Points    []Point
}

func primeFactors(n int) []int {
	var out []int
	for d := 2; d*d <= n; d++ {
		if n%d == 0 {
			out = append(out, d)
			for n%d == 0 {
				n /= d
			}
		}
	}
	if n > 1 {
		out = append(out, n)
	}
	return out
}
func pointKey(p Point) string {
	if p.Inf {
		return "O"
	}
	return p.X.String() + "," + p.Y.String()
}

// PrimeSubgroups returns every distinct cyclic subgroup of prime order.
func (c *Curve) PrimeSubgroups() ([]PrimeSubgroup, error) {
	points, err := c.Points()
	if err != nil {
		return nil, err
	}
	n := len(points)
	factors := primeFactors(n)
	seen := make(map[int]map[string]bool)
	for _, l := range factors {
		seen[l] = make(map[string]bool)
	}
	var groups []PrimeSubgroup
	for _, p := range points[1:] {
		order := n
		for _, l := range factors {
			for order%l == 0 && c.Mul(p, big.NewInt(int64(order/l))).Inf {
				order /= l
			}
		}
		for _, l := range factors {
			if order%l != 0 {
				continue
			}
			g := c.Mul(p, big.NewInt(int64(order/l)))
			if seen[l][pointKey(g)] {
				continue
			}
			group := PrimeSubgroup{Order: l, Generator: copyPoint(g), Points: []Point{{Inf: true}}}
			q := copyPoint(g)
			for i := 1; i < l; i++ {
				group.Points = append(group.Points, copyPoint(q))
				seen[l][pointKey(q)] = true
				q = c.Add(q, g)
			}
			groups = append(groups, group)
		}
	}
	return groups, nil
}
