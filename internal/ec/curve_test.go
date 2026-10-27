package ec

import (
	"math/big"
	"testing"
)

func bi(x int64) *big.Int { return big.NewInt(x) }
func pt(x, y int64) Point { return Point{X: bi(x), Y: bi(y)} }
func eq(p, q Point) bool {
	return p.Inf && q.Inf || !p.Inf && !q.Inf && p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}
func TestGroupArithmetic(t *testing.T) {
	c, err := New(bi(17), bi(2), bi(2))
	if err != nil {
		t.Fatal(err)
	}
	p := pt(5, 1)
	if !eq(c.Add(p, p), pt(6, 3)) || !eq(c.Mul(p, bi(3)), pt(10, 6)) {
		t.Fatal("known multiples")
	}
	if !c.Add(p, c.Neg(p)).Inf || !c.Mul(p, bi(19)).Inf || !eq(c.Mul(p, bi(-1)), pt(5, 16)) {
		t.Fatal("identity/inverse")
	}
	if p.X.Int64() != 5 || p.Y.Int64() != 1 {
		t.Fatal("mutated input")
	}
	q := c.Add(p, Point{Inf: true})
	q.X.SetInt64(0)
	if p.X.Int64() != 5 {
		t.Fatal("aliased return")
	}
	z, _ := New(bi(5), bi(1), bi(0))
	if !z.Add(pt(0, 0), pt(0, 0)).Inf {
		t.Fatal("y zero")
	}
	if c.OnCurve(Point{}) || c.OnCurve(pt(5, 2)) || c.OnCurve(pt(22, 1)) {
		t.Fatal("invalid point accepted")
	}
	huge := new(big.Int).Lsh(bi(19), 512)
	huge.Add(huge, bi(3))
	if !eq(c.Mul(p, huge), pt(10, 6)) {
		t.Fatal("big scalar truncated")
	}
}
func TestInvalidCurve(t *testing.T) {
	for _, v := range [][3]int64{{3, 1, 1}, {15, 1, 1}, {17, 0, 0}} {
		if _, err := New(bi(v[0]), bi(v[1]), bi(v[2])); err == nil {
			t.Fatal(v)
		}
	}
	if _, err := New(nil, bi(1), bi(1)); err == nil {
		t.Fatal("nil modulus")
	}
}
func TestExactEnumerationAndPrimeSubgroups(t *testing.T) {
	c, _ := New(bi(17), bi(2), bi(2))
	points, err := c.Points()
	if err != nil || len(points) != 19 {
		t.Fatalf("count %d %v", len(points), err)
	}
	groups, err := c.PrimeSubgroups()
	if err != nil || len(groups) != 1 || groups[0].Order != 19 || len(groups[0].Points) != 19 {
		t.Fatalf("subgroups %+v %v", groups, err)
	}
	d, _ := New(bi(5), bi(1), bi(0))
	groups, err = d.PrimeSubgroups()
	if err != nil || len(groups) != 3 {
		t.Fatalf("noncyclic group subgroups=%+v %v", groups, err)
	}
	large, _ := New(bi(1031), bi(1), bi(0))
	points, err = large.Points()
	if err != nil || len(points) != 1032 {
		t.Fatalf("demonstration order=%d %v", len(points), err)
	}
	tooBig, _ := New(bi(65537), bi(1), bi(0))
	if _, err = tooBig.Points(); err == nil {
		t.Fatal("unbounded enumeration")
	}
}
