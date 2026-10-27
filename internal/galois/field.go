// Package galois implements bounded finite extension fields without dependencies.
package galois

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxOrder = 65536
const MaxPlainBytes = 1 << 20

type Field struct {
	P, N, Q int
	Modulus []int
}

func New(p, n int, modulus []int) (*Field, error) {
	if p < 2 || p > MaxOrder || n < 1 || n > 16 {
		return nil, errors.New("требуются простое p, 1<=n<=16 и p^n<=65536")
	}
	for d := 2; d*d <= p; d++ {
		if p%d == 0 {
			return nil, errors.New("p не является простым")
		}
	}
	q := 1
	for i := 0; i < n; i++ {
		if q > MaxOrder/p {
			return nil, errors.New("p^n превышает предел 65536")
		}
		q *= p
	}
	f := &Field{P: p, N: n, Q: q}
	if modulus == nil {
		for i := 0; i < q; i++ {
			candidate := append(f.digits(i, n), 1)
			if f.irreducible(candidate) {
				f.Modulus = candidate
				return f, nil
			}
		}
		return nil, errors.New("не найден неприводимый многочлен")
	}
	if len(modulus) != n+1 || modulus[n] != 1 {
		return nil, errors.New("многочлен должен быть унитарным степени n")
	}
	for _, v := range modulus {
		if v < 0 || v >= p {
			return nil, errors.New("коэффициенты должны лежать в [0,p)")
		}
	}
	if !f.irreducible(modulus) {
		return nil, errors.New("многочлен приводим")
	}
	f.Modulus = append([]int(nil), modulus...)
	return f, nil
}
func (f *Field) digits(x, n int) []int {
	a := make([]int, n)
	for i := range a {
		a[i] = x % f.P
		x /= f.P
	}
	return a
}
func (f *Field) index(a []int) int {
	v := 0
	for i := len(a) - 1; i >= 0; i-- {
		v = v*f.P + a[i]
	}
	return v
}
func (f *Field) mod(x int) int {
	x %= f.P
	if x < 0 {
		x += f.P
	}
	return x
}
func (f *Field) irreducible(poly []int) bool {
	count := 1
	for d := 1; d <= f.N/2; d++ {
		count *= f.P
		for idx := 0; idx < count; idx++ {
			div := append(f.digits(idx, d), 1)
			rem := append([]int(nil), poly...)
			for k := f.N; k >= d; k-- {
				v := rem[k]
				for j := 0; j <= d; j++ {
					rem[k-d+j] = f.mod(rem[k-d+j] - v*div[j])
				}
			}
			divisible := true
			for _, v := range rem[:d] {
				if v != 0 {
					divisible = false
					break
				}
			}
			if divisible {
				return false
			}
		}
	}
	return true
}

// Arithmetic accepts canonical element indices in [0,Q).
func (f *Field) Add(x, y int) int {
	a, b := f.digits(x, f.N), f.digits(y, f.N)
	for i := range a {
		a[i] = (a[i] + b[i]) % f.P
	}
	return f.index(a)
}
func (f *Field) Neg(x int) int {
	a := f.digits(x, f.N)
	for i := range a {
		a[i] = f.mod(-a[i])
	}
	return f.index(a)
}
func (f *Field) Mul(x, y int) int {
	a, b := f.digits(x, f.N), f.digits(y, f.N)
	c := make([]int, 2*f.N-1)
	for i, v := range a {
		for j, w := range b {
			c[i+j] = (c[i+j] + v*w) % f.P
		}
	}
	for k := len(c) - 1; k >= f.N; k-- {
		v := c[k]
		for j := 0; j < f.N; j++ {
			c[k-f.N+j] = f.mod(c[k-f.N+j] - v*f.Modulus[j])
		}
	}
	return f.index(c[:f.N])
}
func (f *Field) Pow(x, n int) int {
	result := 1
	for n > 0 {
		if n&1 != 0 {
			result = f.Mul(result, x)
		}
		x = f.Mul(x, x)
		n >>= 1
	}
	return result
}
func (f *Field) Inv(x int) (int, error) {
	if x <= 0 || x >= f.Q {
		return 0, errors.New("обратный элемент требует 0<x<q")
	}
	return f.Pow(x, f.Q-2), nil
}
func factors(n int) []int {
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
func (f *Field) IsGenerator(x int) bool {
	if x <= 0 || x >= f.Q {
		return false
	}
	for _, d := range factors(f.Q - 1) {
		if f.Pow(x, (f.Q-1)/d) == 1 {
			return false
		}
	}
	return true
}
func (f *Field) Generators() []int {
	var out []int
	for x := 1; x < f.Q; x++ {
		if f.IsGenerator(x) {
			out = append(out, x)
		}
	}
	return out
}
func (f *Field) Powers(x int) []int {
	if !f.IsGenerator(x) {
		return nil
	}
	out := make([]int, f.Q-1)
	v := 1
	for i := range out {
		out[i] = v
		v = f.Mul(v, x)
	}
	return out
}

type affineRecord struct {
	Version int   `json:"version"`
	P       int   `json:"p"`
	N       int   `json:"n"`
	Modulus []int `json:"modulus"`
	Length  int   `json:"length"`
	Symbols []int `json:"symbols"`
}

func (f *Field) width() int {
	k, capacity := 1, f.Q
	for capacity < 256 {
		k++
		capacity *= f.Q
	}
	return k
}
func (f *Field) key(alpha, beta int) error {
	if alpha <= 0 || alpha >= f.Q || beta < 0 || beta >= f.Q {
		return errors.New("требуются 0<alpha<q и 0<=beta<q")
	}
	return nil
}
func (f *Field) Encrypt(data []byte, alpha, beta int) ([]byte, error) {
	if err := f.key(alpha, beta); err != nil {
		return nil, err
	}
	if len(data) > MaxPlainBytes {
		return nil, errors.New("исходные данные превышают 1 МиБ")
	}
	k := f.width()
	r := affineRecord{Version: 1, P: f.P, N: f.N, Modulus: append([]int(nil), f.Modulus...), Length: len(data), Symbols: make([]int, 0, len(data)*k)}
	for _, b := range data {
		v := int(b)
		for j := 0; j < k; j++ {
			r.Symbols = append(r.Symbols, f.Add(f.Mul(alpha, v%f.Q), beta))
			v /= f.Q
		}
	}
	return json.Marshal(r)
}
func (f *Field) Decrypt(data []byte, alpha, beta int) ([]byte, error) {
	if err := f.key(alpha, beta); err != nil {
		return nil, err
	}
	if len(data) > 20<<20 {
		return nil, errors.New("контейнер превышает 20 МиБ")
	}
	var r affineRecord
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("лишние данные после JSON")
	}
	if r.Version != 1 || r.P != f.P || r.N != f.N || len(r.Modulus) != len(f.Modulus) {
		return nil, errors.New("неверная версия или параметры поля")
	}
	for i, v := range f.Modulus {
		if r.Modulus[i] != v {
			return nil, errors.New("другой многочлен поля")
		}
	}
	k := f.width()
	if r.Length < 0 || r.Length > MaxPlainBytes || len(r.Symbols) != r.Length*k {
		return nil, errors.New("неверная длина контейнера")
	}
	inverse, _ := f.Inv(alpha)
	out := make([]byte, r.Length)
	for i := range out {
		v, place := 0, 1
		for j := 0; j < k; j++ {
			y := r.Symbols[i*k+j]
			if y < 0 || y >= f.Q {
				return nil, errors.New("элемент шифртекста вне поля")
			}
			x := f.Mul(inverse, f.Add(y, f.Neg(beta)))
			v += x * place
			place *= f.Q
		}
		if v > 255 {
			return nil, errors.New("неканоническое кодирование байта: возможно, неверный ключ")
		}
		out[i] = byte(v)
	}
	return out, nil
}
