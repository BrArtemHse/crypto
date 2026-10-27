package galois

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAESFieldAndInverses(t *testing.T) {
	f, err := New(2, 8, []int{1, 1, 0, 1, 1, 0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Mul(0x57, 0x13); got != 0xfe {
		t.Fatalf("AES product=%x", got)
	}
	for x := 1; x < f.Q; x++ {
		v, err := f.Inv(x)
		if err != nil || f.Mul(x, v) != 1 {
			t.Fatalf("inverse %d", x)
		}
	}
	if _, err = f.Inv(0); err == nil {
		t.Fatal("zero inverse accepted")
	}
}

func TestAffineContainerValidation(t *testing.T) {
	f, _ := New(2, 1, nil)
	enc, err := f.Encrypt([]byte{42}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err = json.Unmarshal(enc, &obj); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["length"] = 2 },
		func(m map[string]any) { m["symbols"] = []int{2, 0, 0, 0, 0, 0, 0, 0} },
		func(m map[string]any) { m["version"] = 2 },
		func(m map[string]any) { m["p"] = 3 },
	} {
		var m map[string]any
		json.Unmarshal(enc, &m)
		change(m)
		bad, _ := json.Marshal(m)
		if _, err = f.Decrypt(bad, 1, 0); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, err = f.Decrypt(append(enc, []byte(` {}`)...), 1, 0); err == nil {
		t.Fatal("trailing JSON")
	}
	g, _ := New(3, 1, nil)
	raw, _ := g.Encrypt([]byte{0}, 1, 0)
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["symbols"] = []int{2, 2, 2, 2, 2, 2}
	bad, _ := json.Marshal(m)
	if _, err = g.Decrypt(bad, 1, 0); err == nil {
		t.Fatal("noncanonical byte")
	}
}

func TestValidationAndOddCharacteristic(t *testing.T) {
	for _, tt := range []struct {
		p, n int
		mod  []int
	}{{4, 2, nil}, {2, 0, nil}, {2, 2, []int{1, 0, 1}}, {3, 2, []int{1, 0, 2}}, {65537, 1, nil}} {
		if _, err := New(tt.p, tt.n, tt.mod); err == nil {
			t.Fatalf("accepted %+v", tt)
		}
	}
	f, err := New(3, 2, []int{1, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if f.Mul(3, 3) != 2 || f.Add(8, 8) != 4 {
		t.Fatal("GF(9) arithmetic")
	}
	g, err := New(3, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	gens := g.Generators()
	if len(gens) != 4 {
		t.Fatalf("generators=%v", gens)
	}
	if len(g.Powers(gens[0])) != 8 {
		t.Fatal("powers")
	}
}

func TestSmallFieldLaws(t *testing.T) {
	for _, pn := range [][2]int{{2, 2}, {3, 2}, {5, 2}} {
		f, err := New(pn[0], pn[1], nil)
		if err != nil {
			t.Fatal(err)
		}
		for a := 0; a < f.Q; a++ {
			if f.Mul(a, 1) != a || f.Add(a, 0) != a || f.Add(a, f.Neg(a)) != 0 {
				t.Fatalf("identities %v %d", pn, a)
			}
			for b := 0; b < f.Q; b++ {
				if f.Mul(a, b) != f.Mul(b, a) {
					t.Fatal("commutativity")
				}
				for c := 0; c < f.Q; c++ {
					if f.Mul(a, f.Add(b, c)) != f.Add(f.Mul(a, b), f.Mul(a, c)) {
						t.Fatal("distributivity")
					}
				}
			}
		}
	}
}

func TestAffineBytesAndMalformed(t *testing.T) {
	data := append([]byte{0, 255, 0}, []byte("Привет, мир! 🌍")...)
	for _, pn := range [][2]int{{2, 1}, {3, 2}, {2, 8}, {257, 1}} {
		f, err := New(pn[0], pn[1], nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, src := range [][]byte{nil, data} {
			enc, err := f.Encrypt(src, 1, f.Q-1)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.Decrypt(enc, 1, f.Q-1)
			if err != nil || !bytes.Equal(got, src) {
				t.Fatalf("%v: %x %v", pn, got, err)
			}
		}
		if _, err := f.Encrypt(data, 0, 0); err == nil {
			t.Fatal("zero alpha")
		}
		if _, err := f.Decrypt([]byte(`{"version":1,"length":-1}`), 1, 0); err == nil {
			t.Fatal("malformed accepted")
		}
	}
}
