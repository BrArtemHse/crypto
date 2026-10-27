package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignatureCLI(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private.json")
	public := filepath.Join(dir, "public.json")
	in := filepath.Join(dir, "file")
	sig := filepath.Join(dir, "sig")
	if err := os.WriteFile(in, []byte("\x00\xffПример"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "-private", private, "-public", public}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "-in", in, "-key", private, "-out", sig}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-in", in, "-key", public, "-sig", sig}); err != nil {
		t.Fatal(err)
	}
	savedSig, err := os.ReadFile(sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(savedSig) != 64 {
		t.Fatal("signature must have 64 binary bytes")
	}
	for _, badSig := range [][]byte{nil, savedSig[:63], append(append([]byte{}, savedSig...), 0), make([]byte, 64)} {
		if err := os.WriteFile(sig, badSig, 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"verify", "-in", in, "-key", public, "-sig", sig}); err == nil {
			t.Fatal("bad signature accepted")
		}
	}
	if err := os.WriteFile(sig, savedSig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "-private", private, "-public", public}); err == nil {
		t.Fatal("key overwrite")
	}
	if err := run([]string{"sign", "-in", in, "-key", private, "-out", in}); err == nil {
		t.Fatal("input overwrite")
	}
	if err := os.WriteFile(in, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-in", in, "-key", public, "-sig", sig}); err == nil {
		t.Fatal("changed file accepted")
	}
	if err := os.WriteFile(public, []byte(`{"algorithm":"unknown","x":"00","y":"00"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-in", in, "-key", public, "-sig", sig}); err == nil {
		t.Fatal("bad key accepted")
	}
	fresh := filepath.Join(dir, "fresh")
	if err := run([]string{"keygen", "-private", fresh, "-public", public}); err == nil {
		t.Fatal("partial collision accepted")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("left partial key on collision")
	}
	for _, args := range [][]string{nil, {"unknown"}, {"keygen"}, {"sign"}, {"verify"}, {"keygen", "-private", fresh, "-public", fresh}} {
		if err := run(args); err == nil {
			t.Fatal("bad args accepted")
		}
	}
}

func TestMalformedPrivateKeys(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	in := filepath.Join(dir, "input")
	out := filepath.Join(dir, "signature")
	if err := os.WriteFile(in, nil, 0600); err != nil {
		t.Fatal(err)
	}
	valid := `{"algorithm":"gost3410-2012-256-rfc7091-test","d":"` + strings.Repeat("0", 63) + `1"}`
	cases := []string{`{}`, `null`, valid + ` {}`, strings.Replace(valid, `}`, `,"unknown":1}`, 1), strings.Replace(valid, strings.Repeat("0", 63)+"1", "00", 1), strings.Replace(valid, strings.Repeat("0", 63)+"1", strings.Repeat("0", 64), 1), strings.Repeat("x", 10000)}
	for _, bad := range cases {
		if err := os.WriteFile(key, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"sign", "-in", in, "-key", key, "-out", out}); err == nil {
			t.Fatal("malformed key accepted")
		}
	}
}
