package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIKeygenRoundtripAttackAndCollisions(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "pub.json")
	priv := filepath.Join(dir, "priv.json")
	in := filepath.Join(dir, "in")
	enc := filepath.Join(dir, "enc")
	out := filepath.Join(dir, "out")
	recovered := filepath.Join(dir, "recovered.json")
	data := []byte("\x00\x00Привет\xff")
	_ = os.WriteFile(in, data, 0600)
	if err := run([]string{"number", "--p", "61", "--q", "53", "--e", "17", "--message", "65"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--p", "61", "--q", "53", "--e", "17", "--public", pub, "--private", priv}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"encrypt", "--key", pub, "--in", in, "--out", enc}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"decrypt", "--key", priv, "--in", enc, "--out", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, data) {
		t.Fatal("binary roundtrip")
	}
	if err := run([]string{"attack", "--key", pub, "--iterations", "10", "--out", recovered}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"encrypt", "--key", pub, "--in", in, "--out", in}, {"decrypt", "--key", priv, "--in", enc, "--out", out}, {"keygen", "--p", "61", "--q", "53", "--public", pub, "--private", priv}, {"keygen", "--bits", "256", "--public", filepath.Join(dir, "new-pub"), "--private", priv}} {
		if err := run(args); err == nil {
			t.Fatal("collision accepted", args)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new-pub")); !os.IsNotExist(err) {
		t.Fatal("partial key output")
	}
	got, _ = os.ReadFile(in)
	if !bytes.Equal(got, data) {
		t.Fatal("input changed")
	}
}
