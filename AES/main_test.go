package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIProtectsFiles(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	enc := filepath.Join(dir, "enc")
	out := filepath.Join(dir, "out")
	data := []byte{0, 0, 255, 42}
	_ = os.WriteFile(in, data, 0600)
	key := "000102030405060708090a0b0c0d0e0f"
	if err := run([]string{"encrypt", "--key", key, "--in", in, "--out", enc}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"decrypt", "--key", key, "--in", enc, "--out", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, data) {
		t.Fatal("binary roundtrip")
	}
	if err := run([]string{"encrypt", "--key", key, "--in", in, "--out", in}); err == nil {
		t.Fatal("input overwritten")
	}
	if err := run([]string{"decrypt", "--key", key, "--in", enc, "--out", out}); err == nil {
		t.Fatal("output overwritten")
	}
	if err := run([]string{"encrypt", "--key", "ff", "--in", in, "--out", filepath.Join(dir, "bad")}); err == nil {
		t.Fatal("bad key")
	}
	got, _ = os.ReadFile(in)
	if !bytes.Equal(got, data) {
		t.Fatal("input changed")
	}
}
