package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashCLI(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input")
	out := filepath.Join(dir, "digest")
	if err := os.WriteFile(in, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"hash", "-in", in, "-out", out}); err != nil {
		t.Fatal(err)
	}
	digest, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(digest) != "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb\n" {
		t.Fatalf("digest file: %q", digest)
	}
	if err := run([]string{"check", "-in", in, "-hash", out}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(" \n"+strings.ToUpper(string(digest))+" \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check", "-in", in, "-hash", out}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"hash", "-in", in, "-out", out}); err == nil {
		t.Fatal("overwrite accepted")
	}
	if err := run([]string{"hash", "-in", in, "-out", in}); err == nil {
		t.Fatal("input overwrite accepted")
	}
	if err := os.WriteFile(in, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check", "-in", in, "-hash", out}); err == nil {
		t.Fatal("changed file accepted")
	}
	for _, bad := range []string{"abc", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", string(make([]byte, 2000))} {
		if err := os.WriteFile(out, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"check", "-in", in, "-hash", out}); err == nil {
			t.Fatal("malformed digest accepted")
		}
	}
	for _, args := range [][]string{nil, {"unknown"}, {"hash"}, {"check", "-in", in}, {"hash", "-in", in, "extra"}} {
		if err := run(args); err == nil {
			t.Fatal("bad args accepted")
		}
	}
}
