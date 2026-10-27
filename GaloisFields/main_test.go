package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIArithmeticAndAffine(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"mul", "--p", "2", "--n", "8", "--poly", "1,1,0,1,1,0,0,0,1", "--x", "87", "--y", "19"}, &out); err != nil || out.String() != "254\n" {
		t.Fatalf("%s %v", out.String(), err)
	}
	enc := filepath.Join(t.TempDir(), "cipher.json")
	out.Reset()
	if err := run([]string{"encrypt", "--p", "3", "--n", "2", "--alpha", "3", "--beta", "5", "--text", "Привет!", "--out", enc}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"decrypt", "--p", "3", "--n", "2", "--alpha", "3", "--beta", "5", "--in", enc}, &out); err != nil || out.String() != "Привет!" {
		t.Fatalf("%s %v", out.String(), err)
	}
	if err := run([]string{"encrypt", "--out", enc}, &out); err == nil {
		t.Fatal("overwrote file")
	}
	if _, err := os.Stat(enc); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"mul", "--x", "-1"}, {"field", "extra"}, {"field", "--p", "4"}, {"bad"}, {"field", "--poly", "1,x,1"}} {
		if err := run(args, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
