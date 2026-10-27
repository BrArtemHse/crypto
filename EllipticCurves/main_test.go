package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIExactCountAndScalar(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"info", "--limit", "0"}, &out); err != nil || !strings.Contains(out.String(), "1032") {
		t.Fatalf("%s %v", out.String(), err)
	}
	out.Reset()
	if err := run([]string{"mul", "--p", "17", "--a", "2", "--b", "2", "--point", "5,1", "--k", "3"}, &out); err != nil || strings.TrimSpace(out.String()) != "(10,6)" {
		t.Fatalf("%s %v", out.String(), err)
	}
	for _, args := range [][]string{{"add", "--point", "1,1"}, {"info", "--limit", "-1"}, {"info", "--p", "65537"}, {"mul", "--k", "bad"}, {"bad"}, {"info", "extra"}} {
		if err := run(args, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
