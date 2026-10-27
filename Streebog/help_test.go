package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestHelpPrintsUsageAndSucceeds(t *testing.T) {
	for _, cmd := range []string{"hash", "check"} {
		t.Run(cmd, func(t *testing.T) {
			original := os.Stdout
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = writer
			defer func() { os.Stdout = original; reader.Close(); writer.Close() }()
			runErr := run([]string{cmd, "--help"})
			writer.Close()
			os.Stdout = original
			output, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if runErr != nil {
				t.Fatalf("help must succeed: %v", runErr)
			}
			if !strings.Contains(string(output), "Usage of "+cmd) || !strings.Contains(string(output), "-") {
				t.Fatalf("missing flag usage: %q", output)
			}
		})
	}
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("top-level help: %v", err)
	}
}
