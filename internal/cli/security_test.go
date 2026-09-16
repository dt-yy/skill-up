package cli

import (
	"io"
	"testing"
)

func TestSecurityCommandRejectsInvalidInput(t *testing.T) {
	for _, args := range [][]string{{}, {"--format", "xml", t.TempDir()}, {"--timeout", "0s", t.TempDir()}} {
		cmd := newSecurityCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}
