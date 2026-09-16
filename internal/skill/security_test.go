package skill

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSecurityArguments(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "skill with spaces;echo")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	opts := SecurityOptions{Path: path, Format: "json"}
	got, err := opts.arguments()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"scan", path, "--format", "json", "--fail-on-findings", "--fail-on-incomplete", "--no-llm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	opts.LLM = true
	got, err = opts.arguments()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want[:len(want)-1]) {
		t.Fatalf("LLM args: %v", got)
	}
	for _, tc := range []struct {
		name string
		edit func(*SecurityOptions)
	}{
		{"missing input", func(o *SecurityOptions) { o.Path = filepath.Join(root, "missing") }},
		{"bad format", func(o *SecurityOptions) { o.Format = "xml" }},
		{"report in skill", func(o *SecurityOptions) { o.Output = filepath.Join(path, "report.json") }},
		{"baseline missing", func(o *SecurityOptions) { o.Baseline = filepath.Join(root, "missing") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			tc.edit(&o)
			if _, err := o.arguments(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	opts.Output = filepath.Join(root, "report.json")
	if _, err := opts.arguments(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.Output, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := opts.arguments(); err == nil {
		t.Fatal("must not overwrite report")
	}
}

func TestSecurityRunner(t *testing.T) {
	opts := SecurityOptions{Path: t.TempDir(), Executable: "scanner", Format: "json", Timeout: time.Second}
	sentinel := errors.New("scanner missing")
	called := false
	run := func(ctx context.Context, bin string, args []string, out, errout io.Writer) error {
		called = true
		if bin != "scanner" || args[0] != "scan" {
			t.Fatalf("unexpected invocation %s %v", bin, args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing deadline")
		}
		return sentinel
	}
	err := scanSecurity(context.Background(), opts, io.Discard, io.Discard, run)
	if !called || !errors.Is(err, sentinel) {
		t.Fatalf("scanner error was lost: %v", err)
	}
	opts.Timeout = 0
	called = false
	if err := scanSecurity(context.Background(), opts, io.Discard, io.Discard, run); err == nil || called {
		t.Fatal("invalid timeout executed scanner")
	}
	opts.Timeout = time.Millisecond
	timeoutRun := func(ctx context.Context, _ string, _ []string, _, _ io.Writer) error { <-ctx.Done(); return ctx.Err() }
	if err := scanSecurity(context.Background(), opts, io.Discard, io.Discard, timeoutRun); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}

func TestSecurityProcessHelper(t *testing.T) {
	if os.Getenv("SKILL_UP_SCANNER_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "findings":
		os.Exit(1)
	case "failure":
		os.Exit(2)
	default:
		os.Exit(0)
	}
}

func TestSecurityProcessExit(t *testing.T) {
	t.Setenv("SKILL_UP_SCANNER_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	opts := SecurityOptions{Path: t.TempDir(), Executable: executable, Format: "json", Timeout: 10 * time.Second}
	for _, tc := range []struct{ name, want string }{
		{"clean", ""}, {"findings", "findings, elevated risk, or incomplete"}, {"failure", "execution failed (exit 2)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(ctx context.Context, bin string, _ []string, out, errout io.Writer) error {
				return runSecurityProcess(ctx, bin, []string{"-test.run=^TestSecurityProcessHelper$", "--", tc.name}, out, errout)
			}
			err := scanSecurity(context.Background(), opts, io.Discard, io.Discard, run)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
