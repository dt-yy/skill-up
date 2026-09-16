package skill

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// SecurityOptions configures a SkillSpector scan of a local skill.
type SecurityOptions struct {
	Path       string
	Executable string
	Format     string
	Output     string
	Baseline   string
	LLM        bool
	Timeout    time.Duration
}

type securityRunner func(context.Context, string, []string, io.Writer, io.Writer) error

// ScanSecurity runs the optional SkillSpector CLI without invoking a shell.
// Reports are owned by SkillSpector; nonzero exits always fail the command.
func ScanSecurity(ctx context.Context, opts SecurityOptions, stdout, stderr io.Writer) error {
	return scanSecurity(ctx, opts, stdout, stderr, runSecurityProcess)
}

func scanSecurity(ctx context.Context, opts SecurityOptions, stdout, stderr io.Writer, run securityRunner) error {
	args, err := opts.arguments()
	if err != nil {
		return err
	}
	if opts.Executable == "" {
		return errors.New("skillspector executable must not be empty")
	}
	if opts.Timeout <= 0 {
		return errors.New("security timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := run(ctx, opts.Executable, args, stdout, stderr); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("security scan interrupted: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 {
				return errors.New("security scan failed: findings, elevated risk, or incomplete analysis; inspect the report")
			}
			return fmt.Errorf("skillspector execution failed (exit %d); inspect scanner diagnostics", exitErr.ExitCode())
		}
		return fmt.Errorf("cannot run skillspector; install it or set --skillspector-bin: %w", err)
	}
	return nil
}

func (opts SecurityOptions) arguments() ([]string, error) {
	if opts.Path == "" {
		return nil, errors.New("a local skill path is required")
	}
	path, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve skill path: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect skill path: %w", err)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, errors.New("skill path must be a directory or regular file")
	}
	switch opts.Format {
	case "terminal", "json", "markdown", "sarif":
	default:
		return nil, fmt.Errorf("unsupported security format %q", opts.Format)
	}
	args := []string{"scan", path, "--format", opts.Format, "--fail-on-findings", "--fail-on-incomplete"}
	if !opts.LLM {
		args = append(args, "--no-llm")
	}
	if opts.Output != "" {
		out, err := filepath.Abs(opts.Output)
		if err != nil {
			return nil, fmt.Errorf("resolve report path: %w", err)
		}
		// Keep reports out of the scanned input so they cannot overwrite or contaminate it.
		resolvedPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("resolve skill symlinks: %w", err)
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(out))
		if err != nil {
			return nil, fmt.Errorf("report parent must exist: %w", err)
		}
		resolvedOut := filepath.Join(parent, filepath.Base(out))
		if _, err := os.Lstat(out); err == nil {
			return nil, errors.New("report path already exists; choose a new file")
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect report path: %w", err)
		}
		rel, err := filepath.Rel(resolvedPath, resolvedOut)
		if err != nil {
			return nil, fmt.Errorf("compare report and input paths: %w", err)
		}
		if rel == "." || (info.IsDir() && filepath.IsLocal(rel)) {
			return nil, errors.New("report must be outside the scanned skill")
		}
		args = append(args, "--output", out)
	}
	if opts.Baseline != "" {
		baseline, err := filepath.Abs(opts.Baseline)
		if err != nil {
			return nil, fmt.Errorf("resolve baseline: %w", err)
		}
		info, err := os.Stat(baseline)
		if err != nil {
			return nil, fmt.Errorf("inspect baseline: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("baseline must be a regular file")
		}
		args = append(args, "--baseline", baseline)
	}
	return args, nil
}

func runSecurityProcess(ctx context.Context, executable string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, executable, args...) // #nosec G204 -- explicit user-selected executable; no shell expansion.
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
