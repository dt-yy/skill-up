# SkillSpector security scanning

`skill-up security` invokes the separately installed NVIDIA SkillSpector CLI.
It scans a local Skill directory (including SKILL.md and supported companion
files) or a single file. It is separate from YAML validation and task-effectiveness
scores; `skill-up run` does not automatically invoke it.

## Install

SkillSpector 2.11.2 is the inspected compatibility target and requires Python
3.12 through 3.14. From the existing local checkout on Windows:

```powershell
py -3.12 -m venv D:\pdf-bench-v2\skillspector\.venv
& D:\pdf-bench-v2\skillspector\.venv\Scripts\python.exe -m pip install D:\pdf-bench-v2\skillspector
```

Build skill-up with `go build -o bin/skill-up.exe ./cmd/skill-up`, then:

```powershell
.\bin\skill-up.exe security .\skills\skill-upper `
  --skillspector-bin D:\pdf-bench-v2\skillspector\.venv\Scripts\skillspector.exe `
  --format json --output .\security-report.json
```

The report path must be new and outside the scanned input; its parent directory
must exist. Omit --output to stream the native report to stdout. Formats are
terminal (default), json, markdown, and sarif. Paths with spaces are passed as
individual arguments, without a shell. Input must be local, not a URL.

## Behavior and limits

- Static-only by default (`--no-llm` is passed upstream). Static analysis may
  still query OSV for dependency vulnerabilities; it is not an offline promise.
- `--llm` explicitly enables semantic analysis and may send skill contents to
  the provider configured for SkillSpector. Its credentials are separate from
  skill-up's evaluation model settings.
- Active findings, elevated risk, incomplete scans, missing executables, scanner
  errors, cancellation, and timeout all return nonzero. This is suitable for a
  CI gate. Upstream diagnostics/report distinguish findings from execution
  errors; skill-up does not promise identical numeric exit codes.
- `--timeout 5m` is the default. Choose a longer duration for large inputs.
- `--baseline reviewed-baseline.yaml` applies an explicitly reviewed upstream
  suppression file. A baseline shipped inside the scanned skill is not trusted
  automatically. This baseline is unrelated to skill-up run --baseline.
- Reports retain upstream evidence, which can include source excerpts or
  secrets. Store them appropriately; they are not redacted by this adapter.
- Detection includes the upstream rules for injection, exfiltration, dangerous
  code, supply chain and other threats. It is not a guarantee of detecting all
  embedded credentials, encoded tokens, or every malicious instruction.

No scanner rules or Python dependencies are vendored into skill-up. The adapter intentionally invokes the external executable on every run, so Skillspector can be updated independently. After an upgrade, verify the installed version and rerun the security integration tests before changing a CI gate:\n\n```powershell\n& D:\\pdf-bench-v2\\skillspector\\.venv\\Scripts\\skillspector.exe --version\n$env:GOCACHE = "$pwd\\work\\go-cache"\ngo test ./internal/skill ./internal/cli\n```\n\nPin the executable path or virtual environment in CI when reproducibility matters; use a deliberate dependency update to move versions. The adapter only relies on the documented `scan` flags and treats upstream exit 1 as a security gate failure.\n\nNo scanner rules or Python dependencies are vendored into skill-up; updating
SkillSpector updates its analyzers. Test version upgrades before using them as
release gates. No installation or provider call occurs simply by running an
ordinary skill-up evaluation.

