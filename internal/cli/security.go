package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/alibaba/skill-up/internal/skill"
)

func newSecurityCommand() *cobra.Command {
	opts := skill.SecurityOptions{}
	cmd := &cobra.Command{
		Use:   "security <local skill directory or file>",
		Short: "Scan a skill with SkillSpector (static analysis by default)",
		Long:  "Scan a local skill with the separately installed SkillSpector CLI. Findings or incomplete analysis fail the command. --llm opts into sending content to the configured SkillSpector model provider. Static scans may query OSV for dependency vulnerabilities.",
		Args:  usageOnError(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Path = args[0]
			return skill.ScanSecurity(cmd.Context(), opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&opts.Executable, "skillspector-bin", "skillspector", "SkillSpector executable path (not a shell command)")
	cmd.Flags().StringVar(&opts.Format, "format", "terminal", "Report format: terminal, json, markdown, sarif")
	cmd.Flags().StringVar(&opts.Output, "output", "", "New report file outside the scanned input (default stdout)")
	cmd.Flags().StringVar(&opts.Baseline, "baseline", "", "Explicitly reviewed SkillSpector suppression baseline")
	cmd.Flags().BoolVar(&opts.LLM, "llm", false, "Enable SkillSpector model analysis using its provider credentials")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "Maximum scanner runtime")
	return cmd
}
