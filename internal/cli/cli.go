// Package cli implements the cloudweave command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vedantparmar12/cloudweave/internal/analysis"
	"github.com/vedantparmar12/cloudweave/internal/report"
	"github.com/vedantparmar12/cloudweave/internal/state"
)

const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

// errThreshold signals that findings met --fail-on; it is not printed as an error.
var errThreshold = errors.New("findings at or above --fail-on")

// Execute runs the CLI and returns the process exit code.
func Execute(version string, args []string, stdout, stderr io.Writer) int {
	root := newRoot(version, stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errThreshold):
		return exitFindings
	default:
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
}

func newRoot(version string, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "cloudweave",
		Short: "Read-only Terraform preflight: drift, blast radius, cross-state and STS federation checks",
		Long: "CloudWeave analyzes Terraform state and plan JSON files offline before terraform apply.\n" +
			"It never writes, locks or pushes state, makes no cloud API calls and sends no telemetry.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newAnalyze(version), newVersion(version))
	return root
}

func newVersion(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CloudWeave version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "cloudweave %s\n", version)
			return nil
		},
	}
}

type analyzeFlags struct {
	states           []string
	plan             string
	primary          string
	htmlOut          string
	jsonOut          string
	mdOut            string
	failOn           string
	planMaxAge       time.Duration
	applyWindow      time.Duration
	blastRadius      int
	maxNodes         int
	checkCredentials bool
	revealIDs        bool
	quiet            bool
}

func newAnalyze(version string) *cobra.Command {
	f := &analyzeFlags{}
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze state and plan files and write a report",
		Example: `  terraform state pull > azure.tfstate
  terraform plan -out tfplan && terraform show -json tfplan > plan.json
  cloudweave analyze --state azure=azure.tfstate --state gcp=gcp.tfstate --plan plan.json --out report.html`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAnalyze(cmd.OutOrStdout(), version, f)
		},
	}
	fl := cmd.Flags()
	fl.StringArrayVarP(&f.states, "state", "s", nil, "state file as [name=]path (raw .tfstate or `terraform show -json`); repeatable")
	fl.StringVarP(&f.plan, "plan", "p", "", "plan JSON from `terraform show -json tfplan`")
	fl.StringVar(&f.primary, "primary-state", "", "name or path of the state the plan applies to (auto-detected by default)")
	fl.StringVarP(&f.htmlOut, "out", "o", "", "write a self-contained HTML report to this path")
	fl.StringVar(&f.jsonOut, "json", "", "write the JSON report to this path (- for stdout)")
	fl.StringVar(&f.mdOut, "markdown", "", "write a Markdown summary for pull request comments to this path (- for stdout)")
	fl.StringVar(&f.failOn, "fail-on", "none", "exit 2 if any finding is at or above this severity (info|low|medium|high|critical|none)")
	fl.DurationVar(&f.planMaxAge, "plan-max-age", time.Hour, "flag saved plans older than this")
	fl.DurationVar(&f.applyWindow, "apply-window", 30*time.Minute, "expected apply duration; credentials expiring within it are flagged")
	fl.IntVar(&f.blastRadius, "blast-radius", 25, "flag changes that impact more than this many resources")
	fl.IntVar(&f.maxNodes, "max-nodes", 400, "maximum nodes drawn per view in the HTML report")
	fl.BoolVar(&f.checkCredentials, "check-credentials", false, "inspect local federation credential env vars and files (values are never printed)")
	fl.BoolVar(&f.revealIDs, "reveal-ids", false, "show full identifiers in findings instead of masked ones")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "suppress the terminal summary")
	return cmd
}

func runAnalyze(stdout io.Writer, version string, f *analyzeFlags) error {
	var failOn analysis.Severity = -1
	if !strings.EqualFold(strings.TrimSpace(f.failOn), "none") {
		s, err := analysis.ParseSeverity(f.failOn)
		if err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
		failOn = s
	}
	if len(f.states) == 0 && f.plan == "" {
		return errors.New("provide at least one --state or a --plan")
	}
	if f.maxNodes <= 0 {
		return errors.New("--max-nodes must be positive")
	}

	var inputs []string
	var states []*state.State
	for _, spec := range f.states {
		name, path := splitStateSpec(spec)
		st, err := state.LoadState(path)
		if err != nil {
			return err
		}
		if name != "" {
			st.Name = name
		}
		states = append(states, st)
		inputs = append(inputs, path)
	}
	var plan *state.Plan
	if f.plan != "" {
		p, err := state.LoadPlan(f.plan)
		if err != nil {
			return err
		}
		plan = p
		inputs = append(inputs, f.plan)
	}

	outs := []string{f.htmlOut, f.jsonOut, f.mdOut}
	for i, out := range outs {
		if err := checkOutputPath(out, inputs); err != nil {
			return err
		}
		for _, other := range outs[i+1:] {
			if out != "" && out == other {
				return errors.New("--out, --json and --markdown must name different files")
			}
		}
	}
	if f.htmlOut == "-" {
		return errors.New("--out needs a file path; the HTML report is not written to stdout")
	}

	res, err := analysis.Analyze(states, plan, analysis.Options{
		PrimaryState:     f.primary,
		PlanMaxAge:       f.planMaxAge,
		ApplyWindow:      f.applyWindow,
		BlastRadius:      f.blastRadius,
		RevealIDs:        f.revealIDs,
		CheckCredentials: f.checkCredentials,
	})
	if err != nil {
		return err
	}
	rep := report.Build(res, version, f.maxNodes)

	if f.htmlOut != "" {
		if err := writeFile(f.htmlOut, func(w io.Writer) error { return report.WriteHTML(w, rep) }); err != nil {
			return err
		}
	}
	for _, o := range []struct {
		path  string
		write func(io.Writer, *report.Report) error
	}{{f.jsonOut, report.WriteJSON}, {f.mdOut, report.WriteMarkdown}} {
		switch o.path {
		case "":
		case "-":
			if err := o.write(stdout, rep); err != nil {
				return err
			}
		default:
			if err := writeFile(o.path, func(w io.Writer) error { return o.write(w, rep) }); err != nil {
				return err
			}
		}
	}
	if !f.quiet && f.jsonOut != "-" && f.mdOut != "-" {
		printSummary(stdout, rep, f)
	}

	if failOn >= 0 && len(res.Findings) > 0 && analysis.MaxSeverity(res.Findings) >= failOn {
		return errThreshold
	}
	return nil
}

// splitStateSpec parses "[name=]path". A prefix is only treated as a name when
// it looks like one, so paths containing '=' still work.
func splitStateSpec(spec string) (string, string) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 {
		return "", spec
	}
	name := spec[:i]
	if strings.ContainsAny(name, `/\:`) {
		return "", spec
	}
	if _, err := os.Stat(spec); err == nil {
		return "", spec
	}
	return name, spec[i+1:]
}

// checkOutputPath refuses to write a report over any input or anything that
// looks like Terraform state.
func checkOutputPath(out string, inputs []string) error {
	if out == "" || out == "-" {
		return nil
	}
	base := strings.ToLower(filepath.Base(out))
	if strings.HasSuffix(base, ".tfstate") || strings.HasSuffix(base, ".tfstate.backup") ||
		strings.Contains(base, ".tfstate.") || base == "terraform.tfstate" {
		return fmt.Errorf("refusing to write report to %s: it looks like a Terraform state file", out)
	}
	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	outInfo, statErr := os.Stat(out)
	for _, in := range inputs {
		absIn, err := filepath.Abs(in)
		if err != nil {
			return err
		}
		if strings.EqualFold(filepath.Clean(absIn), filepath.Clean(absOut)) {
			return fmt.Errorf("refusing to overwrite input file %s", in)
		}
		if statErr == nil {
			if inInfo, err := os.Stat(in); err == nil && os.SameFile(inInfo, outInfo) {
				return fmt.Errorf("refusing to overwrite input file %s", in)
			}
		}
	}
	return nil
}

func writeFile(path string, write func(io.Writer) error) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := write(fh); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

func printSummary(w io.Writer, rep *report.Report, f *analyzeFlags) {
	fmt.Fprintf(w, "CloudWeave preflight: %s\n", strings.ToUpper(rep.Verdict))
	for _, s := range rep.States {
		tag := ""
		if s.Primary {
			tag = " [primary]"
		}
		if s.FromPlan {
			tag += " [from plan]"
		}
		fmt.Fprintf(w, "  state %-24s %6d resources %6d instances %4d outputs%s\n",
			s.Name, s.Resources, s.Instances, s.Outputs, tag)
	}
	if p := rep.Plan; p != nil {
		var parts []string
		for _, a := range []string{"create", "update", "replace", "delete", "forget", "read"} {
			if n := p.Actions[a]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, a))
			}
		}
		if len(parts) == 0 {
			parts = append(parts, "no changes")
		}
		fmt.Fprintf(w, "  plan: %s; %d drifted; %d deferred\n", strings.Join(parts, ", "), p.Drift, p.Deferred)
	}

	fmt.Fprintf(w, "\n%d findings", len(rep.Findings))
	if len(rep.Findings) > 0 {
		var counts []string
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if n := rep.Counts[s]; n > 0 {
				counts = append(counts, fmt.Sprintf("%d %s", n, s))
			}
		}
		fmt.Fprintf(w, " (%s)", strings.Join(counts, ", "))
	}
	fmt.Fprintln(w)

	const limit = 15
	for i, fd := range rep.Findings {
		if i == limit {
			fmt.Fprintf(w, "  ... %d more in the report\n", len(rep.Findings)-limit)
			break
		}
		fmt.Fprintf(w, "  %-8s %s  %s\n", strings.ToUpper(fd.Severity.String()), fd.Rule, fd.Title)
	}

	if f.htmlOut != "" {
		fmt.Fprintf(w, "\nHTML report: %s\n", f.htmlOut)
	}
	if f.jsonOut != "" {
		fmt.Fprintf(w, "JSON report: %s\n", f.jsonOut)
	}
}
