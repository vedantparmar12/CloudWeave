package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ParseSeverity parses a severity name. "none" disables failing.
func ParseSeverity(v string) (Severity, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for i, n := range severityNames {
		if n == v {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", v, strings.Join(severityNames, ", "))
}

const (
	CatPlan       = "plan"
	CatDrift      = "drift"
	CatBlast      = "blast-radius"
	CatCrossState = "cross-state"
	CatSTS        = "sts-federation"
	CatCreds      = "credentials"
	CatState      = "state"
)

// Finding is one preflight observation. It never contains attribute values;
// identifiers in Detail are masked unless the caller opts in.
type Finding struct {
	Rule        string    `json:"rule"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Fix         []FixStep `json:"fix,omitempty"`
	Nodes       []string  `json:"nodes,omitempty"`
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Rule != fs[j].Rule {
			return fs[i].Rule < fs[j].Rule
		}
		return fs[i].Title < fs[j].Title
	})
}

// Verdict summarizes the highest severity into an apply recommendation.
func Verdict(fs []Finding) string {
	max := Severity(-1)
	for _, f := range fs {
		if f.Severity > max {
			max = f.Severity
		}
	}
	switch {
	case max >= SevCritical:
		return "block"
	case max >= SevHigh:
		return "review"
	case max >= SevMedium:
		return "caution"
	default:
		return "clear"
	}
}

// MaxSeverity returns the highest severity, or -1 when there are no findings.
func MaxSeverity(fs []Finding) Severity {
	max := Severity(-1)
	for _, f := range fs {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}
