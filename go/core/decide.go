package core

import "strings"

// SplitCommand splits a REPL line into command word + full arg slice (args[0]
// is the command).
func SplitCommand(line string) (string, []string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields
}

type Severity int

const (
	SevNone Severity = iota
	SevSoft
	SevHard
)

// Decide maps an Isolation Forest score to a severity. LOW score = anomalous,
// so hardThr < softThr. Boundary is inclusive (score <= thr triggers).
func Decide(score, softThr, hardThr float64) Severity {
	switch {
	case score <= hardThr:
		return SevHard
	case score <= softThr:
		return SevSoft
	default:
		return SevNone
	}
}
