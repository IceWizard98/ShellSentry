package core

import "strings"

type Rules struct {
	Commands struct {
		Deny  []string `json:"deny"`
		Allow []string `json:"allow"`
	} `json:"commands"`
	MinSecondsBetween int `json:"min_seconds_between"`
	Countries struct {
		Deny  []string `json:"deny"`
		Allow []string `json:"allow"`
	} `json:"countries"`
}

type RuleOutcome int

const (
	RuleNone RuleOutcome = iota
	RuleAllow
	RuleChallengeSoft
	RuleChallengeHard
)

// Check runs the admin pre-filter (works without a trained model). Precedence:
// deny (hard) > allow (bypass) > min-time (soft) > none.
//
// The command line is split into segments on the top-level shell operators
// && || ; | & so a dangerous command chained after an operator (e.g.
// "echo hi && mkfs /dev/sda") cannot slip past a prefix-only match. Deny fires
// if ANY segment's command is denied; an allow-bypass requires EVERY segment to
// be allowed (a partly-unknown chain still gets scored by the model).
func (r Rules) Check(cmdLine, country string, secsSinceLast int) RuleOutcome {
	segs := splitSegments(cmdLine)

	for _, seg := range segs {
		if tokenPrefixMatch(r.Commands.Deny, seg) {
			return RuleChallengeHard
		}
	}
	if contains(r.Countries.Deny, country) {
		return RuleChallengeHard
	}

	if contains(r.Countries.Allow, country) {
		return RuleAllow
	}
	if len(r.Commands.Allow) > 0 && len(segs) > 0 {
		allAllowed := true
		for _, seg := range segs {
			// A segment that is allow-listed by its leading command but ALSO
			// contains a shell expansion (command substitution, eval, ...) must
			// NOT be bypassed: `ls $(rm -rf /)` would otherwise whitelist the
			// hidden `rm`. Fall through to model scoring instead of bypassing.
			if !tokenPrefixMatch(r.Commands.Allow, seg) || hasShellExpansion(seg) {
				allAllowed = false
				break
			}
		}
		if allAllowed {
			return RuleAllow
		}
	}

	if r.MinSecondsBetween > 0 && secsSinceLast < r.MinSecondsBetween {
		return RuleChallengeSoft
	}
	return RuleNone
}

// splitSegments breaks a command line into individual command segments on the
// top-level shell operators && || ; | &, so each segment's leading command can
// be rule-checked. It has no quote/subshell/redirection awareness — command
// substitution ($(...), backticks), eval, and aliases remain a documented blind
// spot (same class as the nested-shell/multiplexer gap), not a full shell parse.
func splitSegments(line string) []string {
	var segs []string
	var cur strings.Builder
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			segs = append(segs, s)
		}
		cur.Reset()
	}
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		switch c := runes[i]; c {
		case '&', '|':
			if i+1 < len(runes) && runes[i+1] == c { // collapse && and ||
				i++
			}
			flush()
		case ';':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return segs
}

// tokenPrefixMatch reports whether any entry's whitespace tokens are a prefix
// of the command line's whitespace tokens. Entry ["rm"] matches ["rm","-rf","/"]
// but not ["rmdir","/x"]; entry ["rm","-rf"] matches ["rm","-rf","/tmp"] but not
// ["rm","file"]. This is token-aware, so "mkfs" catches "mkfs /dev/sda" without
// the false positives of a raw substring test.
func tokenPrefixMatch(entries []string, line string) bool {
	lineTok := strings.Fields(line)
	for _, e := range entries {
		et := strings.Fields(e)
		if len(et) == 0 || len(et) > len(lineTok) {
			continue
		}
		match := true
		for i, t := range et {
			if lineTok[i] != t {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// hasShellExpansion reports whether a segment contains a shell construct that
// can hide another command from the leading-token check: command substitution
// $(...) or backticks, parameter/arith expansion ${...}, or a leading `eval`.
// Used to deny an allow-bypass for such segments (defence in depth; full
// shell-aware parsing remains a documented blind spot).
func hasShellExpansion(seg string) bool {
	if strings.Contains(seg, "$(") || strings.Contains(seg, "`") || strings.Contains(seg, "${") {
		return true
	}
	fields := strings.Fields(seg)
	return len(fields) > 0 && fields[0] == "eval"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
