package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"shellsentry/core"
	"shellsentry/ports"
)

// readLine reads one byte at a time from r until '\n' or EOF, returning the line
// without the trailing newline. It never reads ahead past the newline, so bytes
// the user types during an interactive command (proxied straight off the raw fd
// by ptyshell) are not stolen by a buffered reader. On "whoami\n" it returns
// ("whoami", nil); the next call returns ("", io.EOF).
func readLine(r io.Reader) (string, error) {
	var b [1]byte
	var line []byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return string(line), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return string(line), err
		}
	}
}

type Deps struct {
	Scorer       ports.Scorer
	Store        ports.Store
	Geo          ports.GeoResolver
	Alerter      ports.Alerter
	OTP          ports.OTPVerifier
	Shell        ports.Shell
	Rules        core.Rules
	Dicts        core.Dicts
	SoftThr      float64
	HardThr      float64
	OTPRetries   int
	ScoreTimeout time.Duration
	Now          func() int64
	// NoveltySeverity escalates a command/country/path that is new to an already
	// trained user (index 0 vs a non-empty vocabulary). SevNone = off.
	NoveltySeverity core.Severity
}

// noveltySeverity returns a severity (and a reason) when the command, country,
// or path is NEVER-SEEN for a user who already has a trained vocabulary — the
// per-user history IS the context (`sudo` is novel for someone who never sudos,
// normal for an admin who does). Only a resolved-but-unknown country counts, so
// a geo-unavailable ("") lookup is not mistaken for a new location.
func (d Deps) noveltySeverity(cmd, country, path string, hasPath bool) (core.Severity, string) {
	if d.NoveltySeverity == core.SevNone {
		return core.SevNone, ""
	}
	var what []string
	if cmd != "" && len(d.Dicts.Command) > 0 && d.Dicts.CmdIndex(cmd) == 0 {
		what = append(what, "command")
	}
	if country != "" && len(d.Dicts.Country) > 0 && d.Dicts.GeoID(country) == 0 {
		what = append(what, "country")
	}
	if hasPath && len(d.Dicts.Path) > 0 && d.Dicts.PathIndex(path, true) == 0 {
		what = append(what, "path")
	}
	if len(what) == 0 {
		return core.SevNone, ""
	}
	return d.NoveltySeverity, "never-seen " + strings.Join(what, "+")
}

func (d Deps) alert(user, sid, sev, reason, detail string) {
	// Best-effort delivery, but leave a trace on failure so a dropped alert
	// (incl. the mandatory scorer-timeout one) is not completely invisible.
	if err := d.Alerter.Alert(ports.Alert{
		TS: d.Now(), User: user, SessionID: sid,
		Severity: sev, Reason: reason, Detail: detail,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ssentry: alert %q delivery failed: %v\n", sev, err)
	}
}

// RunREPL runs the command loop until EOF/exit. Returns the session; caller
// saves it iff s.Valid.
func RunREPL(user, ip, sessionID string, lr LineReader, d Deps) *core.Session {
	country, _ := d.Geo.Country(ip) // "" on unknown; error path already returns ""
	s := core.NewSession(d.Now())
	// Command spacing is measured with a monotonic clock (time.Now carries a
	// monotonic reading) so an NTP wall-clock step back cannot make elapsed
	// negative. d.Now() is kept for the stored wall-clock session timestamps.
	lastCmdTime := time.Now()
	// Per-session cache of command lines the user has already authorized with a
	// correct OTP (only HARD events are challenged, so only those populate it).
	// An identical line later in the SAME session skips the re-challenge.
	// In-memory only (cleared at logout) so a stolen OTP cannot whitelist a
	// command beyond the session.
	authorized := map[string]bool{}

	for {
		line, err := lr.ReadLine("ssentry> ")
		line = strings.TrimRight(line, "\r\n")
		if line == "exit" || (err == io.EOF && line == "") {
			break
		}
		if strings.TrimSpace(line) == "" {
			if err == io.EOF {
				break
			}
			continue
		}

		// Reject an incomplete shell line (unterminated quote, trailing
		// backslash, open paren) before injecting it: otherwise the appended
		// sentinel would be swallowed as continuation and RunCommand would hang.
		if ok, reason := core.LineComplete(line); !ok {
			fmt.Fprintf(lr, "ssentry: incomplete command (%s); not executed\n", reason)
			if err == io.EOF {
				break
			}
			continue
		}

		now := d.Now()
		// Monotonic elapsed seconds since the last command, clamped to >= 0.
		secs := int(time.Since(lastCmdTime).Seconds())
		if secs < 0 {
			secs = 0
		}
		cmd, args := core.SplitCommand(line)
		secOfDay := int(now % 86400)
		feat := core.BuildFeature(d.Dicts, secOfDay, country, cmd, args, secs)

		sev := core.SevNone
		outcome := d.Rules.Check(line, country, secs)
		switch outcome {
		case core.RuleChallengeHard:
			sev = core.SevHard
		case core.RuleChallengeSoft:
			sev = core.SevSoft
		case core.RuleAllow:
			sev = core.SevNone
		default:
			// no rule verdict -> ask the model
			sev = d.scoreSeverity(user, sessionID, feat)
		}

		// A hard challenge originating from a deny rule (command or country) is
		// the highest-signal event: emit a distinct rule-deny alert so admins
		// can tell it apart from a model-driven hard challenge.
		if outcome == core.RuleChallengeHard {
			d.alert(user, sessionID, "rule-deny", "deny rule matched", line)
		}

		// Novelty gate: a command/country/path that is new to an already-trained
		// user is judged in the context of that user's own history — escalate to
		// the stronger of (model severity, novelty severity). An explicit
		// allow-rule is admin-trusted, so it bypasses novelty.
		if outcome != core.RuleAllow {
			path, hasPath := core.DetectPath(args)
			if nsev, reason := d.noveltySeverity(cmd, country, path, hasPath); nsev > sev {
				sev = nsev
				d.alert(user, sessionID, "novelty", reason, line)
			}
		}

		// Challenge policy: a SOFT anomaly is logged only; OTP is required solely
		// for a HARD event (admin deny, model score <= hard threshold, or a
		// novelty gate configured hard). Deny always maps to SevHard, so it can
		// never be downgraded to log-only.
		switch sev {
		case core.SevSoft:
			d.alert(user, sessionID, "soft-log", "soft anomaly logged", line)
		case core.SevHard:
			// An identical hard command already OTP-authorized this session is
			// not re-challenged (see `authorized`). Every SevHard is content-based
			// (deny/model/novelty), so any hard pass is eligible for the cache.
			if authorized[line] {
				d.alert(user, sessionID, "otp-cached", "prior OTP authorization reused", line)
			} else {
				if !d.challenge(user, sessionID, sev, lr) {
					s.Valid = false
					d.alert(user, sessionID, "bad-otp", "otp failed", line)
					break
				}
				authorized[line] = true
			}
		}

		if _, runErr := d.Shell.RunCommand(line); runErr != nil {
			// A shell that died mid-session cannot have run this command; the
			// record would be fabricated. Don't append it, alert, and discard
			// the session (a dead PTY is not a clean exit).
			d.alert(user, sessionID, "shell-error", "shell command failed", runErr.Error())
			fmt.Fprintf(os.Stderr, "ssentry: shell command failed: %v\n", runErr)
			s.Valid = false
			break
		}
		s.Add(core.CommandRecord{TS: now, Feat: feat, RawCmd: line, IP: ip})
		lastCmdTime = time.Now()

		if err == io.EOF {
			break
		}
	}
	s.EndTS = d.Now()
	return s
}

func (d Deps) scoreSeverity(user, sid string, feat core.Feature) core.Severity {
	ctx, cancel := context.WithTimeout(context.Background(), d.ScoreTimeout)
	defer cancel()
	score, err := d.Scorer.Score(ctx, user, sid, feat)
	if err != nil {
		d.alert(user, sid, "scorer-timeout", "scorer unavailable", err.Error())
		score = math.Inf(1) // fail-open: high = normal
	}
	return core.Decide(score, d.SoftThr, d.HardThr)
}

// challenge prompts for OTP up to OTPRetries; true = passed. On pass, emits a
// soft/hard alert; the session stays valid.
func (d Deps) challenge(user, sid string, sev core.Severity, lr LineReader) bool {
	sevName := "soft-otp"
	if sev == core.SevHard {
		sevName = "hard-otp"
	}
	for i := 0; i < d.OTPRetries; i++ {
		code, readErr := lr.ReadLine("OTP: ")
		code = strings.TrimSpace(code)
		// EOF with no data typed = the tty was closed / session abandoned.
		// Stop immediately instead of busy-looping through every retry.
		if code == "" && errors.Is(readErr, io.EOF) {
			return false
		}
		ok, err := d.OTP.Validate(user, code)
		if err != nil {
			// A transient TOTP backend/I/O error is not a wrong code; log it so
			// it's distinguishable, then retry (it may recover). Never treat a
			// validation error as a successful auth.
			fmt.Fprintf(os.Stderr, "ssentry: OTP validation error: %v\n", err)
			continue
		}
		if ok {
			d.alert(user, sid, sevName, "otp passed", "")
			return true
		}
	}
	return false
}
