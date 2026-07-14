package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"shellsentry/core"
	"shellsentry/ports"
)

type fakeScorer struct {
	score float64
	err   error
}

func (f fakeScorer) Score(context.Context, string, string, core.Feature) (float64, error) {
	return f.score, f.err
}

type fakeShell struct {
	ran []string
	cwd string // reported by Cwd (empty -> prompt degrades to no-dir)
	err error  // if set, RunCommand returns it without recording the line
}

func (f *fakeShell) RunCommand(line string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.ran = append(f.ran, line)
	return 0, nil
}
func (f *fakeShell) Cwd() (string, error) { return f.cwd, nil }
func (f *fakeShell) Close() error         { return nil }

type fakeOTP struct{ ok bool }

func (f fakeOTP) EnsureProvisioned(string) error        { return nil }
func (f fakeOTP) Validate(string, string) (bool, error) { return f.ok, nil }

// countingOTP counts Validate calls, so a test can assert how many times the
// user was actually challenged (once per re-prompt).
type countingOTP struct {
	ok    bool
	calls int
}

func (c *countingOTP) EnsureProvisioned(string) error { return nil }
func (c *countingOTP) Validate(string, string) (bool, error) {
	c.calls++
	return c.ok, nil
}

type fakeAlerter struct{ alerts []ports.Alert }

func (f *fakeAlerter) Alert(a ports.Alert) error { f.alerts = append(f.alerts, a); return nil }

// fakeGeo satisfies ports.GeoResolver. baseDeps must set d.Geo — RunREPL
// calls d.Geo.Country(ip) unconditionally, so a nil Geo panics.
type fakeGeo struct{}

func (fakeGeo) Country(string) (string, error) { return "", nil }

func baseDeps() Deps {
	return Deps{
		Scorer: fakeScorer{score: 1.0}, Shell: &fakeShell{},
		OTP: fakeOTP{ok: true}, Alerter: &fakeAlerter{}, Geo: fakeGeo{},
		SoftThr: 0.05, HardThr: 0.02, OTPRetries: 3,
		ScoreTimeout: time.Second, Now: func() int64 { return 1000 },
	}
}

// lineReader builds the non-tty LineReader the REPL reads from. In production a
// single tty feeds both command and OTP prompts sequentially; tests model that
// by concatenating the command stream and any OTP stream.
func lineReader(streams ...io.Reader) LineReader {
	return &plainLineReader{in: io.MultiReader(streams...), out: io.Discard}
}

func TestBuildPrompt(t *testing.T) {
	cases := []struct {
		name             string
		user, host, home string
		cwd              string
		want             string
	}{
		{"home compresses to tilde", "alice", "srv", "/home/alice", "/home/alice", "[ssentry] alice@srv:~$ "},
		{"under home", "alice", "srv", "/home/alice", "/home/alice/dev", "[ssentry] alice@srv:~/dev$ "},
		{"outside home", "alice", "srv", "/home/alice", "/tmp", "[ssentry] alice@srv:/tmp$ "},
		{"empty cwd degrades to no-dir", "alice", "srv", "/home/alice", "", "[ssentry] alice@srv$ "},
		{"home not a prefix-hijack", "alice", "srv", "/home/alice", "/home/alice2", "[ssentry] alice@srv:/home/alice2$ "},
		{"empty home never compresses", "alice", "srv", "", "/tmp", "[ssentry] alice@srv:/tmp$ "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildPrompt(c.user, c.host, c.home, c.cwd); got != c.want {
				t.Fatalf("buildPrompt = %q, want %q", got, c.want)
			}
		})
	}
}

func TestREPL_NormalCommand_Executes_SessionValid(t *testing.T) {
	d := baseDeps()
	sh := d.Shell.(*fakeShell)
	in := strings.NewReader("whoami\n")
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(in), d)
	if !s.Valid || len(s.Commands) != 1 || len(sh.ran) != 1 {
		t.Fatalf("valid=%v cmds=%d ran=%v", s.Valid, len(s.Commands), sh.ran)
	}
}

func TestREPL_DenyRule_BadOTP_DiscardsSession(t *testing.T) {
	d := baseDeps()
	d.OTP = fakeOTP{ok: false}
	d.Rules.Commands.Deny = []string{"rm -rf /"}
	in := strings.NewReader("rm -rf /\n")
	otp := strings.NewReader("000000\n000000\n000000\n")
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(in, otp), d)
	if s.Valid {
		t.Fatal("session must be invalid after failed OTP")
	}
}

func TestREPL_DenyRule_EmitsRuleDenyAlert(t *testing.T) {
	d := baseDeps()
	d.OTP = fakeOTP{ok: true} // pass OTP so the session continues past the challenge
	d.Rules.Commands.Deny = []string{"rm -rf /"}
	al := d.Alerter.(*fakeAlerter)
	in := strings.NewReader("rm -rf /\n")
	otp := strings.NewReader("123456\n")
	RunREPL("alice", "1.2.3.4", "s1", lineReader(in, otp), d)
	found := false
	for _, a := range al.alerts {
		if a.Severity == "rule-deny" {
			found = true
		}
	}
	if !found {
		t.Fatalf("deny match must emit rule-deny alert; got %+v", al.alerts)
	}
}

func TestNopGeo_UnknownCountry(t *testing.T) {
	c, err := nopGeo{}.Country("1.2.3.4")
	if err != nil || c != "" {
		t.Fatalf("nopGeo must return (\"\", nil); got (%q, %v)", c, err)
	}
}

func TestREPL_ScorerTimeout_FailsOpen_Alerts(t *testing.T) {
	d := baseDeps()
	d.Scorer = fakeScorer{err: errors.New("timeout")}
	al := d.Alerter.(*fakeAlerter)
	in := strings.NewReader("ls /x\n")
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(in), d)
	if !s.Valid || len(s.Commands) != 1 {
		t.Fatal("fail-open must let command through")
	}
	found := false
	for _, a := range al.alerts {
		if a.Severity == "scorer-timeout" {
			found = true
		}
	}
	if !found {
		t.Fatal("scorer timeout must emit alert")
	}
}

func TestREPL_AnomalousScore_GoodOTP_StaysValid(t *testing.T) {
	d := baseDeps()
	d.Scorer = fakeScorer{score: 0.01} // below hard
	in := strings.NewReader("nmap 10.0.0.0/8\n")
	otp := strings.NewReader("123456\n")
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(in, otp), d)
	if !s.Valid || len(s.Commands) != 1 {
		t.Fatalf("good OTP must keep session valid: valid=%v", s.Valid)
	}
}

func TestREPL_ShellError_DiscardsSession_NoRecord(t *testing.T) {
	d := baseDeps()
	d.Shell = &fakeShell{err: errors.New("pty died")}
	al := d.Alerter.(*fakeAlerter)
	in := strings.NewReader("whoami\n")
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(in), d)
	if s.Valid {
		t.Fatal("shell error must invalidate the session")
	}
	if len(s.Commands) != 0 {
		t.Fatalf("failed command must NOT be recorded; got %d", len(s.Commands))
	}
	found := false
	for _, a := range al.alerts {
		if a.Severity == "shell-error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shell error must emit shell-error alert; got %+v", al.alerts)
	}
}

func TestREPL_NovelCommandSoft_TrainedUser_LogOnly(t *testing.T) {
	d := baseDeps()
	d.Dicts.Command = map[string]int{"ls": 5, "whoami": 3} // trained vocabulary
	d.NoveltySeverity = core.SevSoft
	otp := &countingOTP{ok: true}
	d.OTP = otp
	al := d.Alerter.(*fakeAlerter)
	sh := d.Shell.(*fakeShell)
	// "nmap" is novel -> soft severity -> logged only, NO OTP, command still runs.
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(strings.NewReader("nmap 10.0.0.0/8\n")), d)
	if !s.Valid || len(sh.ran) != 1 {
		t.Fatalf("valid=%v ran=%v", s.Valid, sh.ran)
	}
	if otp.calls != 0 {
		t.Fatalf("soft severity must not challenge; OTP asked %d times", otp.calls)
	}
	if !hasAlert(al, "novelty") {
		t.Fatalf("novel command must emit a novelty alert; got %+v", al.alerts)
	}
	if !hasAlert(al, "soft-log") {
		t.Fatalf("soft severity must emit a soft-log alert; got %+v", al.alerts)
	}
}

func TestREPL_NovelCommand_BadOTP_DiscardsSession(t *testing.T) {
	d := baseDeps()
	d.Dicts.Command = map[string]int{"ls": 5}
	d.NoveltySeverity = core.SevHard
	d.OTP = fakeOTP{ok: false}
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(strings.NewReader("nmap x\n"), strings.NewReader("000000\n000000\n000000\n")), d)
	if s.Valid {
		t.Fatal("novel command + bad OTP must discard session")
	}
}

func TestREPL_KnownCommand_TrainedUser_NoNovelty(t *testing.T) {
	d := baseDeps()
	d.Dicts.Command = map[string]int{"ls": 5}
	d.NoveltySeverity = core.SevSoft
	sh := d.Shell.(*fakeShell)
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(strings.NewReader("ls /home\n")), d)
	if !s.Valid || len(sh.ran) != 1 {
		t.Fatalf("known command must run without novelty challenge: valid=%v ran=%v", s.Valid, sh.ran)
	}
}

func TestREPL_UntrainedUser_NoNoveltyGate(t *testing.T) {
	d := baseDeps() // empty Dicts -> no trained vocabulary
	d.NoveltySeverity = core.SevSoft
	sh := d.Shell.(*fakeShell)
	s := RunREPL("alice", "1.2.3.4", "s1", lineReader(strings.NewReader("nmap x\n")), d)
	if !s.Valid || len(sh.ran) != 1 {
		t.Fatalf("untrained user must not be novelty-gated: valid=%v ran=%v", s.Valid, sh.ran)
	}
}

// countCached counts otp-cached alerts (a challenge skipped via a prior
// same-session authorization).
func countCached(al *fakeAlerter) int {
	n := 0
	for _, a := range al.alerts {
		if a.Severity == "otp-cached" {
			n++
		}
	}
	return n
}

func hasAlert(al *fakeAlerter, sev string) bool {
	for _, a := range al.alerts {
		if a.Severity == sev {
			return true
		}
	}
	return false
}

func TestREPL_RepeatedDenyCommand_SkipsSecondOTP(t *testing.T) {
	d := baseDeps()
	otp := &countingOTP{ok: true}
	d.OTP = otp
	d.Rules.Commands.Deny = []string{"rm -rf /"}
	al := d.Alerter.(*fakeAlerter)
	sh := d.Shell.(*fakeShell)
	// Single interleaved tty stream: command, its OTP code, then the identical
	// command again (which must NOT prompt for OTP).
	lr := lineReader(strings.NewReader("rm -rf /\n123456\nrm -rf /\n"))
	s := RunREPL("alice", "1.2.3.4", "s1", lr, d)
	if otp.calls != 1 {
		t.Fatalf("identical deny command must challenge once, got %d", otp.calls)
	}
	if !s.Valid || len(sh.ran) != 2 {
		t.Fatalf("both commands must run: valid=%v ran=%v", s.Valid, sh.ran)
	}
	if c := countCached(al); c != 1 {
		t.Fatalf("second run must emit one otp-cached alert, got %d", c)
	}
}

func TestREPL_RepeatedModelHardCommand_SkipsSecondOTP(t *testing.T) {
	d := baseDeps()
	d.Scorer = fakeScorer{score: 0.01} // below hard threshold
	otp := &countingOTP{ok: true}
	d.OTP = otp
	sh := d.Shell.(*fakeShell)
	lr := lineReader(strings.NewReader("nmap x\n123456\nnmap x\n"))
	s := RunREPL("alice", "1.2.3.4", "s1", lr, d)
	if otp.calls != 1 {
		t.Fatalf("identical model-flagged command must challenge once, got %d", otp.calls)
	}
	if !s.Valid || len(sh.ran) != 2 {
		t.Fatalf("both commands must run: valid=%v ran=%v", s.Valid, sh.ran)
	}
}

func TestREPL_DifferentCommand_NotCached_ChallengesAgain(t *testing.T) {
	d := baseDeps()
	otp := &countingOTP{ok: true}
	d.OTP = otp
	d.Rules.Commands.Deny = []string{"nmap a", "nmap b"}
	// Two DIFFERENT deny commands, each with its own OTP code.
	lr := lineReader(strings.NewReader("nmap a\n111111\nnmap b\n222222\n"))
	s := RunREPL("alice", "1.2.3.4", "s1", lr, d)
	if otp.calls != 2 {
		t.Fatalf("distinct commands must each challenge: got %d, want 2", otp.calls)
	}
	if !s.Valid {
		t.Fatal("session must stay valid")
	}
}

func TestREPL_RateLimitSoft_LogOnly_NoOTP(t *testing.T) {
	d := baseDeps()
	d.Rules.MinSecondsBetween = 9999 // any rapid command trips the rate limit
	otp := &countingOTP{ok: true}
	d.OTP = otp
	al := d.Alerter.(*fakeAlerter)
	sh := d.Shell.(*fakeShell)
	// Rate-limit is a soft severity: log only, no OTP, command runs.
	lr := lineReader(strings.NewReader("date\ndate\n"))
	s := RunREPL("alice", "1.2.3.4", "s1", lr, d)
	if otp.calls != 0 {
		t.Fatalf("soft rate-limit must not challenge, got %d OTP prompts", otp.calls)
	}
	if !s.Valid || len(sh.ran) != 2 {
		t.Fatalf("both commands must run: valid=%v ran=%v", s.Valid, sh.ran)
	}
	if !hasAlert(al, "soft-log") {
		t.Fatalf("rate-limit soft must emit soft-log; got %+v", al.alerts)
	}
}

func TestREPL_ModelSoftScore_LogOnly_NoOTP(t *testing.T) {
	d := baseDeps()
	d.Scorer = fakeScorer{score: 0.03} // between hard 0.02 and soft 0.05 -> SevSoft
	otp := &countingOTP{ok: true}
	d.OTP = otp
	al := d.Alerter.(*fakeAlerter)
	sh := d.Shell.(*fakeShell)
	lr := lineReader(strings.NewReader("nmap x\n"))
	s := RunREPL("alice", "1.2.3.4", "s1", lr, d)
	if otp.calls != 0 {
		t.Fatalf("soft model score must not challenge, got %d", otp.calls)
	}
	if !s.Valid || len(sh.ran) != 1 {
		t.Fatalf("command must run: valid=%v ran=%v", s.Valid, sh.ran)
	}
	if !hasAlert(al, "soft-log") {
		t.Fatalf("soft model score must emit soft-log; got %+v", al.alerts)
	}
}
