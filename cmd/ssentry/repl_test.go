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
	err error // if set, RunCommand returns it without recording the line
}

func (f *fakeShell) RunCommand(line string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.ran = append(f.ran, line)
	return 0, nil
}
func (f *fakeShell) Close() error { return nil }

type fakeOTP struct{ ok bool }

func (f fakeOTP) EnsureProvisioned(string) error        { return nil }
func (f fakeOTP) Validate(string, string) (bool, error) { return f.ok, nil }

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

func TestREPL_NormalCommand_Executes_SessionValid(t *testing.T) {
	d := baseDeps()
	sh := d.Shell.(*fakeShell)
	in := strings.NewReader("whoami\n")
	s := RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, strings.NewReader(""), d)
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
	s := RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, otp, d)
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
	RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, otp, d)
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
	s := RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, strings.NewReader(""), d)
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
	s := RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, otp, d)
	if !s.Valid || len(s.Commands) != 1 {
		t.Fatalf("good OTP must keep session valid: valid=%v", s.Valid)
	}
}

func TestREPL_ShellError_DiscardsSession_NoRecord(t *testing.T) {
	d := baseDeps()
	d.Shell = &fakeShell{err: errors.New("pty died")}
	al := d.Alerter.(*fakeAlerter)
	in := strings.NewReader("whoami\n")
	s := RunREPL("alice", "1.2.3.4", "s1", in, io.Discard, strings.NewReader(""), d)
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
