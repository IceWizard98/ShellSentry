package main

import (
	"os"
	"path/filepath"
	"testing"

	"shellsentry/core"
)

func TestLoadConfig_MissingOTPRetries_DefaultsToThree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// A config without otp_retries would unmarshal to 0, locking users out on
	// any challenge (for i := 0; i < 0 returns immediately). LoadConfig must
	// default it to 3.
	if err := os.WriteFile(path, []byte("root_path: /tmp/data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OTPRetries != 3 {
		t.Fatalf("OTPRetries default must be 3; got %d", c.OTPRetries)
	}
}

func TestLoadConfig_ExplicitOTPRetries_Preserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("otp_retries: 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OTPRetries != 5 {
		t.Fatalf("explicit OTPRetries must be kept; got %d", c.OTPRetries)
	}
}

func TestLoadConfig_TrainingParams(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(
		"min_sessions_train: 20\nmax_sessions_keep: 500\notp_retries: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.MinSessionsTrain != 20 || c.MaxSessionsKeep != 500 {
		t.Fatalf("got min=%d max=%d want 20/500", c.MinSessionsTrain, c.MaxSessionsKeep)
	}
}

func TestLoadConfig_PythonParams(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(
		"python_bin: /opt/py/bin/python\ntrainer_script: /opt/ss/trainer.py\notp_retries: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.PythonBin != "/opt/py/bin/python" || c.TrainerScript != "/opt/ss/trainer.py" {
		t.Fatalf("got %q / %q", c.PythonBin, c.TrainerScript)
	}
}

func TestNoveltySev(t *testing.T) {
	cases := map[string]core.Severity{
		"":         core.SevSoft, // unset -> soft
		"soft":     core.SevSoft,
		"hard":     core.SevHard,
		"off":      core.SevNone,
		"SOFT":     core.SevSoft, // invalid -> warn + default soft (not fatal)
		"nonsense": core.SevSoft,
	}
	for in, want := range cases {
		if got := (Config{NoveltySeverity: in}).NoveltySev(); got != want {
			t.Errorf("NoveltySev(%q)=%v want %v", in, got, want)
		}
	}
}
