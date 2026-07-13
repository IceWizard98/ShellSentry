package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"shellsentry/core"
)

type Config struct {
	RootPath     string `yaml:"root_path"`
	GeoIPDBPath  string `yaml:"geoip_db_path"`
	DaemonAddr   string `yaml:"daemon_addr"`
	ScoreTimeout int    `yaml:"score_timeout_ms"`
	AlertSocket  string `yaml:"alert_socket"`
	OTPRetries   int    `yaml:"otp_retries"`
	RulesPath    string `yaml:"rules_path"`
	ModelTTLSec  int    `yaml:"model_ttl_sec"`
	// CommandTimeoutMs is a per-command wall-clock ceiling (0 = disabled). It is
	// a backstop for a command that never emits its sentinel; leave it 0 for
	// interactive use (long-running vi/builds), set it for non-interactive
	// deployments where a stuck command cannot be recovered by the user.
	CommandTimeoutMs int `yaml:"command_timeout_ms"`
	// Training pipeline (spec 3): min stored sessions required to train; and the
	// max sessions kept per user (older ones are pruned before training).
	MinSessionsTrain int `yaml:"min_sessions_train"`
	MaxSessionsKeep  int `yaml:"max_sessions_keep"`
	// Training subprocess (spec 3). Empty = auto: PythonBin tries
	// python/venv/bin/python then python3 on $PATH; TrainerScript defaults to
	// python/trainer.py. Set explicit absolute paths for non-repo-root deploys.
	PythonBin     string `yaml:"python_bin"`
	TrainerScript string `yaml:"trainer_script"`
	// NoveltySeverity gates never-seen items for an already-trained user
	// (command/country/path with index 0 vs a non-empty trained vocabulary):
	// "off" | "soft" | "hard". Empty defaults to "soft". The model cannot flag a
	// lone novel item (it has no such training examples), so this deterministic
	// gate escalates the per-command severity when the item is new to the user.
	NoveltySeverity string `yaml:"novelty_severity"`
}

// NoveltySev maps the config string to a core.Severity; unset -> soft. An
// unrecognized value warns and falls back to soft rather than failing the
// session (a cosmetic-knob typo must not lock every user out — same policy as
// otp_retries).
func (c Config) NoveltySev() core.Severity {
	switch c.NoveltySeverity {
	case "", "soft":
		return core.SevSoft
	case "off":
		return core.SevNone
	case "hard":
		return core.SevHard
	default:
		fmt.Fprintf(os.Stderr, "ssentry: novelty_severity %q invalid (want off|soft|hard), defaulting to soft\n", c.NoveltySeverity)
		return core.SevSoft
	}
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	// A missing otp_retries yields 0, which would make challenge() return false
	// immediately and lock users out on any challenge. Default to 3 retries.
	if c.OTPRetries <= 0 {
		fmt.Fprintln(os.Stderr, "ssentry: otp_retries missing or <=0, defaulting to 3")
		c.OTPRetries = 3
	}
	return c, nil
}

func (c Config) ScoreTimeoutDur() time.Duration {
	return time.Duration(c.ScoreTimeout) * time.Millisecond
}

func (c Config) CommandTimeoutDur() time.Duration {
	return time.Duration(c.CommandTimeoutMs) * time.Millisecond
}
