package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
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
