package main

import (
	"os"
	"path/filepath"
	"testing"
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
