package ports

import (
	"context"
	"shellsentry/core"
)

// Scorer talks to the Python inference daemon. Score returns the raw model
// score (high = normal). On timeout/err the REPL substitutes +Inf itself.
type Scorer interface {
	Score(ctx context.Context, user, sessionID string, f core.Feature) (float64, error)
}

// Store persists a validated session to the per-user SQLite DB.
type Store interface {
	SaveSession(user string, s *core.Session) error
	Close() error
}

// GeoResolver maps a client IP to an ISO country code ("" if unknown).
type GeoResolver interface {
	Country(ip string) (string, error)
}

// Alerter emits an admin alert to the unix alert socket.
type Alerter interface {
	Alert(a Alert) error
}

type Alert struct {
	TS        int64  `json:"ts"`
	User      string `json:"user"`
	SessionID string `json:"session_id"`
	Severity  string `json:"severity"` // soft-otp|hard-otp|rule-deny|bad-otp|scorer-timeout|shell-error|blind-spot
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
}

// OTPVerifier validates a TOTP code for the current user, provisioning a new
// secret + QR on first login.
type OTPVerifier interface {
	EnsureProvisioned(user string) error // first login: print QR + secret
	Validate(user, code string) (bool, error)
}

// Shell is the persistent PTY-backed user shell. RunCommand injects a command,
// proxies raw I/O until the sentinel marker, returns its exit code.
type Shell interface {
	RunCommand(line string) (exitCode int, err error)
	Close() error
}
