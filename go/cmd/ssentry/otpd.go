package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/cobra"

	"shellsentry/adapters/otpsockclient"
	"shellsentry/adapters/totpauth"
	"shellsentry/core"
)

// otpdCmd runs the privileged OTP daemon:
//
//	ssentry otpd --config /etc/ssentry/config.yaml   (run as root)
//
// It owns the TOTP secrets under otp_root (root-only) and answers provision/
// validate requests on otp_socket. The scored user's session reaches it via
// adapters/otpsockclient, so the secret is never stored under the user's uid.
func otpdCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "otpd",
		Short: "Run the privileged TOTP daemon (secret store + validator)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if cfgPath == "" {
				cfgPath = os.Getenv("SSENTRY_CONFIG")
			}
			if cfgPath == "" {
				cfgPath = "config.yaml"
			}
			cfg, err := LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			return runOTPD(cfg)
		},
	}
	c.Flags().StringVar(&cfgPath, "config", "", "path to config.yaml (or $SSENTRY_CONFIG)")
	return c
}

func runOTPD(cfg Config) error {
	if cfg.OTPSocket == "" || cfg.OTPRoot == "" {
		return fmt.Errorf("otpd requires otp_socket and otp_root in config")
	}
	if err := os.MkdirAll(cfg.OTPRoot, 0o700); err != nil {
		return fmt.Errorf("mkdir otp_root: %w", err)
	}
	vault := totpauth.New(cfg.OTPRoot, "shellsentry")

	// Replace a stale socket from a previous run, then listen.
	_ = os.Remove(cfg.OTPSocket)
	ln, err := net.Listen("unix", cfg.OTPSocket)
	if err != nil {
		return fmt.Errorf("listen otp socket: %w", err)
	}
	defer ln.Close()
	// Any local user must be able to connect; peer-uid authorization (not file
	// perms) decides who may touch which secret.
	if err := os.Chmod(cfg.OTPSocket, 0o666); err != nil {
		return fmt.Errorf("chmod otp socket: %w", err)
	}
	fmt.Fprintf(os.Stderr, "ssentry otpd: listening on %s (secrets in %s)\n", cfg.OTPSocket, cfg.OTPRoot)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go handleOTPConn(conn.(*net.UnixConn), vault)
	}
}

// handleOTPConn resolves the peer's uid to a username, then serves one request.
func handleOTPConn(conn *net.UnixConn, vault *totpauth.Vault) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil {
		writeOTPErr(conn, "peer identity unavailable")
		return
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		writeOTPErr(conn, "unknown peer uid")
		return
	}
	var req otpsockclient.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeOTPErr(conn, "bad request")
		return
	}
	resp := serveOTPRequest(vault, u.Username, req)
	_ = json.NewEncoder(conn).Encode(resp)
}

func writeOTPErr(conn net.Conn, msg string) {
	_ = json.NewEncoder(conn).Encode(otpsockclient.Response{Error: msg})
}

// serveOTPRequest is the pure request handler (peerUser already resolved), so it
// is unit-testable without a real socket. A user may only act on their OWN
// secret: req.User must equal the connecting peer's username.
func serveOTPRequest(v *totpauth.Vault, peerUser string, req otpsockclient.Request) otpsockclient.Response {
	if err := core.ValidUsername(req.User); err != nil {
		return otpsockclient.Response{Error: "invalid user"}
	}
	if req.User != peerUser {
		// Prevents a user resetting/validating another user's secret.
		return otpsockclient.Response{Error: "permission denied"}
	}
	switch req.Op {
	case "status":
		return otpsockclient.Response{Enrolled: v.IsEnrolled(req.User)}
	case "provision":
		uri, err := v.Provision(req.User)
		if err != nil {
			return otpsockclient.Response{Error: err.Error()}
		}
		return otpsockclient.Response{URI: uri}
	case "confirm":
		if err := v.Confirm(req.User); err != nil {
			return otpsockclient.Response{Error: err.Error()}
		}
		return otpsockclient.Response{OK: true}
	case "discard":
		if err := v.Discard(req.User); err != nil {
			return otpsockclient.Response{Error: err.Error()}
		}
		return otpsockclient.Response{OK: true}
	case "validate":
		ok, err := v.Validate(req.User, req.Code)
		if err != nil {
			return otpsockclient.Response{Error: err.Error()}
		}
		return otpsockclient.Response{OK: ok}
	default:
		return otpsockclient.Response{Error: "unknown op"}
	}
}
