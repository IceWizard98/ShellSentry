package main

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"shellsentry/adapters/otpsockclient"
	"shellsentry/adapters/totpauth"
)

func TestServeOTPRequest_RejectsForeignUser(t *testing.T) {
	v := totpauth.New(t.TempDir(), "shellsentry")
	// Peer is alice, but the request targets bob -> denied, no secret touched.
	resp := serveOTPRequest(v, "alice", otpsockclient.Request{Op: "provision", User: "bob"})
	if resp.Error != "permission denied" {
		t.Fatalf("cross-user request must be denied; got %+v", resp)
	}
}

func TestServeOTPRequest_RejectsInvalidUserAndUnknownOp(t *testing.T) {
	v := totpauth.New(t.TempDir(), "shellsentry")
	if r := serveOTPRequest(v, "../x", otpsockclient.Request{Op: "status", User: "../x"}); r.Error != "invalid user" {
		t.Fatalf("traversing user must be rejected; got %+v", r)
	}
	if r := serveOTPRequest(v, "alice", otpsockclient.Request{Op: "bogus", User: "alice"}); r.Error != "unknown op" {
		t.Fatalf("unknown op must be rejected; got %+v", r)
	}
}

func TestServeOTPRequest_ProvisionValidateFlow(t *testing.T) {
	root := t.TempDir()
	v := totpauth.New(root, "shellsentry")
	if r := serveOTPRequest(v, "alice", otpsockclient.Request{Op: "provision", User: "alice"}); r.URI == "" {
		t.Fatalf("provision must return a URI; got %+v", r)
	}
	raw, err := os.ReadFile(filepath.Join(root, "alice", "totp.secret"))
	if err != nil {
		t.Fatalf("secret not stored: %v", err)
	}
	code, _ := totp.GenerateCode(string(raw), time.Now())
	if r := serveOTPRequest(v, "alice", otpsockclient.Request{Op: "validate", User: "alice", Code: code}); !r.OK {
		t.Fatalf("valid code must pass; got %+v", r)
	}
	if r := serveOTPRequest(v, "alice", otpsockclient.Request{Op: "validate", User: "alice", Code: "000000"}); r.OK {
		t.Fatalf("bad code must fail; got %+v", r)
	}
}

// serveOTP spins a real unix-socket otpd for the round-trip test, so peerUID
// (SO_PEERCRED/LOCAL_PEERCRED) is exercised end to end.
func serveOTP(t *testing.T, v *totpauth.Vault) string {
	t.Helper()
	// A short socket path: unix sun_path is capped at ~104 bytes, and t.TempDir()
	// paths overflow it on macOS.
	f, err := os.CreateTemp("/tmp", "sso-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sock := f.Name()
	f.Close()
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(sock) })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleOTPConn(conn.(*net.UnixConn), v)
		}
	}()
	return sock
}

func TestOTPD_RoundTrip_EnrollAndValidate(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	root := t.TempDir()
	v := totpauth.New(root, "shellsentry")
	sock := serveOTP(t, v)

	// Provision directly, then drive Validate through the client so peerUID runs.
	if _, err := v.Provision(me.Username); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, me.Username, "totp.secret"))
	code, _ := totp.GenerateCode(string(raw), time.Now())

	c := otpsockclient.New(sock, nil, nil)
	ok, err := c.Validate(me.Username, code)
	if err != nil || !ok {
		t.Fatalf("round-trip validate failed: ok=%v err=%v", ok, err)
	}
}
