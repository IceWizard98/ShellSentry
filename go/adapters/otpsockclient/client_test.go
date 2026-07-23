package otpsockclient

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeOTPD records the ops it receives and answers with canned responses, so a
// test can assert the client drives the right protocol sequence.
type fakeOTPD struct {
	mu       sync.Mutex
	ops      []string
	enrolled bool
	validOK  bool
}

func (f *fakeOTPD) serve(t *testing.T) string {
	t.Helper()
	ff, err := os.CreateTemp("/tmp", "ssc-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sock := ff.Name()
	ff.Close()
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
			var req Request
			if json.NewDecoder(conn).Decode(&req) == nil {
				f.mu.Lock()
				f.ops = append(f.ops, req.Op)
				resp := Response{}
				switch req.Op {
				case "status":
					resp.Enrolled = f.enrolled
				case "provision":
					resp.URI = "otpauth://totp/shellsentry:x?secret=AAAA&issuer=shellsentry"
				case "validate":
					resp.OK = f.validOK
				default:
					resp.OK = true
				}
				f.mu.Unlock()
				_ = json.NewEncoder(conn).Encode(resp)
			}
			conn.Close()
		}
	}()
	return sock
}

func (f *fakeOTPD) seen(op string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.ops {
		if o == op {
			return true
		}
	}
	return false
}

func TestEnsureProvisioned_Confirm_SendsConfirm(t *testing.T) {
	f := &fakeOTPD{}
	c := New(f.serve(t), strings.NewReader("y\n"), io.Discard)
	if err := c.EnsureProvisioned("alice"); err != nil {
		t.Fatal(err)
	}
	if !f.seen("provision") || !f.seen("confirm") {
		t.Fatalf("expected provision+confirm, got %v", f.ops)
	}
	if f.seen("discard") {
		t.Fatal("must not discard when the user confirmed")
	}
}

func TestEnsureProvisioned_Decline_SendsDiscard(t *testing.T) {
	f := &fakeOTPD{}
	c := New(f.serve(t), strings.NewReader("n\n"), io.Discard)
	if err := c.EnsureProvisioned("alice"); err != nil {
		t.Fatal(err)
	}
	if !f.seen("discard") || f.seen("confirm") {
		t.Fatalf("declined enrollment must discard, not confirm; got %v", f.ops)
	}
}

func TestEnsureProvisioned_AlreadyEnrolled_ShortCircuits(t *testing.T) {
	f := &fakeOTPD{enrolled: true}
	c := New(f.serve(t), strings.NewReader(""), io.Discard)
	if err := c.EnsureProvisioned("alice"); err != nil {
		t.Fatal(err)
	}
	if f.seen("provision") {
		t.Fatalf("enrolled user must not be re-provisioned; got %v", f.ops)
	}
}

func TestValidate_ReturnsServerVerdict(t *testing.T) {
	f := &fakeOTPD{validOK: true}
	c := New(f.serve(t), nil, nil)
	ok, err := c.Validate("alice", "123456")
	if err != nil || !ok {
		t.Fatalf("validate should pass: ok=%v err=%v", ok, err)
	}
}
