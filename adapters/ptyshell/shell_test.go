package ptyshell

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestRunCommand_ExitCodeAndStatePersists(t *testing.T) {
	var out bytes.Buffer
	// userIn is unused for non-interactive commands; pass /dev/null.
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()

	sh, err := New("TESTNONCE", devnull, &out, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	if code, err := sh.RunCommand("true"); err != nil || code != 0 {
		t.Fatalf("true: code=%d err=%v", code, err)
	}
	if code, err := sh.RunCommand("false"); err != nil || code != 1 {
		t.Fatalf("false: code=%d err=%v", code, err)
	}
	// state persists across commands (cd then pwd)
	if code, err := sh.RunCommand("cd /tmp"); err != nil || code != 0 {
		t.Fatalf("cd: code=%d err=%v", code, err)
	}
	out.Reset()
	if code, err := sh.RunCommand("pwd"); err != nil || code != 0 {
		t.Fatalf("pwd: code=%d err=%v", code, err)
	}
	if !bytes.Contains(out.Bytes(), []byte("/tmp")) {
		t.Fatalf("cwd did not persist; out=%q", out.String())
	}
}

// TestRunCommand_ProxyActive_DoesNotDeadlock exercises the interactive path:
// userTty is a real pty slave, so term.IsTerminal is true and the keystroke
// proxy goroutine + raw-tty polling run concurrently with the pty-master read
// loop. This is the exact combination that deadlocked the runtime poller on
// macOS/BSD before switching to VMIN/VTIME polling. The command produces
// output and must complete promptly with the correct exit code.
//
// Note: this does NOT assert keystroke *forwarding* (feeding a `read`/`cat`),
// because a synthetic pty slave on macOS returns EOF immediately when read by
// a process that is not its controlling-terminal session, which no real ssh
// stdin does. Keystroke forwarding (vi/nano/top/less actually receiving input)
// is verified manually per the plan's Task 15 acceptance step.
func TestRunCommand_ProxyActive_DoesNotDeadlock(t *testing.T) {
	userPtmx, userTty, err := pty.Open()
	if err != nil {
		t.Fatalf("open user pty: %v", err)
	}
	defer userPtmx.Close()
	defer userTty.Close()

	var out bytes.Buffer
	sh, err := New("TESTNONCE", userTty, &out, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	done := make(chan int, 1)
	go func() {
		code, cerr := sh.RunCommand("echo interactive-ok")
		if cerr != nil {
			t.Errorf("RunCommand err: %v", cerr)
		}
		done <- code
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !bytes.Contains(out.Bytes(), []byte("interactive-ok")) {
			t.Fatalf("output missing; out=%q", out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy-active command hung: poller deadlock regression")
	}
}
