package ptyshell

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestMarkerPrefixHold(t *testing.T) {
	marker := "\x1eabc9\x1e"
	cases := []struct {
		name string
		s    string
		want int
	}{
		{"no prefix", "hello world", 0},
		{"empty", "", 0},
		{"trailing partial marker", "output\x1eab", 3},
		{"single RS byte", "line\x1e", 1},
		{"buffer shorter than marker", "\x1ea", 2},
		{"almost full marker", "x\x1eabc9", 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := markerPrefixHold(c.s, marker); got != c.want {
				t.Fatalf("markerPrefixHold(%q) = %d, want %d", c.s, got, c.want)
			}
		})
	}
}

// signalWriter closes ch the first time its accumulated output contains want.
type signalWriter struct {
	mu   sync.Mutex
	buf  []byte
	want string
	ch   chan struct{}
	done bool
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if !w.done && bytes.Contains(w.buf, []byte(w.want)) {
		w.done = true
		close(w.ch)
	}
	return len(p), nil
}

// TestRunCommand_StreamsBeforeExit guards the freeze bug: a full-screen program
// (vi/top) draws output and then blocks on input, so its bytes MUST reach the
// user before the command's sentinel arrives. Here the command prints "ABC" then
// sleeps 1s before exiting; the output has to surface well before the sleep ends.
// The old echo-gate withheld all output until the sentinel on shells that do not
// echo (dash on a raw pty), which froze vi.
func TestRunCommand_StreamsBeforeExit(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer devnull.Close()

	w := &signalWriter{want: "ABC", ch: make(chan struct{})}
	sh, err := New("nonce", devnull, w, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sh.Close()

	go func() { _, _ = sh.RunCommand("printf ABC; sleep 1") }()

	select {
	case <-w.ch: // streamed live, before the 1s sleep + sentinel
	case <-time.After(700 * time.Millisecond):
		t.Fatal("output not streamed before command exit — live-streaming regression")
	}
}

// TestRunCommand_ForwardsInputAfterIdle guards the input-proxy freeze: keystrokes
// typed AFTER the first idle poll tick must still reach an interactive program.
// The proxy reads the user tty in VMIN=0/VTIME=1 mode, where an idle read returns
// (0, io.EOF) every ~100ms; the old code treated that EOF as fatal and stopped
// forwarding, so vi/top became untypable after ~100ms. A real pty pair stands in
// for the user terminal; input is sent at 150ms (past the first tick) and must be
// delivered to `head -n 1`, which echoes the line and exits.
func TestRunCommand_ForwardsInputAfterIdle(t *testing.T) {
	userMaster, userTty, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer userMaster.Close()
	defer userTty.Close()

	var out bytes.Buffer
	sh, err := New("nonce", userTty, &out, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sh.Close()

	go func() {
		time.Sleep(150 * time.Millisecond) // past the first ~100ms idle tick
		_, _ = userMaster.WriteString("hello\n")
	}()

	code, err := sh.RunCommand("head -n 1")
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !bytes.Contains(out.Bytes(), []byte("hello")) {
		t.Fatalf("input not forwarded to program; out = %q", out.String())
	}
}

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
