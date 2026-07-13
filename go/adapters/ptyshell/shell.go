// Package ptyshell implements ports.Shell using a persistent /bin/sh -i
// process attached to a pseudo-terminal. Each injected command is followed
// by a printf that emits a sentinel marker plus the exit code, so RunCommand
// can find where the command's output ends and recover its exit status.
package ptyshell

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// makeRawPolling puts the tty into raw mode with VMIN=0/VTIME=1: reads return
// immediately with whatever is available, or empty after ~100ms if nothing is.
// This lets the input-proxy poll a done flag without a Go read deadline (which
// deadlocks the runtime poller on a raw tty on macOS/BSD). Returns a restore
// func that reverts the original termios.
func makeRawPolling(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 1 // 0.1s
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &raw); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }, nil
}

// Shell wraps a persistent /bin/sh -i on a PTY. Per-command output is
// delimited by a sentinel: \x1e<nonce><id>\x1e<exit>\x1e\n emitted after the
// command returns.
type Shell struct {
	cmd        *exec.Cmd
	ptmx       *os.File
	rbuf       [1]byte // scratch for readByte
	userTty    *os.File
	userOut    io.Writer
	nonce      string
	nextID     int
	cmdTimeout time.Duration // 0 = no per-command wall-clock ceiling
}

// New spawns /bin/sh -i on a new PTY. userOut receives the command output
// streamed live (sentinel stripped); userTty is the real user terminal
// (typically os.Stdin) whose keystrokes are proxied into interactive commands.
// The pty master is left in its normal mode; raw mode is toggled on userTty
// during command execution (see RunCommand). cmdTimeout is a per-command
// wall-clock ceiling (0 = disabled) — a backstop against a command that never
// emits its sentinel (e.g. a shell line left in continuation); on expiry
// RunCommand returns an error and the caller tears the session down.
func New(nonce string, userTty *os.File, userOut io.Writer, cmdTimeout time.Duration) (*Shell, error) {
	c := exec.Command("/bin/sh", "-i")
	c.Env = append(os.Environ(), "PS1=", "PS2=")
	ptmx, err := pty.Start(c)
	if err != nil {
		return nil, fmt.Errorf("ptyshell: start pty: %w", err)
	}
	// Put the pty's line discipline into raw mode so the shell's own
	// echo/line-editing does not mangle the control bytes (0x1e sentinel) we
	// send/receive or double-echo the injected command line. This configures
	// the pty termios, NOT the outer user tty (that is toggled per-command in
	// RunCommand).
	if _, err := term.MakeRaw(int(ptmx.Fd())); err != nil {
		_ = ptmx.Close()
		_ = c.Process.Kill()
		return nil, fmt.Errorf("ptyshell: set pty raw mode: %w", err)
	}
	return &Shell{
		cmd:        c,
		ptmx:       ptmx,
		userTty:    userTty,
		userOut:    userOut,
		nonce:      nonce,
		cmdTimeout: cmdTimeout,
	}, nil
}

// readByte reads one byte from the pty master using a short read deadline and
// retrying on timeout. Deadline-based polling (rather than a naked blocking
// read) is REQUIRED: when the input-proxy goroutine polls the user tty with
// its own SetReadDeadline, a concurrent blocking read on this pty deadlocks the
// runtime poller on macOS/BSD. Both sides must poll cooperatively.
func (s *Shell) readByte() (byte, error) {
	for {
		_ = s.ptmx.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := s.ptmx.Read(s.rbuf[:])
		if n > 0 {
			return s.rbuf[0], nil
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return 0, err
		}
	}
}

// RunCommand injects the command into the persistent shell, streams its
// output to userOut, and returns its exit code once the sentinel marker for
// this command id is observed.
//
// Byte-wise accumulation, not ReadString('\n') — the shell echo
// and printf output can arrive in fragments that split the marker across
// reads, and a command with no trailing newline in its output would never
// terminate a line-oriented read.
func (s *Shell) RunCommand(line string) (int, error) {
	s.nextID++
	id := s.nextID

	// Put the OUTER user tty into raw mode for the duration of execution so
	// interactive/full-screen programs (vi, top, less, ...) get keystrokes
	// unbuffered and unechoed by the outer terminal. We use VMIN=0/VTIME=1
	// (not term.MakeRaw's blocking VMIN=1) so the proxy's reads self-return
	// every ~100ms and can observe `done` — combining term.MakeRaw with a Go
	// SetReadDeadline deadlocks the runtime poller on macOS/BSD. No-op when
	// userTty is not a terminal (e.g. /dev/null in tests).
	interactive := s.userTty != nil && term.IsTerminal(int(s.userTty.Fd()))
	var restore func()
	if interactive {
		if r, err := makeRawPolling(int(s.userTty.Fd())); err == nil {
			restore = r
		} else {
			interactive = false // could not set raw mode; skip proxying
		}
	}
	if restore != nil {
		defer restore()
	}

	// Start proxying user keystrokes into the pty. The goroutine does plain
	// blocking reads that self-return periodically (via VTIME) so it can notice
	// `done` (set once the sentinel is seen) and stop without stealing bytes
	// meant for the next command's cooked-mode read.
	var wg sync.WaitGroup
	done := make(chan struct{})
	if interactive {
		wg.Add(1)
		go s.proxyInput(done, &wg)
	}
	// Ensure the input proxy is stopped and drained before we return, so the
	// next RunCommand's cooked-mode read owns the tty exclusively.
	defer wg.Wait()
	defer close(done)

	// marker is the actual byte sequence to look for in the PTY's output:
	// 0x1e (RS) nonce id 0x1e.
	marker := fmt.Sprintf("\x1e%s%d\x1e", s.nonce, id)
	// markerLiteral is the same sequence spelled out as shell text using an
	// OCTAL escape (\036 == 0x1e), NOT the raw 0x1e byte and NOT a \xHH hex
	// escape. Two reasons: (1) sending the raw control byte as PTY *input* gets
	// intercepted/stripped by the shell's line editor; (2) hex escapes (\x1e)
	// are a bashism — dash (the default /bin/sh on Debian/Ubuntu) prints them
	// literally, so the marker would never appear and RunCommand would hang.
	// Octal escapes are POSIX and work in both dash and bash. The escape only
	// becomes the real byte once printf expands it on the way *out*.
	markerLiteral := fmt.Sprintf(`\036%s%d\036`, s.nonce, id)
	inject := fmt.Sprintf("%s; printf '%s%%d\\036\\n' $?\n", line, markerLiteral)
	if _, err := io.WriteString(s.ptmx, inject); err != nil {
		return 0, fmt.Errorf("ptyshell: inject command: %w", err)
	}

	// acc accumulates the command's output bytes until the sentinel marker
	// appears. We flush already-safe bytes to userOut as they arrive (so
	// full-screen interactive programs render live) while holding back a
	// trailing window that could still turn out to be the start of the marker.
	var acc strings.Builder
	echoStripped := false
	flushed := 0 // index in acc up to which bytes are already written to userOut
	var deadline time.Time
	if s.cmdTimeout > 0 {
		deadline = time.Now().Add(s.cmdTimeout)
	}
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, fmt.Errorf("ptyshell: command produced no sentinel within %s (shell may be stuck in continuation)", s.cmdTimeout)
		}
		b, err := s.readByte()
		if err != nil {
			return 0, fmt.Errorf("ptyshell: read pty: %w", err)
		}
		acc.WriteByte(b)

		full := acc.String()
		idx := strings.Index(full, marker)
		if idx < 0 {
			// Stream everything except a trailing window that might be a
			// partial marker. Once the leading echoed command line is
			// stripped, forward the safe prefix live.
			if !echoStripped {
				if i := strings.Index(full, "\n"); i >= 0 && strings.Contains(full[:i], line) {
					flushed = i + 1
					echoStripped = true
				} else {
					continue // still buffering the echo line
				}
			}
			safe := len(full) - len(marker) // keep marker-length tail back
			if safe > flushed {
				if _, err := io.WriteString(s.userOut, full[flushed:safe]); err != nil {
					return 0, fmt.Errorf("ptyshell: write user output: %w", err)
				}
				flushed = safe
			}
			continue
		}

		output := full[:idx]
		rest := full[idx+len(marker):]

		// Read until we see the exit code's terminating \x1e.
		for !strings.Contains(rest, "\x1e") {
			b2, err := s.readByte()
			if err != nil {
				return 0, fmt.Errorf("ptyshell: read exit code: %w", err)
			}
			rest += string(b2)
		}
		exitStr := rest[:strings.Index(rest, "\x1e")]

		code, convErr := strconv.Atoi(strings.TrimSpace(exitStr))
		if convErr != nil {
			return 0, fmt.Errorf("ptyshell: parse exit code %q: %w", exitStr, convErr)
		}

		// Flush any output between what we already streamed and the marker.
		// output == full[:idx]; bytes [flushed:idx] are the not-yet-written
		// tail (held-back partial-marker window + anything before echo strip).
		if !echoStripped {
			output = stripEcho(output, line)
			flushed = 0
		}
		if flushed < len(output) {
			if _, err := io.WriteString(s.userOut, output[flushed:]); err != nil {
				return 0, fmt.Errorf("ptyshell: write user output: %w", err)
			}
		}
		return code, nil
	}
}

// stripEcho drops the leading echoed command line that the -i shell prints
// back before the command's own output.
func stripEcho(output, line string) string {
	if i := strings.Index(output, "\n"); i >= 0 && strings.Contains(output[:i], line) {
		return output[i+1:]
	}
	return output
}

// proxyInput copies user-tty keystrokes into the pty master until done is
// closed. The tty is in VMIN=0/VTIME=1 raw mode (see makeRawPolling), so a
// read with no input available returns n=0 after ~100ms; the loop then checks
// done. This yields the tty promptly once the command finishes without
// consuming bytes intended for the next command's cooked-mode read, and
// without a Go read deadline (which deadlocks the poller in raw mode on
// macOS/BSD).
func (s *Shell) proxyInput(done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := s.userTty.Read(buf)
		if n > 0 {
			_, _ = s.ptmx.Write(buf[:n])
		}
		if err != nil {
			// EOF/real error: stop forwarding but stay alive until done so the
			// main loop's deferred wg.Wait does not block on a dead goroutine
			// racing the sentinel.
			<-done
			return
		}
	}
}

// Close terminates the persistent shell: requests a graceful exit, closes
// the PTY, then kills and waits on the process to avoid leaking it.
func (s *Shell) Close() error {
	_, _ = io.WriteString(s.ptmx, "exit\n")
	_ = s.ptmx.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
	return nil
}
