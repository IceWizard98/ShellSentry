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
	"os/signal"
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
	cmdTimeout time.Duration  // 0 = no per-command wall-clock ceiling
	winch      chan os.Signal // SIGWINCH feed; nil when userTty is not a tty
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
	// term.MakeRaw clears OPOST, which drops the NL->CR-NL output translation.
	// The outer user tty is ALSO in raw mode (main sets it for term.Terminal),
	// so with both sides raw a bare LF from the shell moves the cursor down but
	// not to column 0 — every line stair-steps to the right and the prompt lands
	// mid-line. Re-enable OPOST|ONLCR on the pty so the shell's output carries
	// proper CR-LFs before we forward it. Best-effort: on failure output just
	// keeps stair-stepping, no crash.
	if t, err := unix.IoctlGetTermios(int(ptmx.Fd()), ioctlGetTermios); err == nil {
		t.Oflag |= unix.OPOST | unix.ONLCR
		_ = unix.IoctlSetTermios(int(ptmx.Fd()), ioctlSetTermios, t)
	}
	sh := &Shell{
		cmd:        c,
		ptmx:       ptmx,
		userTty:    userTty,
		userOut:    userOut,
		nonce:      nonce,
		cmdTimeout: cmdTimeout,
	}
	// Size the pty to the real terminal so `ls`/full-screen apps format for the
	// user's actual columns (default is 80). Keep it in sync on window resize;
	// ssentry sessions are long-lived SSH shells. No-op when userTty is not a
	// terminal (tests, pipes).
	if userTty != nil && term.IsTerminal(int(userTty.Fd())) {
		_ = pty.InheritSize(userTty, ptmx)
		sh.winch = make(chan os.Signal, 1)
		signal.Notify(sh.winch, unix.SIGWINCH)
		go func() {
			for range sh.winch {
				_ = pty.InheritSize(userTty, ptmx)
			}
		}()
	}
	return sh, nil
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
	echoHandled := false
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
			// Skip a leading echo of the injected command IF the interactive
			// shell echoed it — some do, dash on a raw pty does not. The echo,
			// when present, is the shell repeating our injected bytes, so while
			// the stream is still a prefix of `inject` it may be echo-in-progress
			// and we hold. As soon as it diverges (or the very first byte already
			// differs — a full-screen program's leading ESC), the echo is over:
			// drop the echoed line if we can spot it, then stream live. This
			// NEVER blocks waiting for an echo that will not come, so vi/top/nano
			// render immediately instead of freezing.
			if !echoHandled {
				if strings.HasPrefix(inject, full) {
					continue // still possibly inside the echoed command line
				}
				if i := strings.Index(full, "\n"); i >= 0 && strings.HasPrefix(full[:i], line) {
					flushed = i + 1 // drop the echoed line and its newline
				}
				echoHandled = true
			}
			safe := len(full) - markerPrefixHold(full, marker)
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
		if !echoHandled {
			output = stripEcho(output, line)
			flushed = 0
		}
		if flushed < len(output) {
			if _, err := io.WriteString(s.userOut, output[flushed:]); err != nil {
				return 0, fmt.Errorf("ptyshell: write user output: %w", err)
			}
		}
		s.drainMarkerEOL()
		return code, nil
	}
}

// drainMarkerEOL consumes the newline the sentinel printf emits after the
// closing RS byte. With ONLCR on the pty that newline is "\r\n"; left unread it
// surfaces as a blank line at the start of the NEXT command's output (the marker
// terminator is protocol, not user output, so all of it must be consumed).
// Bounded to the "\r\n" it always produces, and best-effort: a read error just
// leaves the loop, since the caller has already got its exit code.
func (s *Shell) drainMarkerEOL() {
	for i := 0; i < 2; i++ {
		b, err := s.readByte()
		if err != nil {
			return
		}
		if b == '\n' {
			return
		}
		if b != '\r' {
			return // unexpected (format guarantees CR/LF); don't swallow real output
		}
	}
}

// Cwd returns the shell's current working directory by running a silent `pwd`
// (output captured, not streamed to userOut). It lets the REPL render a
// contextual prompt and complete file paths against the shell's real directory
// — which the persistent /bin/sh owns and mutates via `cd`, invisibly to us.
// Safe to call only between commands (no RunCommand in flight): the REPL builds
// the prompt before reading a line and completes on Tab while the read blocks,
// so the ptmx is never read concurrently.
func (s *Shell) Cwd() (string, error) {
	out, _, err := s.runCaptured("pwd")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripEcho(out, "pwd")), nil
}

// runCaptured injects line with the sentinel like RunCommand, but accumulates
// all output into a string instead of streaming it to userOut, and runs no
// input proxy / raw-mode toggle (it is for internal, non-interactive queries
// such as `pwd`). Returns the captured output (echo included) and exit code.
func (s *Shell) runCaptured(line string) (string, int, error) {
	s.nextID++
	id := s.nextID

	marker := fmt.Sprintf("\x1e%s%d\x1e", s.nonce, id)
	markerLiteral := fmt.Sprintf(`\036%s%d\036`, s.nonce, id)
	inject := fmt.Sprintf("%s; printf '%s%%d\\036\\n' $?\n", line, markerLiteral)
	if _, err := io.WriteString(s.ptmx, inject); err != nil {
		return "", 0, fmt.Errorf("ptyshell: inject captured command: %w", err)
	}

	var acc strings.Builder
	var deadline time.Time
	if s.cmdTimeout > 0 {
		deadline = time.Now().Add(s.cmdTimeout)
	}
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return "", 0, fmt.Errorf("ptyshell: captured command produced no sentinel within %s", s.cmdTimeout)
		}
		b, err := s.readByte()
		if err != nil {
			return "", 0, fmt.Errorf("ptyshell: read pty: %w", err)
		}
		acc.WriteByte(b)

		full := acc.String()
		idx := strings.Index(full, marker)
		if idx < 0 {
			continue
		}
		output := full[:idx]
		rest := full[idx+len(marker):]
		for !strings.Contains(rest, "\x1e") {
			b2, err := s.readByte()
			if err != nil {
				return "", 0, fmt.Errorf("ptyshell: read exit code: %w", err)
			}
			rest += string(b2)
		}
		exitStr := rest[:strings.Index(rest, "\x1e")]
		code, convErr := strconv.Atoi(strings.TrimSpace(exitStr))
		if convErr != nil {
			return "", 0, fmt.Errorf("ptyshell: parse exit code %q: %w", exitStr, convErr)
		}
		s.drainMarkerEOL()
		return output, code, nil
	}
}

// markerPrefixHold returns how many trailing bytes of s to withhold from the
// live stream because they could be the START of marker (a sentinel split
// across reads). It is 0 in the common case, so a full-screen program (vi, top)
// that draws a screen and then blocks on input renders live instead of stalling
// on a withheld tail. Bounded by len(marker)-1: a full match is handled by the
// caller's strings.Index path.
func markerPrefixHold(s, marker string) int {
	max := len(marker) - 1
	if max > len(s) {
		max = len(s)
	}
	for n := max; n > 0; n-- {
		if strings.HasPrefix(marker, s[len(s)-n:]) {
			return n
		}
	}
	return 0
}

// stripEcho drops the leading echoed command line that the -i shell prints
// back before the command's own output.
func stripEcho(output, line string) string {
	// HasPrefix (not Contains): the echo is the injected line, which STARTS with
	// `line`; a mere substring match would wrongly strip real output whose first
	// line happens to contain the command name (e.g. a cwd like /home/pwd).
	if i := strings.Index(output, "\n"); i >= 0 && strings.HasPrefix(output[:i], line) {
		return output[i+1:]
	}
	return output
}

// proxyInput copies user-tty keystrokes into the pty master until done is
// closed. The tty is in VMIN=0/VTIME=1 raw mode (see makeRawPolling): an idle
// read returns (0, io.EOF) after ~100ms because Go maps a zero-byte tty read to
// io.EOF. That is the poll TICK, not real end of input — it MUST NOT stop
// forwarding, or the user can no longer type into interactive programs (vi,
// top) after the first idle moment. So we ignore the read error entirely, write
// through whatever bytes we got, and exit only via `done` (command finished) or
// a pty write failure (shell gone). The ~100ms VTIME cadence paces idle reads,
// so this does not busy-spin while the tty stays open.
func (s *Shell) proxyInput(done <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, _ := s.userTty.Read(buf)
		if n > 0 {
			if _, err := s.ptmx.Write(buf[:n]); err != nil {
				<-done // shell gone; stay alive until the caller closes done
				return
			}
		}
	}
}

// Close terminates the persistent shell: requests a graceful exit, closes
// the PTY, then kills and waits on the process to avoid leaking it.
func (s *Shell) Close() error {
	if s.winch != nil {
		signal.Stop(s.winch)
		close(s.winch)
	}
	_, _ = io.WriteString(s.ptmx, "exit\n")
	_ = s.ptmx.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
	return nil
}
