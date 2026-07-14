package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"

	"shellsentry/core"
)

// LineReader reads one command/OTP line at a time and doubles as the user-facing
// writer, so the REPL is agnostic to whether it is driving a real tty (with
// history + autocomplete via term.Terminal) or a plain byte stream (tests, pipes).
type LineReader interface {
	ReadLine(prompt string) (string, error)
	io.Writer
}

// plainLineReader is the non-tty path: it prints the prompt and reads a line
// byte-wise via readLine, never reading past the newline (so ptyshell keeps any
// type-ahead). Identical behavior to the pre-line-editor REPL.
type plainLineReader struct {
	in  io.Reader
	out io.Writer
}

func (p *plainLineReader) ReadLine(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	return readLine(p.in)
}

func (p *plainLineReader) Write(b []byte) (int, error) { return p.out.Write(b) }

// oneByteReader caps every Read to a single byte and drops 0x03 (Ctrl-C). The
// cap is what keeps term.Terminal from reading past a newline into type-ahead
// bytes that ptyshell reads straight off the raw fd during a command. Dropping
// 0x03 makes Ctrl-C a no-op at the prompt (term would otherwise turn it into
// io.EOF and end the session) — consistent with main's SIGINT drain. During a
// running command ptyshell reads the fd directly, so Ctrl-C still interrupts.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var b [1]byte
	for {
		n, err := o.r.Read(b[:])
		if n > 0 && b[0] == 0x03 {
			if err != nil {
				return 0, err
			}
			continue // swallow Ctrl-C, read the next byte
		}
		if n > 0 {
			p[0] = b[0]
		}
		return n, err
	}
}

// termLineReader drives a single term.Terminal for the whole session so its
// line history (arrow up/down) accumulates. term echoes and edits in raw mode;
// Tab completion is served by the vocabulary + this session's commands.
type termLineReader struct {
	t     *term.Terminal
	dicts core.Dicts
	seen  []string               // first words typed this session (autocomplete source)
	cwdFn func() (string, error) // shell cwd for file completion; nil disables it
	home  string                 // for "~" expansion in path completion
}

func newTermLineReader(in io.Reader, out io.Writer, d core.Dicts, cwdFn func() (string, error), home string) *termLineReader {
	lr := &termLineReader{dicts: d, cwdFn: cwdFn, home: home}
	rw := struct {
		io.Reader
		io.Writer
	}{oneByteReader{in}, out}
	lr.t = term.NewTerminal(rw, "")
	lr.t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			return "", 0, false
		}
		// First word (nothing but the cursor's token before it) -> complete a
		// command name. Otherwise -> complete a filesystem path against the
		// shell's cwd. `cd `/`cat ` etc. land in the path branch.
		if pos > 0 && strings.IndexByte(line[:pos], ' ') == -1 {
			return completeFirstWord(line, pos, lr.candidates())
		}
		if lr.cwdFn == nil {
			return "", 0, false
		}
		cwd, err := lr.cwdFn()
		if err != nil {
			return "", 0, false
		}
		return completePath(line, pos, cwd, lr.home)
	}
	return lr
}

func (l *termLineReader) ReadLine(prompt string) (string, error) {
	l.t.SetPrompt(prompt)
	line, err := l.t.ReadLine()
	if err == nil {
		if w := strings.Fields(line); len(w) > 0 {
			l.seen = append(l.seen, w[0])
		}
	}
	return line, err
}

func (l *termLineReader) Write(b []byte) (int, error) { return l.t.Write(b) }

// SetSize tells the line editor the real terminal dimensions so its cursor and
// line-wrap model match the tty (term.Terminal otherwise assumes 80 columns,
// misplacing the prompt after wide command output).
func (l *termLineReader) SetSize(w, h int) { _ = l.t.SetSize(w, h) }

// candidates returns the sorted, de-duplicated command-name set for Tab
// completion: the trained vocabulary plus commands typed this session.
func (l *termLineReader) candidates() []string {
	set := make(map[string]struct{}, len(l.dicts.Command)+len(l.seen))
	for cmd := range l.dicts.Command {
		set[cmd] = struct{}{}
	}
	for _, cmd := range l.seen {
		set[cmd] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for cmd := range set {
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
}

// completeFirstWord completes the first word of line against candidates. It only
// fires while the cursor is still inside the first word. Returns the new line,
// new cursor position, and whether it changed anything. It completes to the
// longest common prefix of the matches; when that prefix equals a whole
// candidate uniquely, it appends a trailing space. Deliberately limited: first
// word only, no path/argument completion, no Tab-cycling through matches.
func completeFirstWord(line string, pos int, candidates []string) (string, int, bool) {
	// Only complete when editing the first word (no space before the cursor).
	if pos == 0 || strings.IndexByte(line[:pos], ' ') != -1 {
		return "", 0, false
	}
	prefix := line[:pos]
	rest := line[pos:]

	var matches []string
	for _, c := range candidates {
		if strings.HasPrefix(c, prefix) {
			matches = append(matches, c)
		}
	}
	if len(matches) == 0 {
		return "", 0, false
	}

	lcp := longestCommonPrefix(matches)
	if len(matches) == 1 {
		completed := lcp + " "
		return completed + rest, len(completed), true
	}
	if len(lcp) <= len(prefix) {
		return "", 0, false // ambiguous, no forward progress
	}
	return lcp + rest, len(lcp), true
}

// completePath completes the path token under the cursor against the real
// filesystem, resolving relative tokens against cwd (the shell's working
// directory) and a leading "~" against home. Directory matches get a trailing
// "/" (so a second Tab descends into them); a unique file match gets a trailing
// space. It completes only up to the longest common prefix when ambiguous, and
// returns ok=false on no match, an unreadable directory, or an empty cwd for a
// relative token. Whitespace-tokenized (no shell-quote handling), matching
// core.SplitCommand's documented simplification.
func completePath(line string, pos int, cwd, home string) (string, int, bool) {
	tokenStart := strings.LastIndexByte(line[:pos], ' ') + 1
	token := line[tokenStart:pos]
	rest := line[pos:]

	// Split the token into the directory part (kept verbatim for display) and
	// the base being completed; resolve the directory part to a real fs path.
	var displayDir, base, fsDir string
	if slash := strings.LastIndexByte(token, '/'); slash >= 0 {
		displayDir = token[:slash+1]
		base = token[slash+1:]
		fsDir = expandDir(displayDir, cwd, home)
	} else {
		base = token
		fsDir = cwd
	}
	if fsDir == "" {
		return "", 0, false // relative token but shell cwd unknown
	}

	entries, err := os.ReadDir(fsDir)
	if err != nil {
		return "", 0, false
	}
	var matches []string
	for _, e := range entries {
		name := e.Name()
		// Hide dotfiles unless the user explicitly typed a leading dot.
		if !strings.HasPrefix(base, ".") && strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasPrefix(name, base) {
			continue
		}
		if e.IsDir() {
			name += "/"
		}
		matches = append(matches, name)
	}
	if len(matches) == 0 {
		return "", 0, false
	}

	var completed string
	if len(matches) == 1 {
		completed = matches[0]
		if !strings.HasSuffix(completed, "/") {
			completed += " " // unique file: advance past it
		}
	} else {
		lcp := longestCommonPrefix(matches)
		if len(lcp) <= len(base) {
			return "", 0, false // ambiguous, no forward progress
		}
		completed = lcp
	}

	newLine := line[:tokenStart] + displayDir + completed
	return newLine + rest, len(newLine), true
}

// expandDir resolves a token's directory part to an absolute filesystem path:
// a leading "~/" against home, an absolute path as-is, and a relative path
// against cwd. Returns "" when it cannot resolve (relative with empty cwd).
func expandDir(displayDir, cwd, home string) string {
	switch {
	case strings.HasPrefix(displayDir, "~/"):
		if home == "" {
			return ""
		}
		return filepath.Join(home, displayDir[2:])
	case strings.HasPrefix(displayDir, "/"):
		return displayDir
	default:
		if cwd == "" {
			return ""
		}
		return filepath.Join(cwd, displayDir)
	}
}

func longestCommonPrefix(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
			if p == "" {
				return ""
			}
		}
	}
	return p
}
