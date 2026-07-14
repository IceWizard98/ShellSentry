package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"shellsentry/core"
)

// The load-bearing invariant: the terminal line editor must not read past the
// newline, or it would steal type-ahead bytes that ptyshell reads directly off
// the raw fd during an interactive command (vi/top).
func TestTermLineReader_NoReadAhead_LeavesTypeAheadInBuffer(t *testing.T) {
	// Raw-mode Enter is CR ('\r'), which is what term.Terminal treats as end of
	// line (keyEnter = '\r'); the outer tty has ICRNL off.
	src := strings.NewReader("ls\rEXTRA")
	lr := newTermLineReader(src, io.Discard, core.Dicts{})

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("ReadLine err: %v", err)
	}
	if line != "ls" {
		t.Fatalf("line = %q, want %q", line, "ls")
	}
	rest, _ := io.ReadAll(src)
	if string(rest) != "EXTRA" {
		t.Fatalf("type-ahead stolen: leftover = %q, want %q", rest, "EXTRA")
	}
}

// Ctrl-C (0x03) at the prompt must be a no-op, not end the session: it is
// dropped before term sees it (term would otherwise turn it into io.EOF).
func TestTermLineReader_CtrlC_Dropped_PromptContinues(t *testing.T) {
	src := strings.NewReader("\x03ls\r")
	lr := newTermLineReader(src, io.Discard, core.Dicts{})

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("Ctrl-C must not end the line, got err %v", err)
	}
	if line != "ls" {
		t.Fatalf("line = %q, want %q", line, "ls")
	}
}

// Tab completes the first word against the trained vocabulary via the real
// AutoCompleteCallback wiring.
func TestTermLineReader_Tab_CompletesKnownCommand(t *testing.T) {
	src := strings.NewReader("who\t\r")
	d := core.Dicts{Command: map[string]int{"whoami": 5}}
	lr := newTermLineReader(src, &bytes.Buffer{}, d)

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("ReadLine err: %v", err)
	}
	if line != "whoami " {
		t.Fatalf("line = %q, want %q", line, "whoami ")
	}
}

func TestCompleteFirstWord(t *testing.T) {
	cands := []string{"git", "grep", "group", "grouped", "grow", "ls", "whoami"}
	tests := []struct {
		name    string
		line    string
		pos     int
		want    string
		wantPos int
		wantOK  bool
	}{
		{"unique match adds space", "who", 3, "whoami ", 7, true},
		{"unique among gr* adds space", "gre", 3, "grep ", 5, true},   // grep unique among gre*
		{"extends to common prefix", "gro", 3, "gro", 3, false},       // group|grow lcp "gro" = prefix, no progress
		{"advances prefix", "g", 1, "g", 1, false},                    // git|grep|group|grow lcp "g", no progress
		{"common prefix advances", "gr", 2, "gr", 2, false},           // grep|group|grow lcp "gr" = prefix
		{"multi-match extends no space", "grou", 4, "group", 5, true}, // group|grouped lcp "group" > prefix
		{"no match", "xyz", 3, "", 0, false},
		{"already complete", "ls", 2, "ls ", 3, true},
		{"empty line", "", 0, "", 0, false},
		{"only first word completes", "ls foo", 6, "", 0, false}, // pos not in first word
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPos, ok := completeFirstWord(tt.line, tt.pos, cands)
			if ok != tt.wantOK || (ok && (got != tt.want || gotPos != tt.wantPos)) {
				t.Fatalf("completeFirstWord(%q,%d) = (%q,%d,%v), want (%q,%d,%v)",
					tt.line, tt.pos, got, gotPos, ok, tt.want, tt.wantPos, tt.wantOK)
			}
		})
	}
}

// plainLineReader preserves the exact byte-wise, no-read-ahead behavior for the
// non-tty path (tests, pipes).
func TestPlainLineReader_ReadsLine_NoReadAhead(t *testing.T) {
	src := strings.NewReader("ls\nEXTRA")
	var out bytes.Buffer
	lr := &plainLineReader{in: src, out: &out}

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("ReadLine err: %v", err)
	}
	if line != "ls" {
		t.Fatalf("line = %q, want %q", line, "ls")
	}
	if rest, _ := io.ReadAll(src); string(rest) != "EXTRA" {
		t.Fatalf("leftover = %q, want EXTRA", rest)
	}
	if !strings.Contains(out.String(), "ssentry> ") {
		t.Fatalf("prompt not written: %q", out.String())
	}
}

func TestPlainLineReader_EOF(t *testing.T) {
	lr := &plainLineReader{in: strings.NewReader(""), out: io.Discard}
	_, err := lr.ReadLine("> ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
}
