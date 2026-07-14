package main

import (
	"bytes"
	"errors"
	"io"
	"os"
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
	lr := newTermLineReader(src, io.Discard, core.Dicts{}, nil, "")

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
	lr := newTermLineReader(src, io.Discard, core.Dicts{}, nil, "")

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
	lr := newTermLineReader(src, &bytes.Buffer{}, d, nil, "")

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("ReadLine err: %v", err)
	}
	if line != "whoami " {
		t.Fatalf("line = %q, want %q", line, "whoami ")
	}
}

// Tab on a non-first word completes a file path against the cwdFn directory,
// exercising the real AutoCompleteCallback path branch.
func TestTermLineReader_Tab_CompletesFilePath(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir+"/report.txt")
	cwdFn := func() (string, error) { return dir, nil }
	src := strings.NewReader("cat rep\t\r")
	lr := newTermLineReader(src, &bytes.Buffer{}, core.Dicts{}, cwdFn, "")

	line, err := lr.ReadLine("ssentry> ")
	if err != nil {
		t.Fatalf("ReadLine err: %v", err)
	}
	if line != "cat report.txt " {
		t.Fatalf("line = %q, want %q", line, "cat report.txt ")
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

func TestCompletePath(t *testing.T) {
	// Hermetic fs: cwd holds two prefix-sharing files, one unique file, and a
	// directory with a nested file. home is a separate dir for ~ expansion.
	cwd := t.TempDir()
	home := t.TempDir()
	mustWrite(t, cwd+"/alpha.txt")
	mustWrite(t, cwd+"/alptwo.txt")
	mustWrite(t, cwd+"/zeta.log")
	if err := os.Mkdir(cwd+"/subdir", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, cwd+"/subdir/nested.txt")
	mustWrite(t, home+"/homefile.txt")

	// abs is an absolute path prefix into cwd/subdir for the absolute-path case.
	abs := cwd + "/subdir/ne"

	tests := []struct {
		name   string
		line   string
		want   string // "" with wantOK false means no completion
		wantOK bool
	}{
		{"unique file adds space", "cat zet", "cat zeta.log ", true},
		{"directory gets trailing slash", "cd subd", "cd subdir/", true},
		{"completes inside a directory", "cat subdir/ne", "cat subdir/nested.txt ", true},
		{"absolute path", "cat " + abs, "cat " + cwd + "/subdir/nested.txt ", true},
		{"tilde expands to home", "cat ~/homef", "cat ~/homefile.txt ", true},
		{"no match", "cat nope", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPos, ok := completePath(tt.line, len(tt.line), cwd, home)
			if ok != tt.wantOK {
				t.Fatalf("completePath(%q) ok=%v, want %v (got %q)", tt.line, ok, tt.wantOK, got)
			}
			if ok {
				if got != tt.want {
					t.Fatalf("completePath(%q) = %q, want %q", tt.line, got, tt.want)
				}
				if gotPos != len(got) {
					t.Fatalf("pos = %d, want %d (end of completed token)", gotPos, len(got))
				}
			}
		})
	}
}

// alpha.txt|alptwo.txt share "alp"; base is already "alp" so there is no
// forward progress -> completePath returns false. Verified separately for clarity.
func TestCompletePath_AmbiguousNoProgress(t *testing.T) {
	cwd := t.TempDir()
	mustWrite(t, cwd+"/alpha.txt")
	mustWrite(t, cwd+"/alptwo.txt")
	if _, _, ok := completePath("cat alp", len("cat alp"), cwd, ""); ok {
		t.Fatal("ambiguous base at the common prefix must not complete")
	}
	// A shorter base does advance to the common prefix "alp".
	got, _, ok := completePath("cat al", len("cat al"), cwd, "")
	if !ok || got != "cat alp" {
		t.Fatalf("completePath(cat al) = (%q,%v), want (cat alp,true)", got, ok)
	}
}

func TestCompletePath_EmptyCwd_NoCompletion(t *testing.T) {
	if _, _, ok := completePath("cat foo", len("cat foo"), "", ""); ok {
		t.Fatal("empty cwd must disable relative path completion")
	}
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
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
