package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"shellsentry/core"
)

// trainFakeGeo resolves 8.8.8.8 -> US; used instead of repl_test.go's fakeGeo
// (which always returns "") because TestFlattenRows_ResolvesCountry needs a
// non-trivial lookup. Named distinctly to avoid colliding with fakeGeo.
type trainFakeGeo struct{}

func (trainFakeGeo) Country(ip string) (string, error) {
	if ip == "8.8.8.8" {
		return "US", nil
	}
	return "", nil
}

// fakeStore is a test double for the sessionStore interface used by
// trainSession: PruneAndLoad returns preset sessions + pruned count.
type fakeStore struct {
	sessions []core.Session
	pruned   int
	err      error
}

func (f *fakeStore) PruneAndLoad(_ string, keep int) ([]core.Session, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.sessions, f.pruned, nil
}

func mkSession(cmds ...string) core.Session {
	s := core.Session{Valid: true}
	for i, c := range cmds {
		s.Commands = append(s.Commands, core.CommandRecord{
			RawCmd: c, IP: "8.8.8.8", Feat: core.Feature{TimeCos: 1, SecsSinceLast: i}})
	}
	return s
}

func TestTrain_BelowMin_Skips(t *testing.T) {
	st := &fakeStore{sessions: []core.Session{mkSession("ls"), mkSession("ls"), mkSession("ls")}}
	var out bytes.Buffer
	cfg := Config{MinSessionsTrain: 10, MaxSessionsKeep: 500}
	err := trainSession(cfg, "u", trainFakeGeo{}, st, "/bin/false", "/dev/null", &out)
	if err != nil {
		t.Fatalf("below-min must not error: %v", err)
	}
	if !strings.Contains(out.String(), "not enough sessions") {
		t.Fatalf("expected skip message, got %q", out.String())
	}
}

// drainScript writes a tiny executable that reads all of stdin and exits 0,
// ignoring its args — a stand-in for the real trainer that neither errors on
// the passed script/--outdir args nor triggers a broken-pipe on the fed matrix.
func drainScript(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/drain.sh"
	if err := os.WriteFile(p, []byte("#!/bin/sh\ncat >/dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTrain_ReportsPruned(t *testing.T) {
	st := &fakeStore{sessions: []core.Session{mkSession("ls")}, pruned: 100}
	var out bytes.Buffer
	// RootPath = TempDir so the dicts.json write doesn't pollute the package dir.
	cfg := Config{MinSessionsTrain: 1, MaxSessionsKeep: 500, RootPath: t.TempDir()}
	if err := trainSession(cfg, "u", trainFakeGeo{}, st, drainScript(t), "/dev/null", &out); err != nil {
		t.Fatalf("train err: %v", err)
	}
	if !strings.Contains(out.String(), "pruned 100 old session") {
		t.Fatalf("expected pruned report, got %q", out.String())
	}
}

func TestTrain_TrainerFailure_Propagates(t *testing.T) {
	st := &fakeStore{sessions: []core.Session{mkSession("ls")}}
	var out bytes.Buffer
	cfg := Config{MinSessionsTrain: 1, MaxSessionsKeep: 500, RootPath: t.TempDir()}
	// "/bin/false" exits non-zero immediately -> runTrainer must return an error.
	if err := trainSession(cfg, "u", trainFakeGeo{}, st, "/bin/false", "/dev/null", &out); err == nil {
		t.Fatal("trainer failure must propagate as an error")
	}
}

func TestFlattenRows_ResolvesCountry(t *testing.T) {
	rows := flattenRows([]core.Session{mkSession("cat /etc/passwd")}, trainFakeGeo{})
	if len(rows) != 1 || rows[0].Country != "US" || rows[0].RawCmd != "cat /etc/passwd" {
		t.Fatalf("bad rows: %+v", rows)
	}
}

func TestResolvePython_MissingScript(t *testing.T) {
	_, _, err := resolvePython(Config{PythonBin: "/bin/sh", TrainerScript: "/no/such/trainer.py"})
	if err == nil {
		t.Fatal("missing trainer script must error")
	}
}

func TestResolvePython_MissingInterpreter(t *testing.T) {
	_, _, err := resolvePython(Config{PythonBin: "/no/such/python", TrainerScript: "/etc/hosts"})
	if err == nil {
		t.Fatal("missing interpreter must error")
	}
}

func TestResolvePython_BadDeps(t *testing.T) {
	// /bin/sh exists and /etc/hosts exists, but `/bin/sh -c "import sklearn, numpy"`
	// exits non-zero -> the deps check must fail.
	_, _, err := resolvePython(Config{PythonBin: "/bin/sh", TrainerScript: "/etc/hosts"})
	if err == nil {
		t.Fatal("interpreter without sklearn/numpy must error")
	}
}
