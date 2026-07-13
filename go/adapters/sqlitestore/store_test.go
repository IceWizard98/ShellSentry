package sqlitestore

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"shellsentry/core"
)

func TestSaveSession_RoundTrip(t *testing.T) {
	root := t.TempDir()
	st := New(root)
	defer st.Close()

	s := core.NewSession(1000)
	s.EndTS = 1100
	s.Add(core.CommandRecord{
		TS:     1010,
		RawCmd: "cat /etc/passwd",
		IP:     "1.2.3.4",
		Feat:   core.Feature{GeoID: 1, CmdIndex: 6, PathIndex: 3, SecsSinceLast: 10},
	})
	if err := st.SaveSession("alice", s); err != nil {
		t.Fatalf("save: %v", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(root, "alice", "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var cnt, cmdCount int
	if err := db.QueryRow(`SELECT command_count FROM session`).Scan(&cmdCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM command`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cmdCount != 1 || cnt != 1 {
		t.Fatalf("command_count=%d rows=%d want 1,1", cmdCount, cnt)
	}

	var raw string
	var geo int
	if err := db.QueryRow(`SELECT raw_cmd, geo_id FROM command`).Scan(&raw, &geo); err != nil {
		t.Fatal(err)
	}
	if raw != "cat /etc/passwd" || geo != 1 {
		t.Fatalf("bad row: %q geo=%d", raw, geo)
	}
}

// TestSaveSession_ConcurrentSameUser guards against data loss when the same
// user has several simultaneous SSH sessions writing to one per-user DB: each
// SaveSession opens its own connection, so without a busy timeout the loser of
// a commit race gets SQLITE_BUSY ("database is locked") and its session is
// dropped. All writers must succeed (blocking briefly is fine; failing is not).
func TestSaveSession_ConcurrentSameUser(t *testing.T) {
	root := t.TempDir()
	st := New(root)
	defer st.Close()

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := core.NewSession(int64(1000 + i))
			s.EndTS = int64(1100 + i)
			for j := 0; j < 10; j++ {
				s.Add(core.CommandRecord{TS: int64(1000 + i), RawCmd: "ls", IP: "8.8.8.8"})
			}
			<-start // release all goroutines together to maximize contention
			errs[i] = st.SaveSession("alice", s)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent SaveSession %d failed: %v", i, err)
		}
	}
	got, err := st.CountSessions("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("persisted %d sessions, want %d (lost writes to lock contention)", got, n)
	}
}

func seedSessions(t *testing.T, st *Store, user string, startTS int64, cmds ...string) {
	t.Helper()
	s := core.NewSession(startTS)
	s.EndTS = startTS + 10
	for i, c := range cmds {
		s.Add(core.CommandRecord{TS: startTS + int64(i), RawCmd: c, IP: "8.8.8.8",
			Feat: core.Feature{TimeCos: 1, TimeSin: 0, SecsSinceLast: i}})
	}
	if err := st.SaveSession(user, s); err != nil {
		t.Fatal(err)
	}
}

func TestCountAndPruneAndLoad(t *testing.T) {
	root := t.TempDir()
	st := New(root)
	defer st.Close()
	seedSessions(t, st, "u", 100, "ls")
	seedSessions(t, st, "u", 200, "whoami", "id")
	seedSessions(t, st, "u", 300, "cat /etc/passwd")

	if n, err := st.CountSessions("u"); err != nil || n != 3 {
		t.Fatalf("count=%d err=%v want 3", n, err)
	}
	// keep newest 2 -> prune the oldest (start_ts 100)
	del, err := st.PruneOldest("u", 2)
	if err != nil || del != 1 {
		t.Fatalf("pruned=%d err=%v want 1", del, err)
	}
	if n, _ := st.CountSessions("u"); n != 2 {
		t.Fatalf("after prune count=%d want 2", n)
	}
	// its commands are gone too (cascade)
	sessions, err := st.LoadSessions("u")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("loaded %d sessions want 2", len(sessions))
	}
	var raws []string
	for _, s := range sessions {
		for _, c := range s.Commands {
			raws = append(raws, c.RawCmd)
		}
	}
	// "ls" (start_ts 100) pruned; whoami/id/cat remain
	for _, r := range raws {
		if r == "ls" {
			t.Fatal("pruned session's command still present")
		}
	}
	if len(raws) != 3 {
		t.Fatalf("got %d commands want 3", len(raws))
	}
}

func TestPruneOldest_KeepGreaterThanCount_NoOp(t *testing.T) {
	root := t.TempDir()
	st := New(root)
	defer st.Close()
	seedSessions(t, st, "u", 100, "ls")
	del, err := st.PruneOldest("u", 10)
	if err != nil || del != 0 {
		t.Fatalf("pruned=%d err=%v want 0", del, err)
	}
}

func TestPruneAndLoad(t *testing.T) {
	root := t.TempDir()
	st := New(root)
	defer st.Close()
	seedSessions(t, st, "u", 100, "ls")
	seedSessions(t, st, "u", 200, "whoami", "id")
	seedSessions(t, st, "u", 300, "cat /etc/passwd")

	sessions, pruned, err := st.PruneAndLoad("u", 2) // keep newest 2
	if err != nil || pruned != 1 {
		t.Fatalf("pruned=%d err=%v want 1", pruned, err)
	}
	if len(sessions) != 2 {
		t.Fatalf("loaded %d want 2", len(sessions))
	}
	for _, s := range sessions {
		for _, c := range s.Commands {
			if c.RawCmd == "ls" {
				t.Fatal("pruned session's command returned")
			}
		}
	}
	// keep >= count: no prune, load all remaining
	sessions, pruned, err = st.PruneAndLoad("u", 10)
	if err != nil || pruned != 0 || len(sessions) != 2 {
		t.Fatalf("no-op prune wrong: pruned=%d n=%d err=%v", pruned, len(sessions), err)
	}
}
