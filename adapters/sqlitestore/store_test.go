package sqlitestore

import (
	"database/sql"
	"path/filepath"
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
