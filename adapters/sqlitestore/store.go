package sqlitestore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
	"shellsentry/core"
)

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

const schema = `
CREATE TABLE IF NOT EXISTS session (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  start_ts INTEGER NOT NULL,
  end_ts INTEGER NOT NULL,
  command_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS command (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_fk INTEGER NOT NULL REFERENCES session(id),
  ts INTEGER NOT NULL,
  time_cos REAL, time_sin REAL,
  geo_id INTEGER, cmd_index INTEGER, path_index INTEGER, secs_since_last INTEGER,
  raw_cmd TEXT, ip TEXT
);`

func (st *Store) SaveSession(user string, s *core.Session) error {
	dir := filepath.Join(st.root, user)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir user dir: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "sessions.db"))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT INTO session(start_ts,end_ts,command_count) VALUES(?,?,?)`,
		s.StartTS, s.EndTS, len(s.Commands))
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	sid, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("session id: %w", err)
	}
	for _, c := range s.Commands {
		if _, err := tx.Exec(`INSERT INTO command
			(session_fk,ts,time_cos,time_sin,geo_id,cmd_index,path_index,secs_since_last,raw_cmd,ip)
			VALUES(?,?,?,?,?,?,?,?,?,?)`,
			sid, c.TS, c.Feat.TimeCos, c.Feat.TimeSin, c.Feat.GeoID, c.Feat.CmdIndex,
			c.Feat.PathIndex, c.Feat.SecsSinceLast, c.RawCmd, c.IP); err != nil {
			return fmt.Errorf("insert command: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (st *Store) Close() error { return nil }
