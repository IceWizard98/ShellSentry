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

// open opens (creating if needed) the per-user DB and ensures the schema exists.
func (st *Store) open(user string) (*sql.DB, error) {
	dir := filepath.Join(st.root, user)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir user dir: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "sessions.db"))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return db, nil
}

func (st *Store) SaveSession(user string, s *core.Session) error {
	db, err := st.open(user)
	if err != nil {
		return err
	}
	defer db.Close()

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

func (st *Store) CountSessions(user string) (int, error) {
	db, err := st.open(user)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM session`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return n, nil
}

// querier is satisfied by both *sql.DB and *sql.Tx, so the prune/load SQL can
// run either standalone or inside a shared transaction.
type querier interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// pruneOldestTx deletes the (count-keep) oldest sessions and their commands,
// returning how many sessions were deleted. keep<=0 prunes nothing.
func pruneOldestTx(q querier, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	var total int
	if err := q.QueryRow(`SELECT COUNT(*) FROM session`).Scan(&total); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	toDelete := total - keep
	if toDelete <= 0 {
		return 0, nil
	}
	const oldest = `SELECT id FROM session ORDER BY start_ts ASC, id ASC LIMIT ?`
	if _, err := q.Exec(`DELETE FROM command WHERE session_fk IN (`+oldest+`)`, toDelete); err != nil {
		return 0, fmt.Errorf("delete commands: %w", err)
	}
	if _, err := q.Exec(`DELETE FROM session WHERE id IN (`+oldest+`)`, toDelete); err != nil {
		return 0, fmt.Errorf("delete sessions: %w", err)
	}
	return toDelete, nil
}

// loadSessionsTx loads every session with its commands, oldest first.
func loadSessionsTx(q querier) ([]core.Session, error) {
	rows, err := q.Query(`SELECT id, start_ts, end_ts FROM session ORDER BY start_ts ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	type sess struct {
		id      int64
		session core.Session
	}
	var list []sess
	for rows.Next() {
		var s sess
		if err := rows.Scan(&s.id, &s.session.StartTS, &s.session.EndTS); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		s.session.Valid = true
		list = append(list, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	out := make([]core.Session, 0, len(list))
	for _, s := range list {
		crows, err := q.Query(`SELECT ts, time_cos, time_sin, geo_id, cmd_index,
			path_index, secs_since_last, raw_cmd, ip FROM command WHERE session_fk=? ORDER BY id ASC`, s.id)
		if err != nil {
			return nil, fmt.Errorf("query commands: %w", err)
		}
		for crows.Next() {
			var c core.CommandRecord
			if err := crows.Scan(&c.TS, &c.Feat.TimeCos, &c.Feat.TimeSin, &c.Feat.GeoID,
				&c.Feat.CmdIndex, &c.Feat.PathIndex, &c.Feat.SecsSinceLast, &c.RawCmd, &c.IP); err != nil {
				crows.Close()
				return nil, fmt.Errorf("scan command: %w", err)
			}
			s.session.Commands = append(s.session.Commands, c)
		}
		crows.Close()
		if err := crows.Err(); err != nil {
			return nil, fmt.Errorf("iterate commands: %w", err)
		}
		out = append(out, s.session)
	}
	return out, nil
}

// PruneOldest deletes the (count-keep) oldest sessions and their commands.
func (st *Store) PruneOldest(user string, keep int) (int, error) {
	db, err := st.open(user)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()
	n, err := pruneOldestTx(tx, keep)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return n, nil
}

func (st *Store) LoadSessions(user string) ([]core.Session, error) {
	db, err := st.open(user)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return loadSessionsTx(db)
}

// PruneAndLoad runs retention (prune oldest beyond keep) and loads the
// remaining sessions in a SINGLE transaction on one connection, so the training
// snapshot is atomic and consistent. keep<=0 prunes nothing.
func (st *Store) PruneAndLoad(user string, keep int) ([]core.Session, int, error) {
	db, err := st.open(user)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return nil, 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	pruned, err := pruneOldestTx(tx, keep)
	if err != nil {
		return nil, 0, err
	}
	sessions, err := loadSessionsTx(tx)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit: %w", err)
	}
	return sessions, pruned, nil
}

func (st *Store) Close() error { return nil }
