package core

type CommandRecord struct {
	TS     int64
	Feat   Feature
	RawCmd string
	IP     string
}

type Session struct {
	StartTS  int64
	EndTS    int64
	Commands []CommandRecord
	Valid    bool
}

func NewSession(startTS int64) *Session {
	return &Session{StartTS: startTS, Valid: true}
}

func (s *Session) Add(rec CommandRecord) { s.Commands = append(s.Commands, rec) }
