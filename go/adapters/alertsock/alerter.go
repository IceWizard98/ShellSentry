package alertsock

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"shellsentry/ports"
)

type Alerter struct{ path string }

func New(path string) *Alerter { return &Alerter{path: path} }

func (a *Alerter) Alert(alert ports.Alert) error {
	conn, err := net.DialTimeout("unix", a.path, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("dial alert socket: %w", err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(alert); err != nil {
		return fmt.Errorf("write alert: %w", err)
	}
	return nil
}
