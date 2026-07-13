package alertsock

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"shellsentry/ports"
)

func TestAlert_WritesNDJSON(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan ports.Alert, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		var a ports.Alert
		_ = json.Unmarshal([]byte(line), &a)
		got <- a
	}()

	al := New(sock)
	if err := al.Alert(ports.Alert{User: "alice", Severity: "hard-otp", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	a := <-got
	if a.User != "alice" || a.Severity != "hard-otp" {
		t.Fatalf("bad alert: %+v", a)
	}
}

func TestAlert_DownListener_ReturnsError(t *testing.T) {
	al := New(filepath.Join(t.TempDir(), "missing.sock"))
	if err := al.Alert(ports.Alert{User: "x"}); err == nil {
		t.Fatal("expected error when socket absent")
	}
}
