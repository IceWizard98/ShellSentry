package scorerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"shellsentry/core"
)

// fakeDaemon echoes a fixed score; optionally sleeps to force a timeout.
func fakeDaemon(t *testing.T, score float64, delay time.Duration) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n') // read request
		time.Sleep(delay)
		_ = json.NewEncoder(conn).Encode(map[string]float64{"score": score})
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestScore_ReturnsDaemonScore(t *testing.T) {
	addr := fakeDaemon(t, 0.42, 0)
	c := New(addr)
	got, err := c.Score(context.Background(), "alice", "s1", core.Feature{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0.42 {
		t.Fatalf("got %v want 0.42", got)
	}
}

func TestScore_TimeoutReturnsError(t *testing.T) {
	addr := fakeDaemon(t, 0.42, 200*time.Millisecond)
	c := New(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Score(ctx, "alice", "s1", core.Feature{}, 0); err == nil {
		t.Fatal("expected timeout error")
	}
}
