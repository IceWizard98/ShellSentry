package scorerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"shellsentry/core"
)

// maxResponseBytes caps a single scorer reply so a misbehaving or hostile
// daemon on the socket cannot make us buffer an unbounded line.
const maxResponseBytes = 1 << 20 // 1 MiB

type Client struct{ addr string }

func New(addr string) *Client { return &Client{addr: addr} }

type request struct {
	User      string       `json:"user"`
	SessionID string       `json:"session_id"`
	Features  core.Feature `json:"features"`
	Gen       int64        `json:"gen"`
}
type response struct {
	Score float64 `json:"score"`
}

func (c *Client) Score(ctx context.Context, user, sessionID string, f core.Feature, gen int64) (float64, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return 0, fmt.Errorf("dial scorer: %w", err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := request{User: user, SessionID: sessionID, Features: f, Gen: gen}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return 0, fmt.Errorf("send request: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxResponseBytes)).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}
	var resp response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return resp.Score, nil
}
