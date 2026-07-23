// Package otpsockclient is the session-side client for the privileged otpd. It
// implements ports.OTPVerifier by talking NDJSON over otpd's unix socket, so the
// TOTP secret stays owned by otpd (root) and is never readable by the scored
// user. Interactive enrollment (QR + confirmation) happens here, on the user's
// terminal; the secret itself lives on the far side of the socket.
package otpsockclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
)

// Request/Response are the otpd wire protocol, shared with the server (cmd/ssentry).
type Request struct {
	Op   string `json:"op"` // status | provision | confirm | discard | validate
	User string `json:"user"`
	Code string `json:"code,omitempty"`
}

type Response struct {
	Enrolled bool   `json:"enrolled,omitempty"`
	URI      string `json:"uri,omitempty"`
	OK       bool   `json:"ok,omitempty"`
	Error    string `json:"error,omitempty"`
}

type Client struct {
	socket string
	in     io.Reader
	out    io.Writer
}

func New(socket string, in io.Reader, out io.Writer) *Client {
	return &Client{socket: socket, in: in, out: out}
}

// EnsureProvisioned shows the enrollment QR on first login and confirms only
// after the user says they saved it (mirrors the old file-based flow, now over
// the socket). Declining discards the pending secret so the QR re-shows.
func (c *Client) EnsureProvisioned(user string) error {
	st, err := c.call(Request{Op: "status", User: user})
	if err != nil {
		return err
	}
	if st.Enrolled {
		return nil
	}
	pr, err := c.call(Request{Op: "provision", User: user})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, "First login. Scan this QR in your Authenticator app:")
	qrterminal.GenerateHalfBlock(pr.URI, qrterminal.L, c.out)
	fmt.Fprintf(c.out, "Or add this URL manually: %s\n", pr.URI)
	fmt.Fprint(c.out, "Have you saved it in your authenticator? Confirm enrollment [y/N]: ")

	if confirmed(readLine(c.in)) {
		if _, err := c.call(Request{Op: "confirm", User: user}); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "Enrollment confirmed.")
		return nil
	}
	if _, err := c.call(Request{Op: "discard", User: user}); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "Enrollment NOT confirmed. You will be prompted again next login.")
	return nil
}

func (c *Client) Validate(user, code string) (bool, error) {
	resp, err := c.call(Request{Op: "validate", User: user, Code: code})
	if err != nil {
		return false, err
	}
	if resp.Error != "" {
		return false, fmt.Errorf("otpd: %s", resp.Error)
	}
	return resp.OK, nil
}

// call opens a fresh connection per request (like the alert/scorer clients),
// sends one NDJSON request, and reads one NDJSON response.
func (c *Client) call(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.socket, 2*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("dial otpd: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // enrollment waits on the user
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send otp request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("read otp response: %w", err)
	}
	if resp.Error != "" && req.Op != "validate" {
		return resp, fmt.Errorf("otpd: %s", resp.Error)
	}
	return resp, nil
}

func confirmed(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// readLine reads one line byte-by-byte (no read-ahead) so it never consumes
// bytes the REPL will later read from the same stdin.
func readLine(r io.Reader) string {
	var b [1]byte
	var line []byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			break
		}
	}
	return string(line)
}
