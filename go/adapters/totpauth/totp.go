package totpauth

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp/totp"
)

type TOTP struct {
	root   string
	issuer string
	in     io.Reader
	out    io.Writer
}

func New(root, issuer string, in io.Reader, out io.Writer) *TOTP {
	return &TOTP{root: root, issuer: issuer, in: in, out: out}
}

func (a *TOTP) secretPath(user string) string {
	return filepath.Join(a.root, user, "totp.secret")
}

// EnsureProvisioned shows the enrollment QR on first login and persists the
// secret ONLY after the user explicitly confirms they saved it. Without that
// confirmation nothing is written, so the QR is shown again on the next login
// instead of the secret being silently persisted and never re-shown (which
// would lock a user who dismissed it out of enrolling and out of every future
// OTP challenge).
func (a *TOTP) EnsureProvisioned(user string) error {
	p := a.secretPath(user)
	if _, err := os.Stat(p); err == nil {
		return nil // already enrolled
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.issuer, AccountName: user})
	if err != nil {
		return fmt.Errorf("generate totp: %w", err)
	}
	fmt.Fprintln(a.out, "First login — scan this QR in your Authenticator app:")
	// Half-block glyphs (not Generate's ANSI-colored full blocks): no color
	// dependency, half the width/height so it fits an 80-col terminal without
	// wrapping, and no sixel terminal-probe side effect on stdout.
	qrterminal.GenerateHalfBlock(key.URL(), qrterminal.L, a.out)
	fmt.Fprintf(a.out, "Or enter this secret manually: %s\n", key.Secret())
	fmt.Fprint(a.out, "Have you saved it in your authenticator? Confirm enrollment [y/N]: ")

	if !confirmed(readLine(a.in)) {
		fmt.Fprintln(a.out, "Enrollment NOT confirmed — secret not saved; you will be prompted again next login.")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("mkdir user dir: %w", err)
	}
	if err := os.WriteFile(p, []byte(key.Secret()), 0o600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	fmt.Fprintln(a.out, "Enrollment confirmed.")
	return nil
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

func (a *TOTP) Validate(user, code string) (bool, error) {
	raw, err := os.ReadFile(a.secretPath(user))
	if err != nil {
		return false, fmt.Errorf("read secret: %w", err)
	}
	return totp.Validate(code, string(raw)), nil
}
