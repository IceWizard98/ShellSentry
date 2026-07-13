package totpauth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp/totp"
)

type TOTP struct {
	root   string
	issuer string
}

func New(root, issuer string) *TOTP { return &TOTP{root: root, issuer: issuer} }

func (a *TOTP) secretPath(user string) string {
	return filepath.Join(a.root, user, "totp.secret")
}

// EnsureProvisioned generates a secret + prints an enrollment QR on first login.
func (a *TOTP) EnsureProvisioned(user string) error {
	p := a.secretPath(user)
	if _, err := os.Stat(p); err == nil {
		return nil // already provisioned
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: a.issuer, AccountName: user})
	if err != nil {
		return fmt.Errorf("generate totp: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("mkdir user dir: %w", err)
	}
	if err := os.WriteFile(p, []byte(key.Secret()), 0o600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	fmt.Println("First login — scan this QR in your Authenticator app:")
	qrterminal.Generate(key.URL(), qrterminal.L, os.Stdout)
	fmt.Printf("Or enter this secret manually: %s\n", key.Secret())
	return nil
}

func (a *TOTP) Validate(user, code string) (bool, error) {
	raw, err := os.ReadFile(a.secretPath(user))
	if err != nil {
		return false, fmt.Errorf("read secret: %w", err)
	}
	return totp.Validate(code, string(raw)), nil
}
