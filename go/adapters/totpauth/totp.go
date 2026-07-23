// Package totpauth is the server-side TOTP vault used INSIDE the privileged
// otpd process. It owns the secrets under a root-only directory and never hands
// a secret back to a caller — it only generates a provisioning URI and answers
// yes/no to a code. The interactive enrollment (QR display, confirmation) lives
// in the session-side client (adapters/otpsockclient), which reaches this vault
// over otpd's unix socket. Keeping the secret out of the scored user's uid is
// the whole point: a stolen SSH key must not also yield the second factor.
package totpauth

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pquerna/otp/totp"
)

type Vault struct {
	root   string
	issuer string
}

func New(root, issuer string) *Vault { return &Vault{root: root, issuer: issuer} }

func (v *Vault) secretPath(user string) string {
	return filepath.Join(v.root, user, "totp.secret")
}

// enrolledPath marks a confirmed enrollment. Its presence is what stops the QR
// being re-shown on every login; a provisioned-but-unconfirmed secret has none.
func (v *Vault) enrolledPath(user string) string {
	return filepath.Join(v.root, user, "totp.enrolled")
}

func (v *Vault) IsEnrolled(user string) bool {
	_, err := os.Stat(v.enrolledPath(user))
	return err == nil
}

// Provision returns a scannable otpauth:// URI for the user, generating and
// persisting a fresh secret on first call. It is idempotent for an unconfirmed
// secret (same URI re-shown), so a dismissed QR can be redisplayed next login.
func (v *Vault) Provision(user string) (string, error) {
	p := v.secretPath(user)
	if raw, err := os.ReadFile(p); err == nil {
		return provisioningURI(v.issuer, user, string(raw)), nil // re-show existing
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: v.issuer, AccountName: user})
	if err != nil {
		return "", fmt.Errorf("generate totp: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("mkdir user dir: %w", err)
	}
	if err := os.WriteFile(p, []byte(key.Secret()), 0o600); err != nil {
		return "", fmt.Errorf("write secret: %w", err)
	}
	return provisioningURI(v.issuer, user, key.Secret()), nil
}

// Confirm records that the user saved the secret in their authenticator, so the
// QR is not shown again.
func (v *Vault) Confirm(user string) error {
	if err := os.MkdirAll(filepath.Dir(v.enrolledPath(user)), 0o700); err != nil {
		return fmt.Errorf("mkdir user dir: %w", err)
	}
	if err := os.WriteFile(v.enrolledPath(user), []byte("1"), 0o600); err != nil {
		return fmt.Errorf("mark enrolled: %w", err)
	}
	return nil
}

// Discard drops an UNCONFIRMED secret (the user declined enrollment), so a fresh
// one is generated and re-shown next login. A confirmed secret is left intact.
func (v *Vault) Discard(user string) error {
	if v.IsEnrolled(user) {
		return nil
	}
	if err := os.Remove(v.secretPath(user)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("discard secret: %w", err)
	}
	return nil
}

// Validate checks a code against the stored secret. A correct code implies the
// user has the authenticator, so it also confirms enrollment.
func (v *Vault) Validate(user, code string) (bool, error) {
	raw, err := os.ReadFile(v.secretPath(user))
	if err != nil {
		return false, fmt.Errorf("read secret: %w", err)
	}
	if !totp.Validate(code, string(raw)) {
		return false, nil
	}
	if !v.IsEnrolled(user) {
		if err := v.Confirm(user); err != nil {
			return false, err
		}
	}
	return true, nil
}

// provisioningURI builds the standard otpauth:// URL authenticator apps expect,
// rebuilt from the stored base32 secret (we persist only the secret, not the URL).
func provisioningURI(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}
