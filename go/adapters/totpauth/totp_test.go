package totpauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestProvision_WritesSecretAndScannableURI(t *testing.T) {
	root := t.TempDir()
	v := New(root, "shellsentry")
	uri, err := v.Provision("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret=") {
		t.Fatalf("uri not a scannable otpauth URL: %q", uri)
	}
	if _, err := os.Stat(filepath.Join(root, "alice", "totp.secret")); err != nil {
		t.Fatalf("secret not persisted: %v", err)
	}
}

func TestProvision_ReshowsSameSecretUntilConfirmed(t *testing.T) {
	root := t.TempDir()
	v := New(root, "shellsentry")
	u1, _ := v.Provision("bob")
	u2, _ := v.Provision("bob") // unconfirmed -> same URI re-shown
	if u1 != u2 {
		t.Fatal("secret regenerated for an unconfirmed user")
	}
	if v.IsEnrolled("bob") {
		t.Fatal("provisioning alone must not mark enrolled")
	}
}

func TestDiscard_RemovesUnconfirmed_KeepsConfirmed(t *testing.T) {
	root := t.TempDir()
	v := New(root, "shellsentry")
	sec := filepath.Join(root, "carol", "totp.secret")

	_, _ = v.Provision("carol")
	if err := v.Discard("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sec); err == nil {
		t.Fatal("declined (unconfirmed) secret must be removed")
	}

	_, _ = v.Provision("carol")
	if err := v.Confirm("carol"); err != nil {
		t.Fatal(err)
	}
	if err := v.Discard("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sec); err != nil {
		t.Fatal("confirmed secret must survive Discard")
	}
}

func TestValidate_GoodCodeEnrolls_BadCodeRejected(t *testing.T) {
	root := t.TempDir()
	v := New(root, "shellsentry")
	_, _ = v.Provision("dave")
	raw, _ := os.ReadFile(filepath.Join(root, "dave", "totp.secret"))

	code, err := totp.GenerateCode(string(raw), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := v.Validate("dave", code)
	if err != nil || !ok {
		t.Fatalf("valid code rejected: ok=%v err=%v", ok, err)
	}
	if !v.IsEnrolled("dave") {
		t.Fatal("a correct code must confirm enrollment")
	}
	if ok, _ := v.Validate("dave", "000000"); ok {
		t.Fatal("bad code accepted")
	}
}
