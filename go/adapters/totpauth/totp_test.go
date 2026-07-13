package totpauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestEnsureProvisioned_CreatesSecret_ThenValidates(t *testing.T) {
	root := t.TempDir()
	a := New(root, "shellsentry")

	if err := a.EnsureProvisioned("alice"); err != nil {
		t.Fatal(err)
	}
	secPath := filepath.Join(root, "alice", "totp.secret")
	if _, err := os.Stat(secPath); err != nil {
		t.Fatalf("secret not written: %v", err)
	}
	raw, _ := os.ReadFile(secPath)

	code, err := totp.GenerateCode(string(raw), timeNow())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := a.Validate("alice", code)
	if err != nil || !ok {
		t.Fatalf("valid code rejected: ok=%v err=%v", ok, err)
	}
	if ok, _ := a.Validate("alice", "000000"); ok {
		t.Fatal("bad code accepted")
	}
}

func TestEnsureProvisioned_Idempotent(t *testing.T) {
	root := t.TempDir()
	a := New(root, "shellsentry")
	_ = a.EnsureProvisioned("bob")
	raw1, _ := os.ReadFile(filepath.Join(root, "bob", "totp.secret"))
	_ = a.EnsureProvisioned("bob") // must not overwrite
	raw2, _ := os.ReadFile(filepath.Join(root, "bob", "totp.secret"))
	if string(raw1) != string(raw2) {
		t.Fatal("secret was regenerated")
	}
}

func timeNow() time.Time { return time.Now() }
