package totpauth

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// The enrollment QR must render as a clean, scannable block grid on a plain
// 80-col terminal: no ANSI color escapes (color-poor terminals collapse
// those to blank) and no line wider than 80 runes (wrapping scrambles it).
func TestEnsureProvisioned_QRIsScannable(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	a := New(root, "shellsentry", strings.NewReader("y\n"), &out)
	if err := a.EnsureProvisioned("dave"); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if len(s) == 0 {
		t.Fatal("no QR output written")
	}
	if strings.Contains(s, "\033[") {
		t.Fatal("QR output contains ANSI escapes; use half-block renderer")
	}
	// Only the QR grid itself must fit 80 cols; informational text lines (the
	// fallback URL) may be longer. QR lines are pure half-block glyphs + space.
	sawQR := false
	for _, line := range strings.Split(s, "\n") {
		if strings.Trim(line, "█▀▄ ") != "" {
			continue // not a QR row
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		sawQR = true
		if n := len([]rune(line)); n > 80 {
			t.Fatalf("QR line wider than 80 cols (%d), will wrap and become unscannable", n)
		}
	}
	if !sawQR {
		t.Fatal("no QR block rows found in output")
	}
}

func TestEnsureProvisioned_ConfirmedThenValidates(t *testing.T) {
	root := t.TempDir()
	a := New(root, "shellsentry", strings.NewReader("y\n"), io.Discard)

	if err := a.EnsureProvisioned("alice"); err != nil {
		t.Fatal(err)
	}
	secPath := filepath.Join(root, "alice", "totp.secret")
	if _, err := os.Stat(secPath); err != nil {
		t.Fatalf("secret not written after confirmation: %v", err)
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

func TestEnsureProvisioned_NotConfirmed_NotSaved(t *testing.T) {
	root := t.TempDir()
	secPath := filepath.Join(root, "carol", "totp.secret")

	// declined with "n" -> nothing persisted, QR would be re-shown next login
	a := New(root, "shellsentry", strings.NewReader("n\n"), io.Discard)
	if err := a.EnsureProvisioned("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secPath); err == nil {
		t.Fatal("secret must NOT be saved without explicit confirmation")
	}

	// empty answer (dismissed) -> also not persisted
	a = New(root, "shellsentry", strings.NewReader("\n"), io.Discard)
	_ = a.EnsureProvisioned("carol")
	if _, err := os.Stat(secPath); err == nil {
		t.Fatal("blank answer must NOT save the secret")
	}

	// finally confirm -> now saved
	a = New(root, "shellsentry", strings.NewReader("yes\n"), io.Discard)
	if err := a.EnsureProvisioned("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secPath); err != nil {
		t.Fatalf("secret must be saved once confirmed: %v", err)
	}
}

func TestEnsureProvisioned_Idempotent(t *testing.T) {
	root := t.TempDir()
	a := New(root, "shellsentry", strings.NewReader("y\n"), io.Discard)
	_ = a.EnsureProvisioned("bob")
	raw1, _ := os.ReadFile(filepath.Join(root, "bob", "totp.secret"))
	// already enrolled -> returns immediately, no prompt read
	a2 := New(root, "shellsentry", strings.NewReader(""), io.Discard)
	_ = a2.EnsureProvisioned("bob")
	raw2, _ := os.ReadFile(filepath.Join(root, "bob", "totp.secret"))
	if string(raw1) != string(raw2) {
		t.Fatal("secret was regenerated")
	}
}

func timeNow() time.Time { return time.Now() }
