package core

import (
	"fmt"
	"strings"
)

// ValidUsername rejects any user string that could escape its per-user directory
// once joined into a filesystem path (<root>/<user>/...). It is a security guard,
// not a policy on legal account names: empty, "." and ".." are rejected, as is any
// path separator ('/' or '\\') or NUL. Backslash is not a Unix separator but is
// refused for cross-platform safety — no legitimate Unix username contains one.
func ValidUsername(user string) error {
	switch user {
	case "", ".", "..":
		return fmt.Errorf("invalid username %q", user)
	}
	if strings.ContainsAny(user, "/\\\x00") {
		return fmt.Errorf("invalid username %q: contains path separator or NUL", user)
	}
	return nil
}
