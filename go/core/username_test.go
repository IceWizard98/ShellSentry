package core

import "testing"

func TestValidUsername_Accepts(t *testing.T) {
	for _, u := range []string{"alice", "bob_1", "user.name", "a-b", "_svc"} {
		if err := ValidUsername(u); err != nil {
			t.Errorf("ValidUsername(%q) = %v, want nil", u, err)
		}
	}
}

func TestValidUsername_RejectsTraversalAndSeparators(t *testing.T) {
	// Empty, dot components, and anything carrying a path separator must be
	// rejected before it reaches a filepath.Join / os.path.join site.
	for _, u := range []string{
		"", ".", "..",
		"../../etc", "a/b", "/abs", "a/../b",
		`dom\ain`, `..\..\x`, // backslash: not a Unix sep but rejected cross-platform
		"a\x00b", // NUL
	} {
		if err := ValidUsername(u); err == nil {
			t.Errorf("ValidUsername(%q) = nil, want error", u)
		}
	}
}
