package core

import "testing"

func TestLineComplete(t *testing.T) {
	complete := []string{
		"echo hi",
		"ls -la /tmp",
		`echo "double quoted"`,
		"echo 'single quoted'",
		`echo \\`,             // escaped backslash = literal, complete
		"echo hi && mkfs /x",  // operators are fine
		`grep "a) b" file`,    // paren inside quotes doesn't count
		"(cd /tmp && ls)",     // balanced subshell
		`echo 'a "b" c'`,      // double quote inside single is literal
	}
	for _, l := range complete {
		if ok, why := LineComplete(l); !ok {
			t.Errorf("LineComplete(%q) = false (%s), want true", l, why)
		}
	}

	incomplete := []string{
		"echo 'oops",   // unterminated single quote
		`echo "oops`,   // unterminated double quote
		`echo hi \`,    // trailing backslash
		"(cd /tmp",     // unbalanced paren
		"echo $(",      // open command substitution
	}
	for _, l := range incomplete {
		if ok, _ := LineComplete(l); ok {
			t.Errorf("LineComplete(%q) = true, want false", l)
		}
	}
}
