package core

import "testing"

func TestDetectPath_FirstPathLike(t *testing.T) {
	cases := []struct {
		args     []string
		wantPath string
		wantHas  bool
	}{
		{[]string{"cat", "/etc/passwd"}, "/etc/passwd", true},
		{[]string{"ls", "-la", "./sub"}, "./sub", true},
		{[]string{"vi", "~/x"}, "~/x", true},
		{[]string{"cp", "a/b", "c/d"}, "a/b", true},   // first match wins
		{[]string{"cd", "../up"}, "../up", true},
		{[]string{"whoami"}, "", false},               // no path
		{[]string{"echo", "hello"}, "", false},        // no slash, not path-like
	}
	for _, c := range cases {
		p, has := DetectPath(c.args)
		if p != c.wantPath || has != c.wantHas {
			t.Errorf("DetectPath(%v)=%q,%v want %q,%v", c.args, p, has, c.wantPath, c.wantHas)
		}
	}
}
