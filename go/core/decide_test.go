package core

import (
	"reflect"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	cmd, args := SplitCommand("  cat /etc/passwd  ")
	if cmd != "cat" || !reflect.DeepEqual(args, []string{"cat", "/etc/passwd"}) {
		t.Fatalf("got %q %v", cmd, args)
	}
	if c, _ := SplitCommand("   "); c != "" {
		t.Fatal("empty line should give empty cmd")
	}
}

func TestDecide_LowScoreIsMoreSevere(t *testing.T) {
	// hardThr < softThr because lower = more anomalous.
	soft, hard := 0.05, 0.02
	if Decide(0.10, soft, hard) != SevNone {
		t.Fatal("normal score must pass")
	}
	if Decide(0.03, soft, hard) != SevSoft {
		t.Fatal("between hard and soft must be soft")
	}
	if Decide(0.01, soft, hard) != SevHard {
		t.Fatal("below hard must be hard")
	}
	if Decide(0.02, soft, hard) != SevHard {
		t.Fatal("boundary <= hard must be hard")
	}
}
