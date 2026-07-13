package core

import "testing"

func TestRules_Check(t *testing.T) {
	r := Rules{MinSecondsBetween: 2}
	r.Commands.Deny = []string{"rm -rf /"}
	r.Commands.Allow = []string{"ls"}
	r.Countries.Deny = []string{"KP"}
	r.Countries.Allow = []string{"IT"}

	if r.Check("rm -rf /", "IT", 100) != RuleChallengeHard {
		t.Fatal("deny command must hard-challenge")
	}
	if r.Check("cat x", "KP", 100) != RuleChallengeHard {
		t.Fatal("deny country must hard-challenge")
	}
	if r.Check("ls", "US", 100) != RuleAllow {
		t.Fatal("allow command must bypass")
	}
	if r.Check("cat x", "IT", 100) != RuleAllow {
		t.Fatal("allow country must bypass")
	}
	if r.Check("cat x", "US", 1) != RuleChallengeSoft {
		t.Fatal("too-fast must soft-challenge")
	}
	if r.Check("cat x", "US", 100) != RuleNone {
		t.Fatal("normal must be none")
	}
}

func TestRules_Check_TokenPrefix(t *testing.T) {
	// bare-command deny catches any args
	var r Rules
	r.Commands.Deny = []string{"mkfs"}
	if r.Check("mkfs /dev/sda", "US", 100) != RuleChallengeHard {
		t.Fatal("deny [mkfs] must match 'mkfs /dev/sda'")
	}

	// no false positive on a longer first token
	r = Rules{}
	r.Commands.Deny = []string{"rm"}
	if r.Check("rmdir /x", "US", 100) != RuleNone {
		t.Fatal("deny [rm] must NOT match 'rmdir /x'")
	}
	if r.Check("rm -rf /", "US", 100) != RuleChallengeHard {
		t.Fatal("deny [rm] must match 'rm -rf /'")
	}

	// multi-token entry: all tokens must be a prefix
	r = Rules{}
	r.Commands.Deny = []string{"rm -rf"}
	if r.Check("rm -rf /tmp", "US", 100) != RuleChallengeHard {
		t.Fatal("deny [rm -rf] must match 'rm -rf /tmp'")
	}
	if r.Check("rm file", "US", 100) != RuleNone {
		t.Fatal("deny [rm -rf] must NOT match 'rm file'")
	}

	// precedence: deny (specific) beats allow (broad)
	r = Rules{}
	r.Commands.Allow = []string{"rm"}
	r.Commands.Deny = []string{"rm -rf /"}
	if r.Check("rm file", "US", 100) != RuleAllow {
		t.Fatal("allow [rm] must allow 'rm file'")
	}
	if r.Check("rm -rf /", "US", 100) != RuleChallengeHard {
		t.Fatal("deny [rm -rf /] must hard-challenge 'rm -rf /'")
	}
}

func TestRules_Check_CompoundSegments(t *testing.T) {
	var r Rules
	r.Commands.Deny = []string{"mkfs"}

	// a denied command chained after an operator must NOT slip past the filter
	for _, line := range []string{
		"echo hi && mkfs /dev/null",
		"echo hi || mkfs /dev/null",
		"echo hi ; mkfs /dev/null",
		"cat x | mkfs",
		"true & mkfs /dev/null",
	} {
		if got := r.Check(line, "US", 100); got != RuleChallengeHard {
			t.Fatalf("deny [mkfs] must hard-challenge %q, got %v", line, got)
		}
	}
	// a safe compound with no denied segment is not blocked by the deny rule
	if r.Check("echo hi && ls", "US", 100) != RuleNone {
		t.Fatal("compound without a denied segment must be RuleNone")
	}

	// allow-bypass requires EVERY segment to be allowed
	r = Rules{}
	r.Commands.Allow = []string{"ls", "echo"}
	if r.Check("ls && echo x", "US", 100) != RuleAllow {
		t.Fatal("all-allowed compound must bypass")
	}
	if r.Check("ls && rm x", "US", 100) != RuleNone {
		t.Fatal("partly-unknown compound must NOT bypass (falls through to scoring)")
	}

	// deny still wins over allow inside a compound
	r = Rules{}
	r.Commands.Allow = []string{"echo"}
	r.Commands.Deny = []string{"mkfs"}
	if r.Check("echo hi && mkfs /dev/sda", "US", 100) != RuleChallengeHard {
		t.Fatal("denied segment must hard-challenge even alongside an allowed one")
	}

	// an allow-listed command must NOT bypass when it hides an expansion
	r = Rules{}
	r.Commands.Allow = []string{"ls"}
	if r.Check("ls $(rm -rf /)", "US", 100) == RuleAllow {
		t.Fatal("allow bypass must be suppressed for a segment containing $(...)")
	}
	if r.Check("ls `rm -rf /`", "US", 100) == RuleAllow {
		t.Fatal("allow bypass must be suppressed for a segment containing backticks")
	}
	if r.Check("ls -la", "US", 100) != RuleAllow {
		t.Fatal("plain allow-listed command must still bypass")
	}
}
