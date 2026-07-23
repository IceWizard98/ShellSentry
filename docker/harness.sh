#!/usr/bin/env bash
# Integration harness: verifies (1) ssentry intercepts every command through the
# wrapper and persists clean sessions, (2) base admin rules (token-prefix deny)
# fire an OTP challenge, valid OTP keeps + saves the session, bad OTP discards it,
# (3) the interactive PTY path executes on a real Linux tty without hanging.
set -u
FAILS=0
pass(){ echo "PASS: $1"; }
fail(){ echo "FAIL: $1"; FAILS=$((FAILS+1)); }

USER_NAME=$(whoami)
DB="/work/data/${USER_NAME}/sessions.db"
CFG=/work/config.yaml
export SSH_CONNECTION="8.8.8.8 22 127.0.0.1 22"

cat > "$CFG" <<EOF
root_path: "/work/data"
geoip_db_path: "/work/missing.mmdb"
daemon_addr: "127.0.0.1:19099"
score_timeout_ms: 500
alert_socket: "/work/alerts.sock"
otp_retries: 2
rules_path: "/work/rules.json"
model_ttl_sec: 900
otp_socket: "/work/otpd.sock"
otp_root: "/work/otp-secrets"
EOF
# Base rule: deny the "id" command (bare token) — must catch "id -un" too (F1 token-prefix).
echo '{"commands":{"deny":["id"],"allow":[]},"min_seconds_between":0,"countries":{"deny":[],"allow":[]}}' > /work/rules.json

count(){ python3 -c "import sqlite3;
try: print(sqlite3.connect('$DB').execute('select count(*) from $1').fetchone()[0])
except Exception: print(0)"; }

python3 /harness/mock_scorer.py & sleep 1

# Privileged OTP daemon owns the secret store; the session validates over its
# socket. In this single-user harness otpd runs as the same user.
ssentry otpd --config "$CFG" >/tmp/otpd.log 2>&1 & sleep 1

echo "=== provision TOTP (first login, confirm enrollment) ==="
# 'y' confirms enrollment so the secret is persisted (and the QR not re-shown);
# the trailing 'exit' ends the empty session.
PROV=$(printf 'y\nexit\n' | timeout 15 ssentry run --config "$CFG" 2>&1)
SECRET=$(cat /work/otp-secrets/"$USER_NAME"/totp.secret 2>/dev/null)
if [ -n "$SECRET" ]; then pass "first-login QR shown + enrollment confirmed"; else fail "no TOTP secret after enrollment"; echo "$PROV" | head; fi

echo "=== Test A: command interception + persistence ==="
OUTA=$(printf 'whoami\ncd /tmp\npwd\nexit\n' | timeout 15 ssentry run --config "$CFG" 2>&1)
echo "$OUTA" | grep -q "$USER_NAME" && echo "$OUTA" | grep -q "/tmp" \
  && pass "A: whoami + cd/pwd executed through wrapper" || { fail "A: commands not executed/echoed"; echo "$OUTA" | tail; }
# Empty sessions (like the provisioning run) are not saved, so this is the first.
[ "$(count session)" = "1" ] && [ "$(count command)" = "3" ] \
  && pass "A: clean session persisted with 3 command records" \
  || fail "A: expected 1 session / 3 commands, got $(count session)/$(count command)"

echo "=== Test B: deny rule (token-prefix) + valid OTP -> runs + saved ==="
CODE=$(python3 /harness/totp.py "$SECRET")
OUTB=$(printf 'id -un\n%s\nexit\n' "$CODE" | timeout 15 ssentry run --config "$CFG" 2>&1)
echo "$OUTB" | grep -q "OTP:" && pass "B: denied 'id -un' triggered OTP challenge (token-prefix match)" \
  || { fail "B: no OTP prompt for denied arg-bearing command"; echo "$OUTB" | tail; }
if [ "$(count session)" = "2" ]; then pass "B: valid OTP kept session -> saved (2 sessions)"; else fail "B: session not saved after valid OTP (sessions=$(count session))"; fi

echo "=== Test C: deny rule + bad OTP -> session discarded ==="
BEFORE=$(count session)
OUTC=$(printf 'id -un\n000000\n000000\nexit\n' | timeout 15 ssentry run --config "$CFG" 2>&1)
echo "$OUTC" | grep -q "OTP:" && pass "C: denied command triggered OTP challenge" || fail "C: no OTP prompt"
AFTER=$(count session)
[ "$BEFORE" = "$AFTER" ] && pass "C: bad OTP discarded session (not saved, still $AFTER)" \
  || fail "C: session saved despite bad OTP ($BEFORE -> $AFTER)"

echo "=== Test D: interactive PTY path on a real tty (no hang) ==="
OUTD=$(python3 - <<'PY'
import pty, os, select, time
pid, fd = pty.fork()
if pid == 0:
    os.environ["SSH_CONNECTION"] = "8.8.8.8 22 127.0.0.1 22"
    os.execvp("ssentry", ["ssentry", "run", "--config", "/work/config.yaml"])
buf = b""
def drain(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: buf += os.read(fd, 4096)
            except OSError: return
drain(1.0)
for c in (b"printf DTEST_OK\n", b"exit\n"):
    os.write(fd, c); drain(1.0)
drain(1.0)
try: os.close(fd)
except OSError: pass
os.waitpid(pid, 0)
import sys; sys.stdout.write(buf.decode(errors="replace"))
PY
)
echo "$OUTD" | grep -q "DTEST_OK" \
  && pass "D: interactive tty command executed via PTY proxy (no hang)" \
  || { fail "D: interactive PTY path failed/hung"; echo "$OUTD" | tail; }

echo "=== Test E: compound commands (&&, ||) execute with correct short-circuit ==="
OE=$(printf 'true && echo AND_OK\nfalse || echo OR_OK\nfalse && echo NOPE\ntrue || echo NOPE2\nexit\n' | timeout 15 ssentry run --config "$CFG" 2>/dev/null)
echo "$OE" | grep -q "AND_OK" && echo "$OE" | grep -q "OR_OK" \
  && ! echo "$OE" | grep -q "NOPE" \
  && pass "E: && / || run through the wrapper with correct short-circuit" \
  || { fail "E: compound execution/short-circuit wrong"; echo "$OE" | tail; }

echo "=== Test F: deny rule catches a dangerous command chained after an operator ==="
# rules.json denies "id"; hide it after && / ; / | -> must still challenge (segment split)
for chain in 'echo hi && id -un' 'echo hi ; id -un' 'echo hi | id'; do
  OF=$(printf '%s\n000000\n000000\nexit\n' "$chain" | timeout 15 ssentry run --config "$CFG" 2>/dev/null)
  echo "$OF" | grep -q "OTP:" && pass "F: '$chain' -> challenged (no operator bypass)" \
    || { fail "F: '$chain' bypassed the deny rule"; }
done

echo "=== Test G: incomplete shell line is rejected, not hung ==="
# echo 'oops leaves the shell in continuation; the precheck must reject it and
# the session must continue (timeout 8 => if it hangs, this fails as 124).
# \047 is a single quote; the first line "echo 'oops" is an unterminated quote.
OG=$(printf 'echo \047oops\necho recovered\nexit\n' | timeout 8 ssentry run --config "$CFG" 2>/dev/null)
RC=$?
if [ "$RC" != "124" ] && echo "$OG" | grep -q "incomplete command" && echo "$OG" | grep -q "recovered"; then
  pass "G: incomplete line rejected, session recovered (no hang)"
else
  fail "G: incomplete line hung or was not rejected (rc=$RC)"; echo "$OG" | tail
fi

echo "======================================"
if [ "$FAILS" = "0" ]; then echo "ALL TESTS PASSED"; exit 0; else echo "$FAILS TEST(S) FAILED"; exit 1; fi
