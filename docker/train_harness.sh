#!/usr/bin/env bash
# Training e2e harness (Linux container): builds the venv, seeds synthetic
# sessions straight into sqlite (schema matches adapters/sqlitestore/store.go),
# runs `ssentry train`, and asserts retention, gating, and trainer outputs.
set -u
FAILS=0
pass(){ echo "PASS: $1"; }
fail(){ echo "FAIL: $1"; FAILS=$((FAILS+1)); }

CFG=/work/config.yaml
ROOT=/work/data

cat > "$CFG" <<EOF
root_path: "$ROOT"
geoip_db_path: "/work/missing.mmdb"
daemon_addr: "127.0.0.1:19099"
score_timeout_ms: 500
alert_socket: "/work/alerts.sock"
otp_retries: 2
rules_path: "/work/rules.json"
model_ttl_sec: 900
command_timeout_ms: 0
min_sessions_train: 20
max_sessions_keep: 30
EOF
echo '{"commands":{"deny":[],"allow":[]},"min_seconds_between":0,"countries":{"deny":[],"allow":[]}}' > /work/rules.json

echo "=== venv setup (python/requirements.txt) ==="
if python3 -m venv python/venv >/tmp/venv.log 2>&1 && ./python/venv/bin/pip install -q -r python/requirements.txt >>/tmp/venv.log 2>&1; then
  pass "venv built + trainer deps installed"
else
  fail "venv/pip install failed"; tail -40 /tmp/venv.log
fi

# seed(user, n_sessions, cmds_per_session) writes N sessions directly into
# <root>/<user>/sessions.db via sqlite3, using the same schema as sqlitestore.
seed() {
  local user="$1" n="$2" cmds_per="$3"
  mkdir -p "$ROOT/$user"
  python3 - "$ROOT/$user/sessions.db" "$n" "$cmds_per" <<'PY'
import sqlite3, sys, time

db_path, n, cmds_per = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
conn = sqlite3.connect(db_path)
conn.execute("""CREATE TABLE IF NOT EXISTS session (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  start_ts INTEGER NOT NULL,
  end_ts INTEGER NOT NULL,
  command_count INTEGER NOT NULL
)""")
conn.execute("""CREATE TABLE IF NOT EXISTS command (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_fk INTEGER NOT NULL REFERENCES session(id),
  ts INTEGER NOT NULL,
  time_cos REAL, time_sin REAL,
  geo_id INTEGER, cmd_index INTEGER, path_index INTEGER, secs_since_last INTEGER,
  raw_cmd TEXT, ip TEXT
)""")

base = int(time.time()) - n * 100
sample_cmds = ["ls -la", "cd /tmp", "whoami", "cat /etc/passwd", "pwd"]
for i in range(n):
    start = base + i * 100
    end = start + cmds_per
    cur = conn.execute(
        "INSERT INTO session (start_ts, end_ts, command_count) VALUES (?, ?, ?)",
        (start, end, cmds_per),
    )
    sid = cur.lastrowid
    for j in range(cmds_per):
        raw = sample_cmds[j % len(sample_cmds)]
        conn.execute(
            "INSERT INTO command (session_fk, ts, time_cos, time_sin, geo_id, "
            "cmd_index, path_index, secs_since_last, raw_cmd, ip) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, start + j, 1.0, 0.0, 0, 0, 0, j, raw, "8.8.8.8"),
        )
conn.commit()
conn.close()
PY
}

count_sessions() {
  python3 -c "
import sqlite3
try:
    print(sqlite3.connect('$ROOT/$1/sessions.db').execute('select count(*) from session').fetchone()[0])
except Exception:
    print(0)
"
}

echo "=== seed: user 'trainee' with 40 sessions (> max_sessions_keep=30, > min_sessions_train=20) ==="
seed trainee 40 5
BEFORE=$(count_sessions trainee)
[ "$BEFORE" = "40" ] && pass "seeded 40 sessions for trainee" || fail "seed count wrong: $BEFORE"

echo "=== seed: user 'newbie' with 5 sessions (< min_sessions_train=20) ==="
seed newbie 5 3

echo "=== run: ssentry train --user trainee ==="
OUT=$(cd /work && SSENTRY_CONFIG="$CFG" ssentry train --user trainee --config "$CFG" 2>&1)
echo "$OUT"

AFTER=$(count_sessions trainee)
[ "$AFTER" = "30" ] && pass "retention pruned trainee to max_sessions_keep=30" \
  || fail "expected 30 sessions after prune, got $AFTER"

# cascade: commands for pruned sessions must be gone too (30 sessions * 5 cmds = 150)
CMD_COUNT=$(python3 -c "
import sqlite3
print(sqlite3.connect('$ROOT/trainee/sessions.db').execute('select count(*) from command').fetchone()[0])
")
[ "$CMD_COUNT" = "150" ] && pass "pruned sessions' commands cascade-deleted (150 remain)" \
  || fail "expected 150 commands after cascade prune, got $CMD_COUNT"

DICTS="$ROOT/trainee/dicts.json"
if [ -f "$DICTS" ]; then
  python3 - "$DICTS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cmd_ok = isinstance(d.get("command"), dict) and len(d["command"]) > 0
path_ok = isinstance(d.get("path"), dict) and len(d["path"]) > 0
sys.exit(0 if cmd_ok and path_ok else 1)
PY
  if [ $? -eq 0 ]; then pass "dicts.json has non-empty command+path maps"; else fail "dicts.json command/path maps empty"; fi
else
  fail "dicts.json missing"
fi

MODEL="$ROOT/trainee/model.pkl"
THRESH="$ROOT/trainee/thresholds.json"
if [ -f "$MODEL" ]; then pass "model.pkl written"; else fail "model.pkl missing"; fi
if [ -f "$THRESH" ]; then
  python3 - "$THRESH" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
sys.exit(0 if "hard" in t and "soft" in t and t["hard"] <= t["soft"] else 1)
PY
  if [ $? -eq 0 ]; then pass "thresholds.json present with hard<=soft"; else fail "thresholds.json missing keys or hard>soft"; fi
else
  fail "thresholds.json missing"
fi

echo "=== run: ssentry train --user newbie (below min_sessions_train) ==="
OUT2=$(cd /work && SSENTRY_CONFIG="$CFG" ssentry train --user newbie --config "$CFG" 2>&1)
echo "$OUT2"
echo "$OUT2" | grep -qi "not enough sessions" && pass "newbie below min_sessions_train -> skip message" \
  || fail "expected skip message for newbie, got: $OUT2"
if [ -f "$ROOT/newbie/model.pkl" ]; then fail "newbie model.pkl should not exist (gated below min)"; else pass "newbie has no model.pkl (correctly gated)"; fi

echo "=== preflight: python_bin missing -> fail fast, DB untouched ==="
# Point python_bin at a non-existent interpreter; training must error before
# pruning. Re-seed a user over max_sessions_keep and confirm no prune happened.
BADCFG=/work/bad.yaml
sed 's#^python_bin:.*#python_bin: "/no/such/python"#' "$CFG" > "$BADCFG"
grep -q '^python_bin:' "$BADCFG" || echo 'python_bin: "/no/such/python"' >> "$BADCFG"
PREBEFORE=$(python3 -c "import sqlite3;print(sqlite3.connect('$ROOT/$USER_NAME/sessions.db').execute('select count(*) from session').fetchone()[0])")
if (cd /work && SSENTRY_CONFIG="$BADCFG" ssentry train --user "$USER_NAME" --config "$BADCFG" 2>/dev/null); then
  fail "training with a missing python_bin should have failed"
else
  pass "missing python_bin -> ssentry train exits non-zero (fail fast)"
fi
PREAFTER=$(python3 -c "import sqlite3;print(sqlite3.connect('$ROOT/$USER_NAME/sessions.db').execute('select count(*) from session').fetchone()[0])")
[ "$PREBEFORE" = "$PREAFTER" ] && pass "preflight failure left the DB untouched ($PREAFTER sessions)" \
  || fail "preflight failure mutated the DB ($PREBEFORE -> $PREAFTER)"

echo "======================================"
if [ "$FAILS" = "0" ]; then echo "ALL TESTS PASSED"; exit 0; else echo "$FAILS TEST(S) FAILED"; exit 1; fi
