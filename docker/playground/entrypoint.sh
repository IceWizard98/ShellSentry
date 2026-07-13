#!/bin/bash
# Playground entrypoint: start the alert sink + inference daemon in the
# background, then drop into an interactive shell so you drive ssentry yourself.
set -u

# 1. admin alert sink -> /tmp/alerts.log
/app/python/venv/bin/python /app/python/alert_reader.py /app/data/alerts.sock \
    >/tmp/alert_reader.log 2>&1 &

# 2. inference daemon (scores every command; no model yet -> everything "normal")
/app/python/venv/bin/python /app/python/daemon.py --config /app/config.yaml \
    >/tmp/daemon.log 2>&1 &
sleep 1

cat <<'MOTD'
============================================================
  Shell Sentry — PLAYGROUND   (user: tester, clean state)
============================================================
Nothing is trained yet. The inference daemon is already running.
Drive it yourself, from moment 0:

  ssentry run                 start a MONITORED session.
                              First time -> a TOTP QR + secret is shown; save it
                              in an authenticator, then answer [y/N] to confirm
                              enrollment. If you DON'T confirm, nothing is saved
                              and the QR is shown again next login. After that,
                              type commands; `exit` (or Ctrl-D) to end — a clean
                              session is saved to the per-user DB. Ctrl-C does
                              NOT drop you out of ssentry (it stays in control);
                              only `exit`/EOF ends the monitored session. In
                              production (ForceCommand) that also closes SSH.

  ssentry train --user tester train a model once you have >= 3 saved sessions
                              (writes dicts.json + model.pkl + thresholds.json;
                              the daemon hot-reloads it).

  otp                         print the current TOTP code (answer challenges;
                              handy from a second `docker exec -it <c> otp`).

Things to try:
  * First `ssentry run`: no model -> every command passes (learning phase).
  * Run a few sessions (whoami, ls, cd, cat ...), `exit` each, then `train`.
  * After training, run again -> now odd-hour / never-seen commands get
    challenged. `mkfs ...` is deny-listed and always challenges (see rules.json).

Inspect anytime:
  sqlite3 /app/data/tester/sessions.db 'SELECT id,command_count FROM session;'
  ls -la /app/data/tester/        cat /app/data/tester/dicts.json
  cat /tmp/alerts.log             cat /tmp/daemon.log
============================================================
MOTD

exec bash
