#!/bin/bash
# Print the CURRENT TOTP code for tester's provisioned secret. Use it to answer
# an OTP challenge (run this in a second `docker exec -it <container> otp`).
set -euo pipefail
SEC=/app/otp-secrets/tester/totp.secret
if [ ! -f "$SEC" ]; then
  echo "no TOTP secret yet, run 'ssentry run' once (and confirm enrollment)" >&2
  exit 1
fi
exec /app/python/venv/bin/python /app/python/totp_code.py "$(cat "$SEC")"
