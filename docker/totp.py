#!/usr/bin/env python3
"""Compute the current TOTP code from a base32 secret, stdlib only.
Matches pquerna/otp defaults: SHA1, 30s period, 6 digits."""
import sys, hmac, hashlib, struct, time, base64

secret = sys.argv[1].strip().upper()
pad = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + pad)
counter = int(time.time()) // 30
msg = struct.pack(">Q", counter)
h = hmac.new(key, msg, hashlib.sha1).digest()
o = h[19] & 0x0F
code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
print("%06d" % code)
