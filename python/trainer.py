#!/usr/bin/env python3
"""Stateless Isolation Forest trainer for Shell Sentry.

Reads a JSON feature matrix on stdin, fits an IsolationForest, computes the
soft/hard anomaly thresholds as low percentiles of score_samples (high = normal,
low = anomalous), and writes model.pkl + thresholds.json to --outdir. It knows
nothing about the DB, encoders, or geo — Go does all of that."""
import argparse
import hashlib
import hmac
import json
import os
import pickle
import sys

import numpy as np
from sklearn.ensemble import IsolationForest

SOFT_PCT = 5.0  # 5th percentile of score_samples
HARD_PCT = 2.0  # 2nd percentile (lower = more anomalous)


def atomic_write(path, data: bytes):
    # Write to a temp file in the same dir and os.replace into place, so a crash
    # mid-write never leaves a truncated model/threshold file for the daemon.
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--hmac-key", default="", help="key file to sign model.pkl")
    ap.add_argument("--gen", type=int, default=0, help="training generation id")
    args = ap.parse_args()

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"trainer: invalid JSON on stdin: {e}", file=sys.stderr)
        return 1

    features = payload.get("features")
    if not features:
        print("trainer: empty feature matrix", file=sys.stderr)
        return 1

    X = np.asarray(features, dtype=float)
    if X.ndim != 2 or X.shape[0] == 0:
        print(f"trainer: bad matrix shape {getattr(X, 'shape', None)}", file=sys.stderr)
        return 1

    clf = IsolationForest(random_state=42, n_estimators=200)
    clf.fit(X)
    scores = clf.score_samples(X)
    soft = float(np.percentile(scores, SOFT_PCT))
    hard = float(np.percentile(scores, HARD_PCT))

    os.makedirs(args.outdir, exist_ok=True)
    model_path = os.path.join(args.outdir, "model.pkl")
    model_bytes = pickle.dumps(clf)
    atomic_write(model_path, model_bytes)

    # Sign the model so the daemon can refuse an unsigned/forged pickle.
    if args.hmac_key:
        with open(args.hmac_key, "rb") as f:
            key = f.read()
        if not key:
            print(f"trainer: hmac key {args.hmac_key!r} is empty", file=sys.stderr)
            return 1
        mac = hmac.new(key, model_bytes, hashlib.sha256).hexdigest()
        atomic_write(model_path + ".hmac", mac.encode())

    # gen lets the runtime detect a model reloaded mid-session that no longer
    # matches its login-time encoders/thresholds (see daemon gen check).
    atomic_write(os.path.join(args.outdir, "thresholds.json"),
                 json.dumps({"soft": soft, "hard": hard, "gen": args.gen}).encode())
    atomic_write(os.path.join(args.outdir, "model.meta.json"),
                 json.dumps({"gen": args.gen}).encode())
    print(f"trainer: fit {X.shape[0]} rows, soft={soft:.4f} hard={hard:.4f} gen={args.gen}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
