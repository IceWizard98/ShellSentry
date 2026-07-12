#!/usr/bin/env python3
"""Stateless Isolation Forest trainer for Shell Sentry.

Reads a JSON feature matrix on stdin, fits an IsolationForest, computes the
soft/hard anomaly thresholds as low percentiles of score_samples (high = normal,
low = anomalous), and writes model.pkl + thresholds.json to --outdir. It knows
nothing about the DB, encoders, or geo — Go does all of that."""
import argparse
import json
import os
import pickle
import sys

import numpy as np
from sklearn.ensemble import IsolationForest

SOFT_PCT = 5.0  # 5th percentile of score_samples
HARD_PCT = 2.0  # 2nd percentile (lower = more anomalous)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
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
    with open(os.path.join(args.outdir, "model.pkl"), "wb") as f:
        pickle.dump(clf, f)
    with open(os.path.join(args.outdir, "thresholds.json"), "w") as f:
        json.dump({"soft": soft, "hard": hard}, f)
    print(f"trainer: fit {X.shape[0]} rows, soft={soft:.4f} hard={hard:.4f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
