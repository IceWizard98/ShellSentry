"""Per-user Isolation Forest model cache for the inference daemon.

Loads <root>/<user>/model.pkl on demand, reloads when the file's mtime changes
(so a retrain is picked up without a restart), and evicts entries idle beyond a
TTL. Thread-safe: the cache dict is guarded by a lock; scoring runs outside the
lock (numpy/sklearn release the GIL)."""
import hashlib
import hmac
import json
import os
import pickle
import sys
import threading
import time

# Returned when a user has no trained model yet: a high score reads as "normal"
# to the runtime (which compares score <= threshold), so nothing is challenged.
NO_MODEL_SCORE = 1e9


class ModelCache:
    def __init__(self, root, ttl_sec, now=time.monotonic, hmac_key=None):
        self._root = root
        self._ttl = ttl_sec
        self._now = now
        # When set, model.pkl is loaded ONLY if <path>.hmac matches an HMAC-SHA256
        # over its bytes with this key. Since a scored user owns their own model
        # dir, an unsigned/forged pickle is a code-exec vector; a mismatch is
        # refused (never unpickled). None = no verification (legacy deploys).
        self._hmac_key = hmac_key
        self._lock = threading.Lock()
        self._entries = {}  # user -> {"model", "key": (mtime, size), "atime"}

    def _model_path(self, user):
        # Defence in depth against a path-traversing user (the daemon also
        # validates before calling): the resolved per-user dir must stay under
        # root, else refuse rather than read an arbitrary pickle off disk.
        base = os.path.realpath(os.path.join(self._root, user))
        root = os.path.realpath(self._root)
        if base != root and not base.startswith(root + os.sep):
            raise ValueError(f"user path escapes root: {user!r}")
        return os.path.join(base, "model.pkl")

    def _hmac_ok(self, path, raw):
        # Returns True iff <path>.hmac exists and matches HMAC-SHA256(key, raw).
        try:
            with open(path + ".hmac", "r") as f:
                want = f.read().strip()
        except OSError:
            return False
        got = hmac.new(self._hmac_key, raw, hashlib.sha256).hexdigest()
        return hmac.compare_digest(got, want)

    def score(self, user, features):
        model = self._get_model(user)
        if model is None:
            return NO_MODEL_SCORE
        return float(model.score_samples([features])[0])

    def model_gen(self, user):
        # Generation id of the on-disk model (from model.meta.json), or None if
        # absent/unreadable. Lets the daemon reject a request whose runtime-side
        # encoders/thresholds no longer match the reloaded model.
        meta = os.path.join(os.path.dirname(self._model_path(user)), "model.meta.json")
        try:
            with open(meta) as f:
                return json.load(f).get("gen")
        except (OSError, ValueError):
            return None

    def _get_model(self, user):
        now = self._now()
        path = self._model_path(user)
        try:
            st = os.stat(path)
        except OSError:
            with self._lock:
                self._entries.pop(user, None)
            return None
        key = (st.st_mtime, st.st_size)  # size guards a same-mtime-tick rewrite

        # Fast path: already cached and unchanged -> no disk I/O, no load.
        with self._lock:
            entry = self._entries.get(user)
            if entry is not None and entry["key"] == key:
                entry["atime"] = now
                return entry["model"]

        # Slow path: load OUTSIDE the lock so a slow/large load doesn't serialize
        # every other user's lookups behind it. Read the bytes ONCE, then verify
        # + deserialize from those same bytes (no TOCTOU between check and load).
        # An OSError here (transient I/O, model.pkl is a dir) deliberately
        # propagates — it must never destroy a good model.
        with open(path, "rb") as f:
            raw = f.read()

        # HMAC gate: an unsigned or forged model is refused (NOT deleted — it may
        # be a legacy/migration model or a transient sidecar loss, and deleting a
        # possibly-good model on a signature miss would be its own footgun).
        if self._hmac_key is not None and not self._hmac_ok(path, raw):
            sys.stderr.write(
                f"model_cache: HMAC verification failed for {path}; refusing to load\n")
            sys.stderr.flush()
            with self._lock:
                self._entries.pop(user, None)
            return None

        try:
            model = pickle.loads(raw)
            if not hasattr(model, "score_samples"):
                raise ValueError(f"model for {user!r} lacks score_samples")
        except (pickle.UnpicklingError, EOFError, ValueError,
                AttributeError, ImportError) as e:
            # Genuine deserialization/schema failure: the bytes are not a usable
            # model, so delete it and treat the user as untrained rather than
            # re-reading a broken file every request. A retrain recreates it.
            # NOTE: a transient I/O error (OSError from open()/read — disk glitch,
            # NFS stale handle, permission race, the trainer rewriting mid-read)
            # is deliberately NOT caught here: it propagates so a flaky read never
            # destroys a good model; that request just fails and retries later.
            sys.stderr.write(f"model_cache: deleting unusable model {path}: {e}\n")
            sys.stderr.flush()
            try:
                os.remove(path)
            except OSError:
                pass
            with self._lock:
                self._entries.pop(user, None)
            return None

        with self._lock:
            # Load-outside-lock can race with a concurrent (re)load: if another
            # thread already cached a NEWER model (larger mtime), keep it instead
            # of clobbering it with our now-stale one.
            existing = self._entries.get(user)
            if existing is None or key[0] >= existing["key"][0]:
                self._entries[user] = {"model": model, "key": key, "atime": now}
                return model
            existing["atime"] = now
            return existing["model"]

    def evict_idle(self, now=None):
        now = self._now() if now is None else now
        with self._lock:
            stale = [u for u, e in self._entries.items() if now - e["atime"] > self._ttl]
            for u in stale:
                del self._entries[u]
        return len(stale)
