"""Per-user Isolation Forest model cache for the inference daemon.

Loads <root>/<user>/model.pkl on demand, reloads when the file's mtime changes
(so a retrain is picked up without a restart), and evicts entries idle beyond a
TTL. Thread-safe: the cache dict is guarded by a lock; scoring runs outside the
lock (numpy/sklearn release the GIL)."""
import os
import pickle
import sys
import threading
import time

# Returned when a user has no trained model yet: a high score reads as "normal"
# to the runtime (which compares score <= threshold), so nothing is challenged.
NO_MODEL_SCORE = 1e9


class ModelCache:
    def __init__(self, root, ttl_sec, now=time.monotonic):
        self._root = root
        self._ttl = ttl_sec
        self._now = now
        self._lock = threading.Lock()
        self._entries = {}  # user -> {"model", "key": (mtime, size), "atime"}

    def _model_path(self, user):
        return os.path.join(self._root, user, "model.pkl")

    def score(self, user, features):
        model = self._get_model(user)
        if model is None:
            return NO_MODEL_SCORE
        return float(model.score_samples([features])[0])

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
        # every other user's lookups behind it.
        try:
            with open(path, "rb") as f:
                model = pickle.load(f)
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
