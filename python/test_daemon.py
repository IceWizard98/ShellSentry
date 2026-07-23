import json, os, pickle, socket, tempfile, threading, unittest
import numpy as np
from sklearn.ensemble import IsolationForest

import daemon as D


def make_model(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    clf = IsolationForest(random_state=0, n_estimators=10).fit(
        np.random.RandomState(0).rand(50, 6))
    with open(path, "wb") as f:
        pickle.dump(clf, f)


FEATS = {"time_cos": 1, "time_sin": 0, "geo_id": 1,
         "cmd_index": 1, "path_index": 1, "secs_since_last": 1}


def send(host, port, obj):
    s = socket.create_connection((host, port), timeout=5)
    s.sendall((json.dumps(obj) + "\n").encode())
    line = s.makefile().readline()
    s.close()
    return line


class _StubCache:
    def __init__(self, score):
        self._score = score

    def score(self, user, vec):
        return self._score

    def evict_idle(self, now=None):
        return 0


class DaemonTest(unittest.TestCase):
    def _serve(self, root, cache=None):
        srv, stop = D.serve({"host": "127.0.0.1", "port": 0, "root": root, "ttl": 900},
                            cache=cache)
        host, port = srv.server_address
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(stop.set)
        self.addCleanup(srv.shutdown)
        return host, port

    def test_load_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.yaml")
            with open(p, "w") as f:
                f.write("daemon_addr: 127.0.0.1:9099\nroot_path: /x\nmodel_ttl_sec: 300\n")
            cfg = D.load_config(p)
            self.assertEqual((cfg["host"], cfg["port"], cfg["root"], cfg["ttl"]),
                             ("127.0.0.1", 9099, "/x", 300))

    def test_load_config_rejects_bad_addr(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ("daemon_addr: myhost\n", "daemon_addr: 127.0.0.1:0\n",
                        "daemon_addr: 127.0.0.1:99999\n"):
                p = os.path.join(d, "c.yaml")
                with open(p, "w") as f:
                    f.write(bad)
                with self.assertRaises(ValueError):
                    D.load_config(p)

    def test_scores_known_user(self):
        with tempfile.TemporaryDirectory() as d:
            make_model(os.path.join(d, "alice", "model.pkl"))
            host, port = self._serve(d)
            resp = json.loads(send(host, port,
                {"user": "alice", "session_id": "s", "features": FEATS}))
            self.assertIn("score", resp)
            self.assertIsInstance(resp["score"], float)

    def test_no_model_high_score(self):
        with tempfile.TemporaryDirectory() as d:
            host, port = self._serve(d)
            resp = json.loads(send(host, port,
                {"user": "ghost", "session_id": "s", "features": FEATS}))
            self.assertGreater(resp["score"], 1e6)

    def test_malformed_closes_without_reply(self):
        with tempfile.TemporaryDirectory() as d:
            host, port = self._serve(d)
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"this is not json\n")
            self.assertEqual(s.makefile().readline(), "")  # closed, no reply
            s.close()

    def test_traversing_user_closes_without_reply(self):
        with tempfile.TemporaryDirectory() as d:
            host, port = self._serve(d)
            for bad in ("../../etc", "a/b", "..", ""):
                r = send(host, port,
                         {"user": bad, "session_id": "s", "features": FEATS})
                self.assertEqual(r, "", f"user {bad!r} must be rejected")

    def test_concurrent_clients(self):
        with tempfile.TemporaryDirectory() as d:
            make_model(os.path.join(d, "alice", "model.pkl"))
            host, port = self._serve(d)
            out, lock = [], threading.Lock()

            def worker():
                r = json.loads(send(host, port,
                    {"user": "alice", "session_id": "s", "features": FEATS}))
                with lock:
                    out.append(r)

            ts = [threading.Thread(target=worker) for _ in range(10)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.assertEqual(len(out), 10)
            self.assertTrue(all("score" in r for r in out))

    def test_gen_mismatch_closes(self):
        with tempfile.TemporaryDirectory() as d:
            make_model(os.path.join(d, "alice", "model.pkl"))
            with open(os.path.join(d, "alice", "model.meta.json"), "w") as f:
                json.dump({"gen": 100}, f)
            host, port = self._serve(d)
            ok = send(host, port,
                      {"user": "alice", "session_id": "s", "features": FEATS, "gen": 100})
            self.assertIn("score", json.loads(ok))  # matching gen -> scored
            bad = send(host, port,
                       {"user": "alice", "session_id": "s", "features": FEATS, "gen": 999})
            self.assertEqual(bad, "")  # stale gen -> closed, Go fail-opens

    def test_nan_score_closes_without_reply(self):
        with tempfile.TemporaryDirectory() as d:
            host, port = self._serve(d, cache=_StubCache(float("nan")))
            s = socket.create_connection((host, port), timeout=5)
            s.sendall((json.dumps(
                {"user": "u", "session_id": "s", "features": FEATS}) + "\n").encode())
            self.assertEqual(s.makefile().readline(), "")  # NaN -> closed, no reply
            s.close()

    def test_oversized_request_closes(self):
        with tempfile.TemporaryDirectory() as d:
            host, port = self._serve(d)
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"x" * (D.MAX_REQUEST_BYTES + 10))  # no newline, over cap
            self.assertEqual(s.makefile().readline(), "")  # rejected, no reply
            s.close()


if __name__ == "__main__":
    unittest.main()
