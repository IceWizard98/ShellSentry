import os, pickle, tempfile, unittest
import numpy as np
from sklearn.ensemble import IsolationForest

from model_cache import ModelCache, NO_MODEL_SCORE


def make_model(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    clf = IsolationForest(random_state=0, n_estimators=10).fit(
        np.random.RandomState(0).rand(50, 6))
    with open(path, "wb") as f:
        pickle.dump(clf, f)


VEC = [1.0, 0.0, 1, 1, 1, 1]


class ModelCacheTest(unittest.TestCase):
    def test_no_model_returns_sentinel(self):
        with tempfile.TemporaryDirectory() as d:
            c = ModelCache(d, 900)
            self.assertEqual(c.score("ghost", VEC), NO_MODEL_SCORE)

    def test_scores_with_model(self):
        with tempfile.TemporaryDirectory() as d:
            make_model(os.path.join(d, "alice", "model.pkl"))
            c = ModelCache(d, 900)
            s = c.score("alice", VEC)
            self.assertIsInstance(s, float)

    def test_corrupt_model_deleted_and_treated_as_untrained(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bob", "model.pkl")
            os.makedirs(os.path.dirname(p))
            with open(p, "wb") as f:
                f.write(b"not a pickle")
            c = ModelCache(d, 900)
            # unusable model -> deleted from disk + scored as untrained (sentinel)
            self.assertEqual(c.score("bob", VEC), NO_MODEL_SCORE)
            self.assertFalse(os.path.exists(p))

    def test_transient_io_error_does_not_delete(self):
        # A model path that is a directory makes open() raise IsADirectoryError
        # (an OSError) — a transient/IO-class error that must PROPAGATE, not
        # delete the path or mask it as untrained.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "eve", "model.pkl")
            os.makedirs(p)  # model.pkl is a directory -> open() raises OSError
            c = ModelCache(d, 900)
            with self.assertRaises(OSError):
                c.score("eve", VEC)
            self.assertTrue(os.path.exists(p))  # not deleted

    def test_model_removed_returns_sentinel(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "al", "model.pkl")
            make_model(p)
            c = ModelCache(d, 900)
            self.assertIsInstance(c.score("al", VEC), float)
            os.remove(p)
            self.assertEqual(c.score("al", VEC), NO_MODEL_SCORE)

    def test_reload_on_mtime_change(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "al", "model.pkl")
            make_model(p)
            c = ModelCache(d, 900)
            c.score("al", VEC)
            make_model(p)                       # rewrite
            os.utime(p, (2_000_000_000, 2_000_000_000))  # force newer mtime
            # must reload without error and keep scoring
            self.assertIsInstance(c.score("al", VEC), float)

    def test_evict_idle(self):
        with tempfile.TemporaryDirectory() as d:
            make_model(os.path.join(d, "al", "model.pkl"))
            fake = [1000.0]
            c = ModelCache(d, 100, now=lambda: fake[0])
            c.score("al", VEC)
            fake[0] = 1050.0
            self.assertEqual(c.evict_idle(), 0)   # within ttl
            fake[0] = 1200.0
            self.assertEqual(c.evict_idle(), 1)   # idle > 100


if __name__ == "__main__":
    unittest.main()
