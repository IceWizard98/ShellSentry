import hashlib, hmac, json, os, pickle, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINER = os.path.join(HERE, "trainer.py")


def run(features, outdir, extra=None):
    p = subprocess.run(
        [sys.executable, TRAINER, "--outdir", outdir, *(extra or [])],
        input=json.dumps({"features": features}),
        text=True, capture_output=True,
    )
    return p


class TrainerTest(unittest.TestCase):
    def test_produces_model_and_thresholds(self):
        # 60 "normal" rows + a few outliers so percentiles are meaningful
        rows = [[1.0, 0.0, 1, 1, 2, 5] for _ in range(60)]
        rows += [[-1.0, 0.0, 0, 99, 0, 9999999] for _ in range(5)]
        with tempfile.TemporaryDirectory() as d:
            p = run(rows, d)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(os.path.exists(os.path.join(d, "model.pkl")))
            with open(os.path.join(d, "thresholds.json")) as f:
                th = json.load(f)
            self.assertIn("soft", th)
            self.assertIn("hard", th)
            # low score = anomalous, so hard (2nd pct) <= soft (5th pct)
            self.assertLessEqual(th["hard"], th["soft"])
            with open(os.path.join(d, "model.pkl"), "rb") as f:
                clf = pickle.load(f)
            self.assertTrue(hasattr(clf, "score_samples"))

    def test_empty_input_errors(self):
        with tempfile.TemporaryDirectory() as d:
            p = run([], d)
            self.assertNotEqual(p.returncode, 0)

    def test_signs_model_and_writes_gen(self):
        rows = [[1.0, 0.0, 1, 1, 2, 5] for _ in range(60)]
        with tempfile.TemporaryDirectory() as d:
            keyp = os.path.join(d, "k")
            key = b"secret-key-32-bytes-xxxxxxxxxxxx"
            with open(keyp, "wb") as f:
                f.write(key)
            p = run(rows, d, extra=["--hmac-key", keyp, "--gen", "12345"])
            self.assertEqual(p.returncode, 0, p.stderr)
            # HMAC sidecar matches the model bytes
            with open(os.path.join(d, "model.pkl"), "rb") as f:
                want = hmac.new(key, f.read(), hashlib.sha256).hexdigest()
            with open(os.path.join(d, "model.pkl.hmac")) as f:
                self.assertEqual(f.read().strip(), want)
            # gen propagated into both thresholds and the model meta
            with open(os.path.join(d, "thresholds.json")) as f:
                self.assertEqual(json.load(f)["gen"], 12345)
            with open(os.path.join(d, "model.meta.json")) as f:
                self.assertEqual(json.load(f)["gen"], 12345)
            # no leftover temp files from atomic writes
            self.assertFalse(any(n.endswith(".tmp") for n in os.listdir(d)))


if __name__ == "__main__":
    unittest.main()
