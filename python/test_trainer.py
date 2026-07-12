import json, os, pickle, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINER = os.path.join(HERE, "trainer.py")


def run(features, outdir):
    p = subprocess.run(
        [sys.executable, TRAINER, "--outdir", outdir],
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


if __name__ == "__main__":
    unittest.main()
