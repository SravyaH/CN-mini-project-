"""Runs experiments/measure.py end-to-end with the SYNTHETIC FakeLab to check the CSV schema and
aggregation code. Output goes to a temp dir; nothing here is a real measurement."""
import csv
import os
import shutil
import sys
import tempfile
import time
import unittest

from experiments import measure
from tests.fake_lab import FakeLab


class MeasurePipeline(unittest.TestCase):
    def test_quick_grid_writes_all_csvs(self):
        tmp = tempfile.mkdtemp()
        real_sleep = time.sleep
        time.sleep = lambda s: real_sleep(min(s, 0.01))
        argv = sys.argv
        sys.argv = ["measure", "--quick", "--out", tmp]
        try:
            measure.main(lab_factory=FakeLab)
        finally:
            time.sleep, sys.argv = real_sleep, argv
        rows = {n: list(csv.DictReader(open(os.path.join(tmp, n + ".csv")))) for n in ("impact", "coldstart", "response")}
        self.assertEqual(len(rows["impact"]), 3 * 2 * 2)                 # modes x clients x rates
        self.assertEqual(len(rows["coldstart"]), 3 * 5)
        self.assertTrue(rows["response"])
        dyn = [r for r in rows["impact"] if r["mode"] == "dynamic" and r["attack_rate"] == "200"]
        self.assertTrue(all(r["blocked"] == "yes" and float(r["response_ms"]) > 0 for r in dyn))
        self.assertTrue(all(float(r["response_ms"]) > 0 for r in rows["response"] if r["response_ms"]))
        shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
