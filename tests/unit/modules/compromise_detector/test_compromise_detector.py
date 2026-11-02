# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the TRINETRA engine (modules/compromise_detector/core).

Plain unittest so they also run without the Slips test fixtures:
    python -m unittest tests.unit.modules.compromise_detector.test_compromise_detector
"""
import math
import os
import random
import tempfile
import unittest

from modules.compromise_detector.core.detectors import BeaconDetector, TailCalibrator, cauchy_combine
from modules.compromise_detector.core.features import (CONTEXT, FEATURES, FIDX, NOVELTY_KINDS, FleetConsensus,
                                                       Profile, compute, window_items)
from modules.compromise_detector.core.schema import KINDS, Event, Inventory, read_events, write_events
from modules.compromise_detector.core.simulate import simulate


def flow(ts, src, dst, dport=443, bout=500, bin_=900, proto="tcp", dev="WS-01"):
    return Event(ts, dev, "flow", {"src": src, "dst": dst, "dport": dport, "bout": bout, "bin": bin_, "proto": proto})


def empty_items():
    return {k: set() for k in NOVELTY_KINDS}


class SchemaTest(unittest.TestCase):
    def test_events_round_trip_through_jsonl(self):
        evs = [flow(20.0, "10.0.1.5", "8.8.8.8"), Event(10.0, "RTR-1", "log", {"t": "config_exit"})]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ubt.jsonl")
            write_events(path, evs)
            back = read_events(path)
        self.assertEqual([e.ts for e in back], [10.0, 20.0])          # sorted by time
        self.assertEqual(back[1].a["dst"], "8.8.8.8")

    def test_inventory_rejects_unknown_device_type(self):
        with self.assertRaises(ValueError):
            Inventory.from_dict({"devices": [{"id": "X", "type": "toaster", "ip": "10.0.0.9"}]})

    def test_simulator_only_emits_known_kinds(self):
        events, _, _ = simulate(seed=3, days=2, train_days=1, attacks=set())
        self.assertTrue({e.kind for e in events} <= set(KINDS))


class FeatureTest(unittest.TestCase):
    def test_vector_shape_and_counts(self):
        evs = [flow(i, "10.0.1.5", f"45.33.32.{i}", dport=1000 + i, bin_=0) for i in range(10)]
        f = compute(evs, Profile().novel(window_items(evs)), ts=0)
        self.assertEqual(len(f), len(FEATURES) + len(CONTEXT))
        self.assertEqual(round(math.expm1(f[FIDX["n_dport"]])), 10)
        self.assertEqual(round(math.expm1(f[FIDX["failed_conn"]])), 10)   # tcp with no bytes back
        self.assertEqual(round(math.expm1(f[FIDX["new_dst"]])), 10)

    def test_profile_forgets_nothing_it_learned(self):
        p, items = Profile(), window_items([flow(0, "10.0.1.5", "1.1.1.1")])
        self.assertEqual(p.novel(items)["dst"], {"1.1.1.1"})
        p.learn(items)
        self.assertEqual(p.novel(items)["dst"], set())


class FleetConsensusTest(unittest.TestCase):
    def setUp(self):
        self.hosts = [f"WS-{i:02d}" for i in range(6)]
        self.fc = FleetConsensus({h: "host" for h in self.hosts})

    def novel(self, devs, domain="patch.example.com", w=10):
        by_dev = {}
        for h in self.hosts:
            items = empty_items()
            if h in devs:
                items["domain"].add(domain)
            by_dev[h] = items
        self.fc.add(w, by_dev)
        return by_dev

    def test_change_on_many_peers_is_common(self):
        self.novel(self.hosts[:3])
        self.assertIn("patch.example.com", self.fc.common(10)["domain"])

    def test_change_on_one_device_is_not_common(self):
        self.novel(self.hosts[:1], domain="evil.example.net")
        self.assertEqual(self.fc.common(10)["domain"], set())

    def test_fleet_change_only_while_spreading(self):
        by_dev = self.novel(self.hosts[:3])
        self.fc.common(10)
        self.fc.touch(10, by_dev)
        self.assertTrue(self.fc.fleet_change(10))                     # 3 of 6 hosts, still spreading
        self.fc.touch(20, by_dev)                                     # same hosts keep using it later
        self.assertFalse(self.fc.fleet_change(20))                    # steady use is not a change


class CalibrationTest(unittest.TestCase):
    def test_tail_p_values_are_monotone(self):
        rng = random.Random(1)
        cal = TailCalibrator().fit([rng.gauss(0, 1) for _ in range(2000)])
        ps = [cal.p(x) for x in (-1, 0, 1, 2, 4, 8)]
        self.assertTrue(all(0 < p <= 1 for p in ps))
        self.assertEqual(ps, sorted(ps, reverse=True))
        self.assertLess(ps[-1], 1e-3)

    def test_cauchy_combination(self):
        self.assertAlmostEqual(cauchy_combine([0.1, 0.1, 0.1]), 0.1, places=6)  # equal evidence keeps its p
        self.assertEqual(cauchy_combine([0.6, 0.9]), 1.0)                     # one-sided: p >= 0.5 is no evidence
        self.assertLess(cauchy_combine([1e-6, 0.6, 0.7, 0.9]), 1e-5)          # one strong signal survives fusion


class BeaconTest(unittest.TestCase):
    def run_flows(self, det, gaps, learn=False):
        t, evs = 0.0, []
        for g in gaps:
            t += g
            evs.append(flow(t, "10.0.1.5", "45.33.32.156"))   # public address (TEST-NET ranges count as private)
        return det.score("WS-01", evs, t, learn=learn)

    def test_regular_contacts_are_a_beacon(self):
        rng = random.Random(2)
        score, info = self.run_flows(BeaconDetector(), [60 * rng.uniform(0.95, 1.05) for _ in range(40)])
        self.assertGreaterEqual(score, BeaconDetector.MIN_REG)
        self.assertAlmostEqual(info["period_s"], 60, delta=3)

    def test_irregular_contacts_are_not(self):
        rng = random.Random(3)
        score, _ = self.run_flows(BeaconDetector(), [rng.expovariate(1 / 60) + 3 for _ in range(40)])
        self.assertLess(score, BeaconDetector.MIN_REG)

    def test_pairs_seen_while_baselining_are_ignored(self):
        det = BeaconDetector()
        self.run_flows(det, [60] * 30, learn=True)
        score, _ = self.run_flows(det, [60] * 30)
        self.assertEqual(score, 0.0)


class SimulatorTest(unittest.TestCase):
    def test_failed_spraying_does_not_label_the_target(self):
        _, _, truth = simulate(seed=99, attacks={"A1"})
        self.assertNotIn("SRV-DB", truth["compromised"])
        self.assertIn("SRV-FILE", truth["compromised"])               # the later successful login does

    def test_same_seed_same_week(self):
        a, _, _ = simulate(seed=5, days=2, train_days=1)
        b, _, _ = simulate(seed=5, days=2, train_days=1)
        self.assertEqual([(e.ts, e.device, e.kind) for e in a[:500]], [(e.ts, e.device, e.kind) for e in b[:500]])


@unittest.skipUnless(os.environ.get("TRINETRA_SLOW"), "end-to-end benchmark, set TRINETRA_SLOW=1")
class BenchmarkTest(unittest.TestCase):
    def test_seed_7_benchmark(self):
        from modules.compromise_detector.core.pipeline import run_demo
        ev = run_demo(7, ablations=False)["evaluation"]
        self.assertEqual((ev["tp"], ev["fp"], ev["n_attacked"]), (7, 0, 7))


if __name__ == "__main__":
    unittest.main()
