"""Run from this folder with: python -m unittest -v test_mvp"""
import importlib.util
import unittest

import numpy as np
import pandas as pd

import manifest
import sweep
from test import build_baseline, detect_anomalies, flag_persistent, make_features, split_benign, sweep_thresholds


class DetectorChecks(unittest.TestCase):
    def packets(self):
        return pd.DataFrame({
            "ts": [10.0, 12.0], "frame_len": [100, 200], "iat": [0.0, 2.0],
            "dst_ip": ["a", "b"], "dst_port": [80, 443], "tcp_syn": [1, 0],
        })

    def test_empty_seconds_have_counts_but_no_packet_averages(self):
        features = make_features(self.packets())
        self.assertEqual(features.index.tolist(), [0, 1, 2])
        self.assertEqual(features.loc[1, "packet_count"], 0)
        self.assertEqual(features.loc[1, "total_bytes"], 0)
        self.assertEqual(features.loc[1, "syn_count"], 0)
        self.assertTrue(pd.isna(features.loc[1, "mean_packet_size"]))
        self.assertTrue(pd.isna(features.loc[1, "mean_iat"]))
        mean, std = build_baseline(features)
        self.assertEqual(mean["packet_count"], 2 / 3)
        self.assertEqual(mean["mean_packet_size"], 150)
        results = detect_anomalies(features, mean, std)
        self.assertTrue(pd.notna(results.loc[1, "anomaly_score"]))

    def test_held_out_windows_never_enter_baseline(self):
        features = pd.DataFrame({"packet_count": range(10)})
        baseline, evaluation = split_benign(features)
        self.assertEqual(baseline.index.tolist(), list(range(7)))
        self.assertEqual(evaluation.index.tolist(), [7, 8, 9])
        evaluation.iloc[:] = 10000
        mean, _ = build_baseline(baseline)
        self.assertEqual(mean["packet_count"], 3)
        self.assertEqual(features.loc[7, "packet_count"], 7)

    def test_insufficient_baseline_is_rejected(self):
        for values in [[], [1], [1, np.nan]]:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "Insufficient"):
                build_baseline(pd.DataFrame({"packet_count": values}))
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            split_benign(pd.DataFrame({"packet_count": [1, 2]}))

    def test_alert_preserves_the_feature_and_signed_evidence(self):
        features = pd.DataFrame({"packet_count": [20], "total_bytes": [20]})
        mean = pd.Series({"packet_count": 10.0, "total_bytes": 100.0})
        std = pd.Series({"packet_count": 5.0, "total_bytes": 10.0})
        row = detect_anomalies(features, mean, std).iloc[0]
        self.assertTrue(row.anomaly)
        self.assertEqual(row.status, "anomaly")
        self.assertEqual(row.top_feature, "total_bytes")
        self.assertEqual(row.observed_value, 20)
        self.assertEqual(row.expected_mean, 100)
        self.assertEqual(row.expected_std, 10)
        self.assertEqual(row.feature_z_score, -8)
        self.assertEqual(row.anomaly_score, 8)

    def test_constant_features_and_unknown_observations(self):
        mean, std = build_baseline(pd.DataFrame({"packet_count": [4, 4]}))
        results = detect_anomalies(pd.DataFrame({"packet_count": [4, 5, 3, np.nan]}), mean, std)
        self.assertEqual(results.anomaly_score.iloc[0], 0)
        self.assertFalse(results.anomaly.iloc[0])
        self.assertEqual(results.feature_z_score.iloc[1], np.inf)
        self.assertEqual(results.feature_z_score.iloc[2], -np.inf)
        self.assertTrue(results.anomaly.iloc[1])
        self.assertTrue(results.anomaly.iloc[2])
        self.assertTrue(pd.isna(results.anomaly.iloc[3]))
        self.assertEqual(results.status.iloc[3], "insufficient_data")
        self.assertTrue(pd.isna(results.top_feature.iloc[3]))

    def test_persistence_rule_requires_consecutive_flags(self):
        features = pd.DataFrame({"packet_count": [20, 20, 20, 2, 20, 20]})
        mean = pd.Series({"packet_count": 5.0})
        std = pd.Series({"packet_count": 1.0})
        out = flag_persistent(detect_anomalies(features, mean, std))
        self.assertEqual(out["persistent_flag"].tolist(),
                         [False, False, True, False, False, False])
        self.assertEqual(out["status"].iloc[2], "persistent_anomaly")

    def test_threshold_sweep_runs(self):
        mean, std = build_baseline(pd.DataFrame({"packet_count": [4, 4, 6]}))
        sweep_thresholds(detect_anomalies(pd.DataFrame({"packet_count": [1, 9]}), mean, std),
                         detect_anomalies(pd.DataFrame({"packet_count": [5]}), mean, std))

    def test_invalid_inputs_and_mismatched_baseline_are_rejected(self):
        for column, value in [("ts", np.nan), ("frame_len", np.inf), ("iat", "bad")]:
            packets = self.packets().astype({column: object})
            packets.loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError):
                make_features(packets)
        with self.assertRaisesRegex(ValueError, "Missing packet columns"):
            make_features(self.packets().drop(columns="ts"))
        with self.assertRaisesRegex(ValueError, "No packets"):
            make_features(self.packets().iloc[:0])
        with self.assertRaisesRegex(ValueError, "match"):
            detect_anomalies(pd.DataFrame({"x": [1]}), pd.Series({"y": 1}), pd.Series({"y": 1}))
        with self.assertRaisesRegex(ValueError, "finite"):
            detect_anomalies(pd.DataFrame({"x": [1]}), pd.Series({"x": 1}), pd.Series({"x": np.nan}))


class ManifestChecks(unittest.TestCase):
    def test_parse_capture_keeps_label_and_method(self):
        self.assertEqual(manifest.parse_capture("pod-nginx-tcp.csv"), ("pod-nginx", "tcp"))
        self.assertEqual(manifest.parse_capture("/x/y/pod-robot-controller-ptcp.csv"),
                         ("pod-robot-controller", "ptcp"))
        with self.assertRaises(ValueError):
            manifest.parse_capture("router-any.csv")

    def test_level_comes_from_the_label_prefix(self):
        self.assertEqual(manifest.level_from_label("pod-lidar"), "pod")
        self.assertEqual(manifest.level_from_label("node-gchild9"), "node")
        self.assertEqual(manifest.level_from_label("router-flannel"), "router")
        with self.assertRaises(ValueError):
            manifest.level_from_label("child4")

    def _tree(self):
        import tempfile
        from pathlib import Path
        root = Path(tempfile.mkdtemp())
        for scenario, folder in [("benign", "csv files/tcp/pod level"),
                                 ("injection attack", "csv files")]:
            target = root / scenario / folder
            target.mkdir(parents=True)
            (target / "pod-nginx-tcp.csv").write_text(
                "ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
                + "\n".join(f"{10.0 + i},0.1,100,::1,8080,0,0" for i in range(30)) + "\n")
        (root / "benign" / "csv files" / "ptcp" / "router level").mkdir(parents=True)
        (root / "benign" / "csv files" / "ptcp" / "router level" / "router-any-ptcp.csv").write_text(
            "ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
            + "\n".join(f"{10.0 + i},0.1,100,::1,8080,0,0" for i in range(10)) + "\n")
        return root

    def test_manifest_finds_both_tree_layouts(self):
        frame = manifest.build_manifest(self._tree())
        self.assertEqual(len(frame), 3)
        self.assertEqual(frame["scenario"].tolist(), ["benign", "benign", "injection attack"])
        self.assertEqual(set(frame["level"]), {"pod", "router"})
        self.assertEqual(set(frame["method"]), {"tcp", "ptcp"})

    def test_describe_captures_counts_packets_and_flags_bad_timebase(self):
        root = self._tree()
        bad = root / "injection attack" / "csv files" / "pod-nginx-tcp.csv"
        bad.write_text("ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
                       + "\n".join("0.0,0.1,100,::1,8080,0,0" for _ in range(12)) + "\n")
        described = manifest.describe_captures(manifest.build_manifest(root))
        broken = described[described["scenario"].eq("injection attack")].iloc[0]
        self.assertEqual(int(broken["rows"]), 12)
        self.assertEqual(int(broken["bad_ts"]), 12)
        self.assertFalse(bool(broken["usable"]))
        whole = described[described["label"].eq("pod-nginx")].iloc[0]
        self.assertEqual(int(whole["rows"]), 30)
        self.assertTrue(bool(whole["usable"]))


def fake_stratum(label="pod-nginx", method="tcp", active=40, windows=60):
    """One fake stratum: benign reference plus a target whose traffic is `active` packets/s."""
    import tempfile
    from pathlib import Path
    root = Path(tempfile.mkdtemp())
    rows = []
    for name, rate in [("benign", 5), ("nginx attack", active)]:
        target = root / name / "csv files" / method / "pod level"
        target.mkdir(parents=True)
        path = target / f"{label}-{method}.csv"
        lines = ["ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst"]
        for window in range(windows):
            for index in range(rate):
                stamp = 1.0 + window + index / rate  # exactly `rate` packets inside each 1 s bin
                lines.append(f"{stamp:.4f},{1.0 / rate:.4f},100,::1,8080,0,0")
        path.write_text("\n".join(lines) + "\n")
        rows.append((name, path))
    return rows


def described_from(rows):
    """The capture-manifest-shaped frame the comparison modules expect."""
    return pd.DataFrame([{"scenario": name, "level": "pod", "label": "pod-nginx",
                          "method": "tcp", "path": str(path)} for name, path in rows])


class SweepChecks(unittest.TestCase):
    def test_run_sweep_flags_a_matched_view_and_spares_benign(self):
        described = described_from(fake_stratum(active=40))
        results = sweep.run_sweep(described)
        attack = results[results["scenario"].eq("nginx attack")].iloc[0]
        benign = results[results["scenario"].eq("benign")].iloc[0]
        self.assertGreater(attack["flagged_fraction"], 0.9)   # 8x rate shift, same view
        self.assertLess(benign["flagged_fraction"], 0.2)       # holdout windows, matched reference
        self.assertEqual(attack["group"], "all")
        self.assertEqual(int(attack["windows"]), 60)

    def test_unusable_capture_is_recorded_not_dropped(self):
        rows = fake_stratum(active=5)
        described = described_from(rows)
        bad_path = rows[1][1]
        bad_path.write_text("ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
                            + "\n".join("0.0,0.05,100,::1,8080,0,0" for _ in range(60)) + "\n")
        results = sweep.run_sweep(described)
        attack = results[results["scenario"].eq("nginx attack")].iloc[0]
        self.assertIn("excluded", attack["note"])
        self.assertEqual(int(attack["windows"]), 0)


class DetectorComparisonChecks(unittest.TestCase):
    def setUp(self):
        self.train = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 10, 11, 9, 10, 10, 11, 12]})
        self.holdout = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 11, 10, 9]})
        self.shifted = pd.DataFrame({"packet_count": [900, 950, 1000, 920, 880, 970, 910, 990, 930]})

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_every_learned_detector_separates_a_shifted_rate_from_held_out_benign(self):
        import iforest_compare
        self.assertEqual(set(iforest_compare.LEARNED_FITTERS), {"isolation_forest", "one_class_svm"})
        for name, fitter in iforest_compare.LEARNED_FITTERS.items():
            with self.subTest(detector=name):
                model = fitter(self.train)
                cutoff = iforest_compare.detector_cutoff(model, self.holdout)
                flagged = iforest_compare.detector_flags(model, self.shifted, cutoff)
                benign = iforest_compare.detector_flags(model, self.holdout, cutoff)
                self.assertGreater(int(flagged.sum()), len(self.shifted) // 2)
                self.assertLessEqual(int(benign.sum()), 1)

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_compare_detectors_scores_every_detector_on_the_same_windows(self):
        import iforest_compare
        comparison = iforest_compare.compare_detectors(described_from(fake_stratum(active=40)))
        self.assertEqual(set(comparison["detector"]),
                         {"z_score", "isolation_forest", "one_class_svm"})
        per_detector = comparison.groupby("detector")["windows"].apply(list)
        self.assertTrue(all(values == per_detector.iloc[0] for values in per_detector),
                        "every detector must see the same windows")
        self.assertEqual(len(comparison), 2 * 3)  # two scenarios x three detectors

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_plot_comparison_writes_a_chart(self):
        import tempfile
        from pathlib import Path
        import iforest_compare
        rows = [{"detector": detector, "scenario": scenario, "label": "pod-nginx", "method": "tcp",
                 "windows": 10, "flagged": 3, "flagged_fraction": 0.3,
                 "persistent": 1, "persistent_fraction": 0.1}
                for scenario in ["benign", "nginx attack"]
                for detector in ["z_score", "isolation_forest", "one_class_svm"]]
        path = Path(tempfile.mkdtemp()) / "chart.png"
        iforest_compare.plot_comparison(pd.DataFrame(rows), path=str(path))
        self.assertGreater(path.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
