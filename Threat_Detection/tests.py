"""Run from this folder with: python -m unittest -v tests"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

import data_io
import sweep
from detectors import build
from features import make_windows, split_reference
from reporting import threshold_table

# The pre-refactor function names, mapped onto their layer homes. The old
# DetectorChecks class pins behavior through these aliases so the assertions read the same
# while the implementation lives in one place. New tests should import the layer directly.
build_baseline = lambda benign: _fit_z(benign)
detect_anomalies = lambda windows, mean, std: _score_z(windows, mean, std)
flag_persistent = lambda results: _persist(results)
make_features = make_windows
split_benign = split_reference
sweep_thresholds = threshold_table


def _fit_z(benign):
    """fit() and the (mean, std) the old build_baseline() returned."""
    detector = build("z_score").fit(benign)
    return detector.mean, detector.std


def _score_z(windows, mean, std):
    """score against a given (mean, std) pair, as the old detect_anomalies() did."""
    detector = build("z_score")
    detector.mean, detector.std = mean, std
    detector.cutoff = detector.threshold
    return detector.annotate(windows)


def _persist(results):
    """annotate() already applies persistence; this is the no-op seam for old tests."""
    return results


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


class DetectorProtocolChecks(unittest.TestCase):
    def setUp(self):
        self.train = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 10, 11, 9, 10, 10, 11, 12]})
        self.holdout = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 11, 10, 9]})
        self.shifted = pd.DataFrame({"packet_count": [900, 950, 1000, 920, 880, 970, 910, 990, 930]})

    def test_registry_covers_the_three_documented_detectors(self):
        import detectors
        self.assertEqual(set(detectors.REGISTRY), {"z_score", "isolation_forest", "one_class_svm"})

    def test_every_detector_flags_a_shift_and_spares_held_out_benign(self):
        import detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                det = make().fit(self.train).calibrate(self.holdout)
                flagged = det.flag(self.shifted)
                benign = det.flag(self.holdout)
                self.assertGreater(int(flagged.sum()), len(self.shifted) // 2)
                self.assertLessEqual(int(benign.sum()), max(1, len(self.holdout) // 8))

    def test_higher_score_means_more_anomalous_for_every_detector(self):
        """sklearn's decision_function runs the other way; the protocol must normalize it."""
        import detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                det = make().fit(self.train).calibrate(self.holdout)
                self.assertGreater(float(det.score(self.shifted).mean()),
                                   float(det.score(self.holdout).mean()),
                                   f"{name} scores the attack lower than benign")

    def test_flagging_before_calibration_is_an_error(self):
        import detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                with self.assertRaises(RuntimeError):
                    make().fit(self.train).flag(self.shifted)

    def test_only_z_score_explains_which_feature_moved(self):
        import detectors
        self.assertIsNotNone(detectors.REGISTRY["z_score"]().explain)
        for name in ("isolation_forest", "one_class_svm"):
            with self.subTest(detector=name):
                self.assertIsNone(detectors.REGISTRY[name]().explain,
                                  "learned detectors report no attribution by design")

    def test_z_score_explain_names_the_feature_and_its_baseline(self):
        import detectors
        # Real baseline spread, so the strongest feature is decided by magnitude, not by a
        # zero-std tie (a zero std scores infinite the moment its feature moves at all).
        reference = pd.DataFrame({"packet_count": [9, 10, 11, 10],
                                  "total_bytes": [90, 100, 110, 100]})
        windows = pd.DataFrame({"packet_count": [10, 10], "total_bytes": [100, 400]})
        det = detectors.build("z_score").fit(reference)
        det.calibrate(reference)
        evidence = det.explain(windows)
        # Window 1 moves total_bytes far and packet_count not at all -> total_bytes is named.
        # Window 0 changes neither feature, so every z is 0 and idxmax reports the first
        # column; that is the documented tie-break, not a detection decision.
        self.assertEqual(evidence["top_feature"].tolist(), ["packet_count", "total_bytes"])
        # expected_mean/std follow the feature named for THAT window, not one fixed feature.
        self.assertEqual(evidence["expected_mean"].tolist(), [10.0, 100.0])
        self.assertEqual(evidence["observed_value"].tolist(), [10, 400])
        self.assertAlmostEqual(float(evidence["feature_z_score"].iloc[0]), 0.0)

    def test_persistence_needs_consecutive_flags(self):
        """A run of L flags marks its last L-1: the first flag of a run is not yet an alert."""
        import detectors
        flags = pd.Series([False, True, True, True, True, False])
        self.assertEqual(detectors.persistent_mask(flags).tolist(),
                         [False, False, False, True, True, False])
        # a run of exactly PERSISTENCE_WINDOW marks only its final window
        exact = pd.Series([True, True, True, False, False])
        self.assertEqual(detectors.persistent_mask(exact).tolist(),
                         [False, False, True, False, False])

    def test_insufficient_baseline_is_rejected(self):
        import detectors
        for name in detectors.REGISTRY:
            with self.subTest(detector=name), self.assertRaisesRegex(ValueError, "Insufficient"):
                detectors.build(name).fit(pd.DataFrame({"packet_count": [1]}))


class FeatureLayerChecks(unittest.TestCase):
    def test_features_module_does_not_import_local_paths(self):
        script = "import sys; sys.path.insert(0, '.'); import features; print(features.WINDOW_SIZE)"
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_windows_keep_empty_seconds_and_leave_averages_undefined(self):
        import features
        packets = pd.DataFrame({"ts": [10.0, 12.0], "frame_len": [100, 200], "iat": [0.0, 2.0],
                                "dst_ip": ["a", "b"], "dst_port": [80, 443], "tcp_syn": [1, 0]})
        windows = features.make_windows(packets)
        self.assertEqual(windows.index.tolist(), [0, 1, 2])
        self.assertEqual(windows.loc[1, "packet_count"], 0)
        self.assertEqual(windows.loc[1, "total_bytes"], 0)
        self.assertEqual(windows.loc[1, "syn_count"], 0)
        self.assertTrue(pd.isna(windows.loc[1, "mean_packet_size"]))
        self.assertTrue(pd.isna(windows.loc[1, "mean_iat"]))
        self.assertEqual(windows.loc[0, "unique_dst_ips"], 1)
        # tcp_rst is absent from this frame, so no rst_count column is invented.
        self.assertNotIn("rst_count", windows.columns)

    def test_flag_features_appear_when_the_columns_are_present(self):
        import features
        packets = pd.DataFrame({"ts": [10.0, 10.5], "frame_len": [100, 200], "iat": [0.0, 0.5],
                                "dst_ip": ["a", "b"], "dst_port": [80, 443],
                                "tcp_syn": [1, 0], "tcp_rst": [0, 1]})
        windows = features.make_windows(packets)
        self.assertEqual(windows.loc[0, "syn_count"], 1)
        self.assertEqual(windows.loc[0, "rst_count"], 1)

    def test_feature_groups_cover_every_feature_exactly_once(self):
        import features
        grouped = {f for members in features.FEATURE_GROUPS.values() for f in members}
        self.assertEqual(grouped, set(features.FEATURE_LABELS))

    def test_split_reference_holds_out_the_last_thirty_percent(self):
        import features
        windows = pd.DataFrame({"packet_count": range(100)})
        reference, holdout = features.split_reference(windows)
        self.assertEqual(len(reference), 70)
        self.assertEqual(len(holdout), 30)
        self.assertEqual(holdout.index.tolist(), list(range(70, 100)))


class DataIoChecks(unittest.TestCase):
    def test_io_layer_does_not_need_local_paths(self):
        """data_io must import with no machine-specific path file present."""
        script = ("import sys; sys.path.insert(0, '.');"
                  " import data_io; print(len(data_io.PACKET_COLUMNS))")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_load_capture_normalizes_headers_and_keeps_needed_columns(self):
        import tempfile
        import data_io
        path = Path(tempfile.mkdtemp()) / "pod-nginx-tcp.csv"
        path.write_text("TS ,IAT,Frame Len,Dst IP,Dst Port,TCP SYN,TCP RST\n"
                        "10.0,0.1,100,::1,8080,1,0\n")
        frame = data_io.load_capture(str(path))
        self.assertEqual(list(frame.columns), data_io.PACKET_COLUMNS)
        self.assertEqual(int(frame.iloc[0]["tcp_syn"]), 1)

    def test_load_capture_names_a_missing_column(self):
        import tempfile
        import data_io
        path = Path(tempfile.mkdtemp()) / "pod-nginx-tcp.csv"
        path.write_text("ts,iat,frame_len,dst_ip,dst_port\n10.0,0.1,100,::1,8080\n")
        with self.assertRaisesRegex(ValueError, "Missing packet columns"):
            data_io.load_capture(str(path))

    def test_output_path_is_anchored_to_the_module_not_the_cwd(self):
        import data_io
        self.assertTrue(data_io.OUTPUT_DIR.is_absolute())
        self.assertEqual(data_io.OUTPUT_DIR.parent, Path(data_io.__file__).resolve().parent)


class DatasetChecks(unittest.TestCase):
    def test_parse_capture_keeps_label_and_method(self):
        self.assertEqual(data_io.parse_capture("pod-nginx-tcp.csv"), ("pod-nginx", "tcp"))
        self.assertEqual(data_io.parse_capture("/x/y/pod-robot-controller-ptcp.csv"),
                         ("pod-robot-controller", "ptcp"))
        with self.assertRaises(ValueError):
            data_io.parse_capture("router-any.csv")

    def test_level_comes_from_the_label_prefix(self):
        self.assertEqual(data_io.level_from_label("pod-lidar"), "pod")
        self.assertEqual(data_io.level_from_label("node-gchild9"), "node")
        self.assertEqual(data_io.level_from_label("router-flannel"), "router")
        with self.assertRaises(ValueError):
            data_io.level_from_label("child4")

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
        frame = data_io.build_manifest(self._tree())
        self.assertEqual(len(frame), 3)
        self.assertEqual(frame["scenario"].tolist(), ["benign", "benign", "injection attack"])
        self.assertEqual(set(frame["level"]), {"pod", "router"})
        self.assertEqual(set(frame["method"]), {"tcp", "ptcp"})

    def test_describe_captures_counts_packets_and_flags_bad_timebase(self):
        root = self._tree()
        bad = root / "injection attack" / "csv files" / "pod-nginx-tcp.csv"
        bad.write_text("ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
                       + "\n".join("0.0,0.1,100,::1,8080,0,0" for _ in range(12)) + "\n")
        described = data_io.describe_captures(data_io.build_manifest(root))
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


class FeatureValueChecks(unittest.TestCase):
    def test_auc_and_budget_detection_behave(self):
        import feature_value
        self.assertEqual(feature_value.separation_auc([1, 2, 3], [4, 5, 6]), 1.0)
        self.assertEqual(feature_value.separation_auc([4, 5, 6], [1, 2, 3]), 0.0)
        self.assertEqual(feature_value.separation_auc([1, 2, 3], [1, 2, 3]), 0.5)
        self.assertTrue(pd.isna(feature_value.separation_auc([1], [2])))
        # a clean shift is flagged; attack windows that look benign are not
        benign = list(range(100, 120))
        self.assertGreater(feature_value.detection_at_budget(benign, benign, [1000, 1050, 1100]), 0.9)
        self.assertLess(feature_value.detection_at_budget(benign, benign, benign[8:11]), 0.5)


class DetectorComparisonChecks(unittest.TestCase):
    def setUp(self):
        self.train = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 10, 11, 9, 10, 10, 11, 12]})
        self.holdout = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 11, 10, 9]})
        self.shifted = pd.DataFrame({"packet_count": [900, 950, 1000, 920, 880, 970, 910, 990, 930]})

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_every_learned_detector_separates_a_shifted_rate_from_held_out_benign(self):
        import detectors
        learned = [name for name in detectors.REGISTRY if name != "z_score"]
        self.assertEqual(set(learned), {"isolation_forest", "one_class_svm"})
        for name in learned:
            with self.subTest(detector=name):
                detector = detectors.build(name).pipeline(self.train, self.holdout)
                flagged = detector.flag(self.shifted)
                benign = detector.flag(self.holdout)
                self.assertGreater(int(flagged.sum()), len(self.shifted) // 2)
                self.assertLessEqual(int(benign.sum()), 1)

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_compare_detectors_scores_every_detector_on_the_same_windows(self):
        import compare
        comparison = compare.compare_detectors(described_from(fake_stratum(active=40)))
        self.assertEqual(set(comparison["detector"]),
                         {"z_score", "isolation_forest", "one_class_svm"})
        per_detector = comparison.groupby("detector")["windows"].apply(list)
        self.assertTrue(all(values == per_detector.iloc[0] for values in per_detector),
                        "every detector must see the same windows")
        self.assertEqual(len(comparison), 2 * 3)  # two scenarios x three detectors

    def test_chart_name_carries_the_svm_nu(self):
        import inspect
        import detectors
        import data_io
        import reporting
        # the SVM default and the chart filename must both follow the one constant
        self.assertEqual(detectors.SVM_NU,
                         inspect.signature(detectors.OneClassSvmDetector).parameters["nu"].default)
        # Let plot_comparison build its own default name, but redirect OUTPUT_DIR into a
        # temp dir so the test cannot overwrite outputs/detector_comparison_nu0.1.png.
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            original, data_io.OUTPUT_DIR = data_io.OUTPUT_DIR, Path(folder)
            try:
                written = reporting.plot_comparison(self._rows())
            finally:
                data_io.OUTPUT_DIR = original
            self.assertEqual(Path(written).name, f"detector_comparison_nu{detectors.SVM_NU:g}.png")
            self.assertNotEqual(Path(written).name, "detector_comparison.png")

    def _rows(self):
        return pd.DataFrame([
            {"detector": d, "scenario": s, "label": "pod-nginx", "method": "tcp",
             "windows": 10, "flagged": 3, "flagged_fraction": 0.3,
             "persistent": 1, "persistent_fraction": 0.1}
            for d in ("z_score", "isolation_forest", "one_class_svm")
            for s in ("benign", "nginx attack")])

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_plot_comparison_writes_a_chart(self):
        import tempfile
        from pathlib import Path
        import compare
        rows = [{"detector": detector, "scenario": scenario, "label": "pod-nginx", "method": "tcp",
                 "windows": 10, "flagged": 3, "flagged_fraction": 0.3,
                 "persistent": 1, "persistent_fraction": 0.1}
                for scenario in ["benign", "nginx attack"]
                for detector in ["z_score", "isolation_forest", "one_class_svm"]]
        path = Path(tempfile.mkdtemp()) / "chart.png"
        compare.plot_comparison(pd.DataFrame(rows), path=str(path))
        self.assertGreater(path.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()