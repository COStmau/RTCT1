"""Run from this folder with: python -m unittest -v tests"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

import data_io
import demo
import evaluation
import features
import flag_scores
import flag_verdict
import reporting
import statemachine
import sweep
from detectors import build
from features import make_windows, split_reference
from reporting import plot_detection_gap, threshold_table, to_events, write_events

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


def _score_z(windows, mean, std, cutoff=None):
    """score against a given (mean, std) pair, as the old detect_anomalies() did.

    `cutoff` defaults to the module threshold; a fixture whose values sit near that
    threshold passes its own, so changing the constant cannot flip its expectations.
    """
    detector = build("z_score")
    detector.mean, detector.std = mean, std
    detector.cutoff = detector.threshold if cutoff is None else cutoff
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
        # Windows are [2 packets, 0 packets, 1 packet], so the centre is the median (1.0),
        # not the mean (0.667). The detector's baseline is robust by design.
        self.assertEqual(mean["packet_count"], 1.0)
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
        # Its own cutoff: at 5 spreads the packet_count of 2 (z = -3) stays normal, so
        # the fixture tests the persistence rule rather than where the constant sits.
        out = flag_persistent(_score_z(features, mean, std, cutoff=5.0))
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

    def test_z_score_uses_a_robust_baseline_for_a_lopsided_baseline(self):
        """A baseline with a few enormous windows must not turn ordinary held-out seconds into flags.

        Mean/std is the wrong summary when 8 of 47 benign windows carry the whole dynamic
        range: the standard deviation is set by those windows, so a window near either mode
        lands outside the cutoff and a third of held-out benign traffic flags. Median/MAD
        ignores them. This is the router-any shape.
        """
        import detectors
        # 40 quiet windows at 50, one 146 MB window, 6 held-out windows near the quiet mode.
        reference = pd.DataFrame({"payload_bytes": [50.0] * 40 + [146_000_000.0] + [50.0] * 6})
        detector = detectors.build("z_score").fit(reference).calibrate(reference)
        quiet = detector.annotate(reference.tail(6))
        self.assertEqual(int(quiet["anomaly"].sum()), 0,
                         "held-out windows in the dominant mode must not flag")
        bulk = detector.annotate(pd.DataFrame({"payload_bytes": [146_000_000.0]}))
        self.assertEqual(int(bulk["anomaly"].sum()), 1,
                         "the bulk-transfer window is still the thing that flags")

    def test_constant_feature_is_marked_degenerate_and_does_not_flag_everything(self):
        """MAD is 0 for a constant feature, and dividing by that 0 would flag every window."""
        import detectors
        reference = pd.DataFrame({"packet_count": [3.0] * 12})
        detector = detectors.build("z_score").fit(reference).calibrate(reference)
        # A constant feature has no scale, so it IS degenerate -- recorded, not hidden.
        self.assertTrue(bool(detector.degenerate["packet_count"]))
        same = detector.annotate(pd.DataFrame({"packet_count": [3.0]}))
        self.assertEqual(int(same["anomaly"].sum()), 0,
                         "an unchanged window on a constant feature is not a flag")
        moved = detector.annotate(pd.DataFrame({"packet_count": [9.0]}))
        self.assertEqual(int(moved["anomaly"].sum()), 1,
                         "movement on a scale-less feature is infinitely far from normal")

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

    def test_payload_and_protocol_features_are_summed_per_window(self):
        """Payload and app-protocol columns are read on purpose; the 34-column set is a pool."""
        import features
        # Two packets inside bin 0 (ts 10.0, 10.5) and one in bin 1 (ts 11.0).
        packets = pd.DataFrame({
            "ts": [10.0, 10.5, 11.0], "frame_len": [100, 200, 300],
            "iat": [0.0, 0.5, 0.5], "dst_ip": ["a", "b", "c"], "dst_port": [80, 53, 80],
            "tcp_syn": [1, 0, 0], "tcp_rst": [0, 1, 0],
            "tcp_payload_len": [40.0, np.nan, 80.0],
            "is_http": [1, 0, 1], "is_dns": [0, 1, 0], "is_https": [0, 0, 0]})
        windows = features.make_windows(packets)
        self.assertEqual(windows.loc[0, "packet_count"], 2)
        # Bin 0 holds only the first packet, so payload is 40.0, not 120.0. min_count=1 means
        # the NaN in the second packet's payload is skipped, not treated as zero-and-counted.
        self.assertEqual(windows.loc[0, "payload_bytes"], 40.0)
        self.assertEqual(windows.loc[1, "payload_bytes"], 80.0)
        self.assertEqual(windows.loc[0, "http_count"], 1)
        self.assertEqual(windows.loc[1, "http_count"], 1)
        self.assertEqual(windows.loc[0, "dns_count"], 1)
        self.assertEqual(windows.loc[1, "dns_count"], 0)
        # Protocol mix as a share of the window's packets, so it is comparable across vantages.
        self.assertEqual(windows.loc[0, "http_frac"], 0.5)
        self.assertEqual(windows.loc[1, "http_frac"], 1.0)
        # An empty second keeps zero counts and no invented averages. ts 10.0 and 12.0 leave
        # bin 1 with no packets at all.
        empty = features.make_windows(pd.DataFrame({
            "ts": [10.0, 12.0], "frame_len": [100, 100], "iat": [0.0, 2.0],
            "dst_ip": ["a", "a"], "dst_port": [80, 80],
            "tcp_syn": [0, 0], "tcp_rst": [0, 0], "tcp_payload_len": [40.0, 40.0],
            "is_http": [1, 1], "is_dns": [0, 0], "is_https": [0, 0]}))
        self.assertEqual(empty.loc[1, "packet_count"], 0)
        self.assertEqual(empty.loc[1, "payload_bytes"], 0.0)
        self.assertEqual(empty.loc[1, "http_count"], 0)
        self.assertTrue(pd.isna(empty.loc[1, "mean_packet_size"]))

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
        path.write_text("TS ,IAT,Frame Len,Dst IP,Dst Port,TCP SYN,TCP RST,tcp_payload_len,is_http\n"
                        "10.0,0.1,100,::1,8080,1,0,40,1\n")
        frame = data_io.load_capture(str(path))
        # Every column present is read; the ones this file lacks are simply absent.
        self.assertEqual(list(frame.columns),
                         data_io.PACKET_REQUIRED + ["tcp_payload_len", "is_http"])
        self.assertEqual(int(frame.iloc[0]["tcp_syn"]), 1)
        self.assertEqual(float(frame.iloc[0]["tcp_payload_len"]), 40.0)

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


class ManifestChecks(unittest.TestCase):
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

    def test_snaplen_ceiling_is_reported_not_silently_scored(self):
        """A truncated capture stays usable, but its saturation is stated for the reader."""
        root = self._tree()
        capped = root / "benign" / "csv files" / "tcp" / "pod level" / "pod-nginx-tcp.csv"
        capped.write_text("ts,iat,frame_len,dst_ip,dst_port,tcp_syn,tcp_rst\n"
                          + "\n".join(f"{10.0 + i},0.1,65555,::1,8080,0,0" for i in range(30)) + "\n")
        packets = data_io.load_capture(str(capped))
        issues = data_io.timebase_issues(packets)
        self.assertEqual(issues["at_snaplen"], 1.0)
        self.assertTrue(issues["usable"], "a snaplen wall does not make a capture unscorable")
        described = data_io.describe_captures(data_io.build_manifest(root))
        row = described[described["label"].eq("pod-nginx")].iloc[0]
        self.assertEqual(float(row["at_snaplen"]), 1.0)

    def test_ordinary_capture_reports_no_saturation(self):
        issues = data_io.timebase_issues(data_io.load_capture(
            str(self._tree() / "benign" / "csv files" / "tcp" / "pod level" / "pod-nginx-tcp.csv")))
        self.assertEqual(issues["at_snaplen"], 0.0)

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

    def test_detection_gap_is_relative_to_each_captures_own_benign(self):
        """The cell is the gap, not the raw fraction: a noisy vantage cannot win on volume."""
        import tempfile

        import matplotlib.pyplot as plt
        results = pd.DataFrame([
            {"group": "all", "method": "tcp", "label": "noisy", "scenario": "benign",
             "windows": 20, "flagged_fraction": 0.90},
            {"group": "all", "method": "tcp", "label": "noisy", "scenario": "nginx attack",
             "windows": 30, "flagged_fraction": 0.95},
            {"group": "all", "method": "tcp", "label": "quiet", "scenario": "benign",
             "windows": 20, "flagged_fraction": 0.10},
            {"group": "all", "method": "tcp", "label": "quiet", "scenario": "nginx attack",
             "windows": 30, "flagged_fraction": 0.80},
        ])
        close, plt.close = plt.close, lambda *args, **kwargs: None
        try:
            path = Path(tempfile.mkdtemp()) / "gap.png"
            plot_detection_gap(results, path=str(path))
            fig = plt.gcf()
            fig.canvas.draw()
            cells = [text.get_text() for text in fig.axes[0].texts]
        finally:
            plt.close = close
        self.assertEqual(path.stat().st_size > 1000, True)
        self.assertIn("+0.05\n30 windows", cells)   # 0.95 against its own 0.90: barely above
        self.assertIn("+0.70\n30 windows", cells)   # 0.80 against its own 0.10: clearly above

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


class ShowcaseReportChecks(unittest.TestCase):
    """The showcase report must be one file: real numbers, real images, nothing padded."""

    def _sweep(self):
        return pd.DataFrame([
            {"group": "all", "scenario": "benign", "label": "pod-nginx", "method": "tcp",
             "windows": 100, "flagged": 30, "persistent": 10, "flagged_fraction": 0.30,
             "peak_score": 4.1, "top_feature": "total_bytes", "note": ""},
            {"group": "all", "scenario": "benign", "label": "router-any", "method": "tcp",
             "windows": 100, "flagged": 90, "persistent": 70, "flagged_fraction": 0.90,
             "peak_score": 9.0, "top_feature": "total_bytes", "note": ""},
            {"group": "all", "scenario": "benign", "label": "pod-nginx", "method": "ptcp",
             "windows": 100, "flagged": 32, "persistent": 11, "flagged_fraction": 0.32,
             "peak_score": 4.0, "top_feature": "total_bytes", "note": ""},
            {"group": "all", "scenario": "benign", "label": "router-any", "method": "ptcp",
             "windows": 100, "flagged": 92, "persistent": 72, "flagged_fraction": 0.92,
             "peak_score": 9.2, "top_feature": "total_bytes", "note": ""},
            {"group": "all", "scenario": "injection attack", "label": "pod-nginx",
             "method": "tcp", "windows": 100, "flagged": 66, "persistent": 45,
             "flagged_fraction": 0.66, "peak_score": 12.0, "top_feature": "total_bytes",
             "note": ""},
            {"group": "all", "scenario": "nginx attack", "label": "pod-nginx", "method": "tcp",
             "windows": 100, "flagged": 60, "persistent": 40, "flagged_fraction": 0.60,
             "peak_score": 8.0, "top_feature": "http_count", "note": ""},
        ])

    def _ablation(self):
        rows = []
        for group in ("volume", "size_timing", "diversity", "flags", "protocol"):
            for scenario in ("benign", "injection attack", "lidar attack", "nginx attack"):
                for label in ("pod-nginx", "router-any"):
                    for method in ("tcp", "ptcp"):
                        rows.append({
                            "group": group, "scenario": scenario, "label": label,
                            "method": method, "windows": 100, "flagged": 20, "persistent": 5,
                            "flagged_fraction": 0.20, "peak_score": 4.0,
                            "top_feature": "total_bytes", "note": "",
                        })
        return pd.DataFrame(rows)

    def _manifest(self):
        return pd.DataFrame([
            {"scenario": "benign", "level": "pod", "label": "pod-nginx", "method": "tcp",
             "path": "a.csv", "rows": 1000, "bad_ts": 0, "span_s": 100.0,
             "at_snaplen": 0.0, "usable": True},
            {"scenario": "benign", "level": "router", "label": "router-any", "method": "tcp",
             "path": "b.csv", "rows": 1000, "bad_ts": 0, "span_s": 100.0,
             "at_snaplen": 0.59, "usable": True},
        ])

    def _comparison(self):
        return pd.DataFrame([
            {"detector": detector, "scenario": scenario, "label": "pod-nginx", "method": "tcp",
             "windows": 100, "flagged": 20, "flagged_fraction": 0.20, "persistent": 5,
             "persistent_fraction": 0.05}
            for detector in ("z_score", "one_class_svm", "isolation_forest")
            for scenario in ("benign", "injection attack", "lidar attack", "nginx attack")])

    def _write(self, folder, **overrides):
        from reporting import write_report
        frames = {"sweep": self._sweep(), "ablation": self._ablation(),
                  "manifest": self._manifest(), "comparison": self._comparison()}
        frames.update(overrides)
        # folder=None exercises the default chart_dir; otherwise write into that folder.
        chart_dir = Path(folder) if folder is not None else None
        return Path(write_report(chart_dir=chart_dir, **frames))

    def test_report_is_a_markdown_file_whose_every_image_exists(self):
        import re
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = self._write(folder)
            self.assertTrue(path.exists(), "write_report must create the markdown file")
            text = path.read_text()
            refs = re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)
            self.assertGreaterEqual(len(refs), 4, f"expected the core chart set, got {refs}")
            for ref in refs:
                self.assertTrue((path.parent / ref).exists(), f"missing image on disk: {ref}")

    def test_report_has_no_placeholders_or_stray_nulls(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            text = self._write(folder).read_text()
            for junk in ("TODO", "None", "nan", "NaN"):
                self.assertNotIn(junk, text, f"placeholder {junk!r} leaked into the report")

    def test_report_numbers_follow_the_data(self):
        """Change a fixture number; the report text must change with it."""
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            before = self._write(folder).read_text()
        sweep = self._sweep()
        sweep.loc[sweep["label"] == "pod-nginx", "flagged_fraction"] = 0.42
        with tempfile.TemporaryDirectory() as folder:
            after = self._write(folder, sweep=sweep).read_text()
        self.assertNotEqual(before, after, "report text must follow the data, not constants")

    def test_report_defaults_to_the_output_directory(self):
        """chart_dir=None must land in outputs/, not on top of a file."""
        import data_io
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            original, data_io.OUTPUT_DIR = data_io.OUTPUT_DIR, Path(folder)
            try:
                path = self._write(None)
            finally:
                data_io.OUTPUT_DIR = original
            # resolve_output() with no name is the manifest path; the report must use its
            # parent, or mkdir walks into a file and the run dies with FileExistsError.
            self.assertEqual(path.parent, Path(folder))
            self.assertEqual(path.name, "SHOWCASE.md")
            self.assertTrue((Path(folder) / "steady_bulk_split.png").exists())

    def test_report_states_the_correction_and_never_the_retracted_claim(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            text = self._write(folder).read_text().lower()
            self.assertIn("bulk", text, "the regime-change finding must be stated")
            self.assertIn("steady", text, "the steady captures must be counted separately")
            # The retracted version asserted per-vantage calibration was still needed. The
            # report must argue the opposite, and must not repeat the old numbers.
            self.assertNotIn("needs calibrating", text)
            self.assertNotIn("still needs", text)
            self.assertIn("per-vantage cutoff would suppress", text)


class WindowedScorerChecks(unittest.TestCase):
    """The expiring clock: visits leave the window, so a burst stops scoring as a burst."""

    def setUp(self):
        self.pdfa = statemachine.learn_pdfa(
            [("a", "b", "c")] * 12 + [("a", "b", "b")] * 12 + [("c", "a")] * 12)

    def stream(self, score, burst):
        """Quiet ("c", "a") every second for 20 s, with ("a", "b", "b") x5 per second in 4-7 s.

        `score(trace, when)`; the cumulative scorer ignores `when`.
        """
        scores = []
        for second in range(20):
            if burst and 4 <= second < 8:
                for offset in range(5):
                    score(("a", "b", "b"), second + offset / 10)
            scores.append(score(("c", "a"), second + 0.9))
        return scores

    def windowed(self, forget):
        return statemachine.WindowedFrequencyScorer(self.pdfa, forget).score

    def cumulative(self):
        scorer = statemachine.FrequencyScorer(self.pdfa)
        return lambda trace, when: scorer.score(trace)

    def test_infinite_window_is_cumulative_sequent(self):
        traces = [("a", "b", "c"), ("a", "b", "b"), ("c", "a"), ("a", "b", "c"),
                  ("a", "c", "b"), ("b", "b", "a")] * 5
        cumulative = statemachine.FrequencyScorer(self.pdfa)
        windowed = statemachine.WindowedFrequencyScorer(self.pdfa, float("inf"))
        self.assertEqual([cumulative.score(trace) for trace in traces],
                         [windowed.score(trace, float(when)) for when, trace in enumerate(traces)])

    def test_score_returns_exactly_to_baseline_after_the_window(self):
        forget = 4.0
        control = self.stream(self.windowed(forget), False)
        burst = self.stream(self.windowed(forget), True)
        self.assertGreater(max(burst[4:8]), max(control[4:8]))     # the burst scores higher
        # last burst visit is at 7.4 s; from 7.4 + 4 = 11.4 s it has left the window
        self.assertEqual(burst[12:], control[12:])

    def test_cumulative_score_never_returns_to_baseline(self):
        control = self.stream(self.cumulative(), False)
        burst = self.stream(self.cumulative(), True)
        self.assertTrue(all(b > c for b, c in zip(burst[12:], control[12:])))

    def test_window_is_in_seconds_not_in_traces(self):
        scorer = statemachine.WindowedFrequencyScorer(self.pdfa, forget_seconds=2.0)
        scorer.score(("a", "b", "b"), when=0.0)
        scorer.score(("a", "b", "b"), when=2.0)               # 0.0 is still inside [0, 2]
        self.assertEqual(sum(scorer.counts.values()), 6)
        scorer.score(("c", "a"), when=5.0)                    # both earlier traces expire
        self.assertEqual(sum(scorer.counts.values()),
                         len(statemachine.trace_states(self.pdfa, ("c", "a"))))

    def test_rejects_out_of_order_traces_and_empty_windows(self):
        scorer = statemachine.WindowedFrequencyScorer(self.pdfa, forget_seconds=2.0)
        scorer.score(("c", "a"), when=3.0)
        with self.assertRaises(ValueError):
            scorer.score(("c", "a"), when=1.0)
        with self.assertRaises(ValueError):
            statemachine.WindowedFrequencyScorer(self.pdfa, forget_seconds=0)

    def test_default_window_is_the_module_constant(self):
        scorer = statemachine.WindowedFrequencyScorer(self.pdfa)
        self.assertEqual(scorer.forget_seconds, statemachine.FORGET_SECONDS)

    def flows(self, burst):
        """One request/response pair per second for 30 s; a flood repeats it 6x in 10-13 s.

        The flood is the benign pattern hammered, not a new one: SEQUENT's score rises with
        visits to known states, and a novel sequence walks fewer states and scores lower.
        """
        rows = []
        for second in range(30):
            pairs = 6 if burst and 10 <= second < 14 else 1
            for pair in range(pairs):
                start = second + 0.1 + pair / 8
                rows += [{"start_ts": start, "bytes": 200, "duration": 0.01, "proto": "tcp"},
                         {"start_ts": start + 0.05, "bytes": 300, "duration": 0.02,
                          "proto": "tcp"}]
        return pd.DataFrame(rows)

    def test_per_window_scores_clear_where_cumulative_never_does(self):
        model = statemachine.fit_model(self.flows(burst=False))
        forget = statemachine.FORGET_SECONDS
        scores = {(name, burst): statemachine.frequency_scores_by_window(
                      model, self.flows(burst), 0.0, 30, forget_seconds=window)
                  for name, window in (("cumulative", None), ("windowed", forget))
                  for burst in (False, True)}
        self.assertGreater(scores["windowed", True][12], scores["windowed", False][12])
        # last burst flow starts before 14 s, so from window 14 + 8 = 22 on it has expired
        np.testing.assert_array_equal(scores["windowed", True][22:],
                                      scores["windowed", False][22:])
        self.assertTrue((scores["cumulative", True][22:]
                         > scores["cumulative", False][22:]).all())
        # two flows a second and five-flow traces: no trace has ended inside window 0 or 1
        self.assertTrue(np.isnan(scores["windowed", False][:2]).all())
        self.assertTrue(np.isfinite(scores["windowed", False][2:]).all())


class StateMachineChecks(unittest.TestCase):
    def flow_packets(self):
        return pd.DataFrame({
            "ts": [10.0, 10.5, 12.0, 12.2, 12.9],
            "frame_len": [100, 200, 150, 150, 150],
            "src_ip": ["a", "a", "c", "c", "c"],
            "dst_ip": ["b", "b", "d", "d", "d"],
            "src_port": [1, 1, 2, 2, 2],
            "dst_port": [80, 80, 443, 443, 443],
            "proto": ["tcp", "tcp", "tcp", "tcp", "tcp"],
        })

    def test_make_flows_groups_by_five_tuple(self):
        flows = statemachine.make_flows(self.flow_packets())
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows.iloc[0]["bytes"], 300)
        self.assertAlmostEqual(flows.iloc[0]["duration"], 0.5)
        self.assertTrue((flows["start_ts"].diff().dropna() >= 0).all())

    def test_segment_flows_drops_flows_crossing_a_window_boundary(self):
        flows = pd.DataFrame({
            "start_ts": [10.0, 10.1, 10.9, 10.0],
            "bytes": [100, 100, 100, 100],
            "duration": [1.0, 0.5, 0.3, 2.0],
            "proto": ["tcp"] * 4,
        })
        kept, dropped = statemachine.segment_flows(flows, t0=10.0)
        # Ending exactly on a boundary stays; anything reaching past it does not.
        self.assertEqual(list(kept["duration"]), [1.0, 0.5])
        self.assertEqual(dropped, 2)

    def test_score_pair_drops_crossing_flows_before_symbolizing(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        header = "ts,frame_len,src_ip,dst_ip,src_port,dst_port,proto\n"
        # One long flow spans the whole capture; the rest fit inside their seconds.
        lines = [header, "10.0,100,::1,::2,9999,8080,tcp\n", "70.0,100,::1,::2,9999,8080,tcp\n"]
        lines += [f"{10.0 + w + i / 5:.4f},100,::1,::2,{1000 + w},8080,tcp\n"
                  for w in range(30) for i in range(5)]
        benign = root / "benign.csv"
        benign.write_text("".join(lines))
        benign_flags, _ = statemachine.score_pair(str(benign), str(benign))
        self.assertEqual(len(benign_flags), 61)

    def test_frequency_score_does_not_depend_on_chunk_boundaries(self):
        """One windowed scorer for the stream equals a fresh scorer per chunk.

        The windowed score depends only on the traces inside the trailing window, so a scorer
        started at any chunk boundary and warmed with the previous FORGET_SECONDS of traces
        returns bit-identical scores. Memory is bounded by the window, not the stream.
        """
        traces = [("a", "b", "c"), ("a", "b", "c"), ("a", "c", "b"),
                  ("b", "a", "c"), ("a", "b", "b"), ("a", "b", "c")] * 10
        times = [0.5 * index for index in range(len(traces))]
        pdfa = statemachine.learn_pdfa(traces[:6])
        forget = 4.0
        stream = statemachine.WindowedFrequencyScorer(pdfa, forget)
        whole = [stream.score(trace, when) for trace, when in zip(traces, times)]
        for chunk in (1, 7, 13):
            per_chunk = []
            for start in range(0, len(traces), chunk):
                scorer = statemachine.WindowedFrequencyScorer(pdfa, forget)
                for trace, when in zip(traces[:start], times[:start]):
                    if when >= times[start] - forget:      # warm-up: the trailing window only
                        scorer.score(trace, when)
                per_chunk += [scorer.score(trace, when) for trace, when in
                              zip(traces[start:start + chunk], times[start:start + chunk])]
            with self.subTest(chunk=chunk):
                self.assertEqual(whole, per_chunk)
        self.assertLessEqual(len(stream.visits), 3 * (forget / 0.5 + 1))

    def test_load_flow_packets_reads_flags_only_when_asked(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        header = ("ts,frame_len,src_ip,dst_ip,src_port,dst_port,proto,"
                  "tcp_syn,tcp_rst\n")
        path = root / "one.csv"
        path.write_text(header + "10.0,100,::1,::2,1000,80,tcp,1,0\n")
        plain = statemachine.load_flow_packets(str(path))
        with_flags = statemachine.load_flow_packets(str(path), flags=True)
        self.assertNotIn("tcp_syn", plain.columns)
        self.assertIn("tcp_syn", with_flags.columns)
        self.assertIn("tcp_rst", with_flags.columns)

    def test_make_flows_marks_flag_presence_per_flow(self):
        packets = pd.DataFrame({
            "ts": [10.0, 10.2, 11.0],
            "frame_len": [100, 100, 100],
            "src_ip": ["a", "a", "c"], "dst_ip": ["b", "b", "d"],
            "src_port": [1, 1, 2], "dst_port": [80, 80, 443],
            "proto": ["tcp", "tcp", "tcp"],
            "tcp_syn": [1, 0, 0], "tcp_rst": [0, 1, 0],
        })
        flows = statemachine.make_flows(packets)
        self.assertEqual(list(flows["syn_seen"]), [True, False])
        self.assertEqual(list(flows["rst_seen"]), [True, False])

    def test_encode_adds_flag_bits_only_for_tcp_when_asked(self):
        flows = pd.DataFrame({"proto": ["tcp", "tcp", "udp"],
                              "bytes": [10, 900, 50],
                              "duration": [0.1, 0.2, 0.1],
                              "syn_seen": [True, False, False],
                              "rst_seen": [False, True, False]})
        plain = statemachine.fit_percentile(flows)
        with_flags = statemachine.fit_percentile(flows, flags=True)
        plain_symbols = list(statemachine.encode(flows, plain))
        flag_symbols = list(statemachine.encode(flows, with_flags))
        self.assertEqual(len(plain_symbols[0].split("_")), 3)
        self.assertTrue(flag_symbols[0].startswith("tcp_s1r0_p"))
        self.assertTrue(flag_symbols[1].startswith("tcp_s0r1_p"))
        # UDP has no flags; its symbol stays three-part so its alphabet does not grow.
        self.assertTrue(flag_symbols[2].startswith("udp_p"))
        self.assertEqual(len(flag_symbols[2].split("_")), 3)

    def test_encode_refuses_flags_when_flows_have_none(self):
        flows = pd.DataFrame({"proto": ["tcp"], "bytes": [10], "duration": [0.1]})
        enc = statemachine.fit_percentile(flows, flags=True)
        with self.assertRaises(ValueError):
            statemachine.encode(flows, enc)

    def test_fit_model_carries_the_flag_setting(self):
        flows = pd.DataFrame({"proto": ["tcp"] * 6, "bytes": range(6),
                              "duration": [0.1] * 6,
                              "syn_seen": [True] * 6, "rst_seen": [False] * 6})
        self.assertTrue(statemachine.fit_model(flows, flags=True)["enc"]["flags"])
        self.assertFalse(statemachine.fit_model(flows)["enc"]["flags"])

    def test_percentile_encoding_separates_small_from_large(self):
        train = pd.DataFrame({"proto": ["tcp"] * 4, "bytes": [10, 20, 30, 40],
                              "duration": [0.1] * 4})
        enc = statemachine.fit_percentile(train, nbins=2)
        symbols = statemachine.encode(train, enc)
        self.assertNotEqual(symbols.iloc[0], symbols.iloc[-1])

    def test_sliding_traces_cover_the_sequence(self):
        self.assertEqual(statemachine.make_traces(["a", "b", "c", "d"], length=2),
                         [("a", "b"), ("b", "c"), ("c", "d")])

    def test_frequency_encoding_labels_repeated_values(self):
        train = pd.DataFrame({"proto": ["tcp"] * 8,
                              "bytes": [10] * 5 + [20, 30, 40],
                              "duration": [0.1] * 8})
        enc = statemachine.fit_frequency(train, nbins=2, min_count=3)
        symbols = statemachine.encode(train, enc)
        self.assertTrue(symbols.iloc[0].split("_")[1].startswith("f"))
        self.assertNotEqual(symbols.iloc[0], symbols.iloc[-1])

    def test_merging_collapses_identical_futures(self):
        pdfa = statemachine.learn_pdfa([("a", "b")] * 8 + [("a", "c")] * 8)
        self.assertEqual(pdfa.n_states, 3)  # root, a, one merged final state

    def test_seen_trace_scores_above_unseen(self):
        pdfa = statemachine.learn_pdfa([("a", "b")] * 10)
        self.assertGreater(statemachine.trace_score(pdfa, ("a", "b")),
                           statemachine.trace_score(pdfa, ("a", "never-seen")))

    def test_plot_pdfa_writes_a_graph(self):
        import tempfile
        from pathlib import Path
        pdfa = statemachine.learn_pdfa([("a", "b")] * 8 + [("a", "c")] * 8)
        path = Path(tempfile.mkdtemp()) / "graph.png"
        statemachine.plot_pdfa(pdfa, path=str(path))
        self.assertGreater(path.stat().st_size, 1000)

    def test_plot_pdfa_legend_clears_the_states(self):
        """States sit on the unit circle, so nothing in the key may reach y = -1."""
        import tempfile
        from pathlib import Path

        import matplotlib.pyplot as plt
        pdfa = statemachine.learn_pdfa([("a", "b")] * 8 + [("a", "c")] * 8)
        close, plt.close = plt.close, lambda *args, **kwargs: None
        try:
            statemachine.plot_pdfa(pdfa, path=str(Path(tempfile.mkdtemp()) / "graph.png"))
            fig = plt.gcf()
            fig.canvas.draw()
            ax = fig.axes[0]
            key = ax.legend_.get_window_extent(fig.canvas.get_renderer())
            top = key.transformed(ax.transData.inverted()).y1
        finally:
            plt.close = close
        self.assertLessEqual(top, -1.0)
        self.assertLess(key.x0, fig.bbox.width / 2)  # bottom left, not bottom right

    def test_plot_pdfa_edge_labels_do_not_stack(self):
        """A transition and its reverse, and a self-loop, each get their own label."""
        import tempfile
        from pathlib import Path

        import matplotlib.pyplot as plt

        # root -lb-> other is 1.00, other -lb-> root is 0.70: opposite directions on
        # one pair of states, which matplotlib would otherwise draw on one arc.
        other = statemachine._Node()
        root = statemachine._Node()
        root.visits, root.edge, root.children = 10, {"lb": 10}, {"lb": other}
        other.visits, other.edge = 10, {"lb": 7, "loop": 3}
        other.children = {"lb": root, "loop": other}
        pdfa = statemachine.PDFA(root)
        close, plt.close = plt.close, lambda *args, **kwargs: None
        try:
            statemachine.plot_pdfa(pdfa, path=str(Path(tempfile.mkdtemp()) / "graph.png"))
            fig = plt.gcf()
            fig.canvas.draw()
            renderer = fig.canvas.get_renderer()
            labels = [(text.get_text(), text.get_window_extent(renderer))
                      for text in fig.axes[0].texts
                      if len(text.get_text().split()) == 2
                      and not text.get_text()[0].isdigit()]
        finally:
            plt.close = close
        self.assertGreater(len(labels), 1)
        for i, (name, box) in enumerate(labels):
            for other_label, other_box in labels[i + 1:]:
                with self.subTest(labels=(name, other_label)):
                    self.assertFalse(box.overlaps(other_box))

    def test_transition_probabilities_stay_within_unit_range(self):
        traces = ([("a", "b", "c")] * 8 + [("a", "b", "d")] * 8
                  + [("b", "c")] * 8 + [("a", "b")] * 8 + [("b",)] * 8)
        pdfa = statemachine.learn_pdfa(traces)
        for _, outgoing in pdfa.probs.values():
            for _, probability in outgoing.values():
                self.assertGreaterEqual(probability, 0.0)
                self.assertLessEqual(probability, 1.0)

    def test_end_to_end_flags_new_protocol_and_spares_benign(self):
        import tempfile
        from pathlib import Path
        root = Path(tempfile.mkdtemp())
        header = "ts,frame_len,src_ip,dst_ip,src_port,dst_port,proto\n"
        benign_lines = [header] + [
            f"{10.0 + w + i / 5:.4f},100,::1,::2,{1000 + w},8080,tcp"
            for w in range(30) for i in range(5)]
        attack_lines = [header] + [
            f"{10.0 + w + i / 5:.4f},100,::1,::2,{2000 + w},8080,udp"
            for w in range(30) for i in range(5)]
        benign_path, attack_path = root / "benign.csv", root / "attack.csv"
        benign_path.write_text("\n".join(benign_lines) + "\n")
        attack_path.write_text("\n".join(attack_lines) + "\n")
        benign_flags, attack_flags = statemachine.score_pair(
            str(benign_path), str(attack_path))
        self.assertLess(benign_flags.mean(), 0.2)
        # 26 of 30 windows: the first TRACE_LEN - 1 windows hold no finished
        # trace, so nothing can flag there by construction.
        self.assertGreater(attack_flags.mean(), 0.8)


class EventLogChecks(unittest.TestCase):
    def flagged_frame(self):
        return pd.DataFrame(
            {"anomaly_score": [4.0, 1.0, 7.0, float("inf")],
             "anomaly": [True, False, True, True]},
            index=[3, 4, 5, 6])

    def test_only_flagged_windows_emit_in_order(self):
        events = to_events(self.flagged_frame(), detector="z_score", pods=["pod-nginx"])
        self.assertEqual([e["severity"] for e in events], ["low", "med", "high"])
        for event in events:
            self.assertEqual(set(event), {"version", "detector", "severity", "locations"})
        first = events[0]
        self.assertEqual(first["version"], "LogV0")
        self.assertEqual(first["detector"], "z_score")
        self.assertEqual(first["locations"], {"pods": ["pod-nginx"]})

    def test_event_lines_are_valid_json(self):
        import json
        events = to_events(self.flagged_frame(), detector="z_score", pods=["pod-nginx"])
        for event in events:
            json.dumps(event, allow_nan=False)
        import tempfile
        path = Path(tempfile.mkdtemp()) / "events.jsonl"
        write_events(events, path=str(path))
        self.assertEqual(len(path.read_text().strip().split("\n")), 3)


class BoundaryChecks(unittest.TestCase):
    """The evaluation policy lives in one module, and the scoring paths read that one."""

    def test_bulk_labels_cover_six_files(self):
        self.assertEqual(evaluation.BULK_LABELS,
                         {"router-any", "node-child4", "pod-robot-controller"})
        self.assertEqual(len(evaluation.BULK_LABELS) * len(data_io.METHODS), 6)

    def test_bulk_labels_have_one_definition(self):
        # reporting used to carry its own copy, so the label set could drift from the one
        # the tests pin. demo.py and reporting.py must both resolve to evaluation's.
        self.assertIs(reporting.BULK_LABELS, evaluation.BULK_LABELS)
        self.assertIs(demo.BULK_LABELS, evaluation.BULK_LABELS)

    def test_split_fraction_comes_from_evaluation(self):
        self.assertEqual(features.BENIGN_TRAIN_FRACTION, evaluation.TRAIN_FRACTION)

    def test_warmup_covers_a_whole_trace(self):
        self.assertEqual(evaluation.WARMUP_WINDOWS, statemachine.TRACE_LEN)


class FlagVerdictChecks(unittest.TestCase):
    """The keep-or-drop rule for the flag alphabet, fixed before any AUROC was computed."""

    def row(self, label, scenario, auc_plain, auc_flags, det_plain=0.5, det_flags=0.5):
        return {"label": label, "scenario": scenario, "auc_plain": auc_plain,
                "auc_flags": auc_flags, "det_plain": det_plain, "det_flags": det_flags}

    def rows(self, target_plain=0.50, target_flags=0.62, router=0.60, child4=0.55,
             det_plain=0.50, det_flags=0.50):
        return [self.row("pod-lidar", "lidar attack", target_plain, target_flags,
                         det_plain, det_flags),
                self.row("router-any", "injection attack", router, router),
                self.row("node-child4", "injection attack", child4, child4)]

    def test_keep_when_the_target_gain_clears_the_bar(self):
        verdict, reasons = flag_verdict.decide(self.rows())
        self.assertEqual(verdict, "keep")
        self.assertTrue(reasons)

    def test_keep_at_the_exact_boundaries(self):
        rows = self.rows(target_flags=0.60, router=0.65)
        rows[1]["auc_flags"] = 0.60          # exactly the 0.05 allowed loss
        verdict, _ = flag_verdict.decide(rows)
        self.assertEqual(verdict, "keep")

    def test_drop_when_the_target_gain_is_too_small(self):
        verdict, reasons = flag_verdict.decide(self.rows(target_flags=0.58))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("target AUC gain" in reason for reason in reasons))

    def test_drop_when_target_detection_falls(self):
        verdict, reasons = flag_verdict.decide(self.rows(det_plain=0.55, det_flags=0.50))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("detection fell" in reason for reason in reasons))

    def test_drop_when_another_stratum_loses_more_than_allowed(self):
        rows = self.rows()
        rows[1]["auc_plain"], rows[1]["auc_flags"] = 0.70, 0.63   # 0.07 loss on router-any
        verdict, reasons = flag_verdict.decide(rows)
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("router-any" in reason for reason in reasons))

    def test_undecidable_when_a_stratum_is_missing(self):
        rows = self.rows()[:-1]
        verdict, reasons = flag_verdict.decide(rows)
        self.assertEqual(verdict, "undecidable")
        self.assertTrue(any("node-child4" in reason for reason in reasons))


class FlagScoreChecks(unittest.TestCase):
    """Orientation and matching properties of the score dump's helpers."""

    def test_auroc_is_one_when_attack_always_outranks_benign(self):
        self.assertEqual(flag_scores.auroc([0.0, 1.0], [2.0, 3.0]), 1.0)

    def test_auroc_is_zero_when_the_ranking_is_inverted(self):
        self.assertEqual(flag_scores.auroc([2.0, 3.0], [0.0, 1.0]), 0.0)

    def test_auroc_counts_ties_as_half(self):
        self.assertEqual(flag_scores.auroc([1.0, 1.0], [1.0, 1.0]), 0.5)

    def test_auroc_ignores_unscored_windows_and_needs_both_sides(self):
        self.assertEqual(flag_scores.auroc([np.nan, 0.0], [1.0]), 1.0)
        with self.assertRaises(ValueError):
            flag_scores.auroc([], [1.0])

    def test_window_scores_keep_the_most_anomalous_trace(self):
        scored = [(10.1, 1.0), (10.9, 4.0), (11.5, 2.0)]
        scores = flag_scores.window_scores(scored, t0=10.0, n_windows=3)
        self.assertEqual(scores[0], 4.0)
        self.assertEqual(scores[1], 2.0)
        self.assertTrue(np.isnan(scores[2]))          # no trace ends there

    def test_detection_uses_the_plain_model_benign_rate(self):
        benign = [0.0, 1.0, 2.0, 3.0, 4.0]
        attack = [4.0, 5.0]
        detection, realised = flag_scores.detection_at_benign_rate(benign, attack, 0.2)
        self.assertEqual(realised, 0.2)               # exactly the top fifth
        self.assertEqual(detection, 1.0)
        with self.assertRaises(ValueError):
            flag_scores.detection_at_benign_rate(benign, attack, 0.0)


    def test_alphabet_slope_draws_every_stratum_and_carries_the_verdict(self):
            """One line per stratum, and the title's verdict is the committed rule's."""
            import tempfile

            import matplotlib.pyplot as plt
            summary = pd.DataFrame([
                {"label": "pod-lidar", "scenario": "lidar attack", "method": "tcp",
                 "n_benign_plain": 15, "n_attack_plain": 55, "n_benign_flags": 15,
                 "n_attack_flags": 55, "auc_plain": 0.50, "auc_flags": 0.65,
                 "det_plain": 0.30, "det_flags": 0.35, "benign_rate_plain": 0.13,
                 "benign_rate_flags": 0.13},
                {"label": "router-any", "scenario": "injection attack", "method": "tcp",
                 "n_benign_plain": 24, "n_attack_plain": 16, "n_benign_flags": 24,
                 "n_attack_flags": 16, "auc_plain": 0.70, "auc_flags": 0.72,
                 "det_plain": 0.40, "det_flags": 0.41, "benign_rate_plain": 0.20,
                 "benign_rate_flags": 0.20},
                {"label": "node-child4", "scenario": "injection attack", "method": "tcp",
                 "n_benign_plain": 12, "n_attack_plain": 9, "n_benign_flags": 12,
                 "n_attack_flags": 9, "auc_plain": 0.80, "auc_flags": 0.82,
                 "det_plain": 0.50, "det_flags": 0.50, "benign_rate_plain": 0.25,
                 "benign_rate_flags": 0.25},
            ])
            close, plt.close = plt.close, lambda *args, **kwargs: None
            try:
                path = Path(tempfile.mkdtemp()) / "alphabet.png"
                flag_scores.plot_alphabet_slope(summary, path=str(path))
                fig = plt.gcf()
                fig.canvas.draw()
                ax = fig.axes[0]
                drawn = [line for line in ax.get_lines()
                     if len(line.get_xdata()) == 2
                     and line.get_ydata()[0] == line.get_ydata()[1]]  # rows, not axvline
                labels = [tick.get_text() for tick in ax.get_yticklabels()]
                title = fig.get_suptitle()
            finally:
                plt.close = close
            self.assertEqual(path.stat().st_size > 1000, True)
            self.assertEqual(len(drawn), len(summary))          # one line per stratum, none dropped
            self.assertIn("pod-lidar · lidar", labels)
            self.assertIn("verdict: keep", title)               # 0.50 -> 0.65 clears the 0.10 bar
            self.assertEqual(flag_scores.verdict_rows(summary)[0]["label"], "pod-lidar")


# --- Capture files built byte by byte, so the reader is tested without the Drive -------

def _capture_file(blob, name="capture.pcapng"):
    import tempfile
    path = Path(tempfile.mkdtemp()) / name
    path.write_bytes(blob)
    return path


def _pcap_bytes(frames, linktype=276, nano=False, big_endian=False, snaplen=262144):
    """A classic pcap. frames: (sec, frac, data, orig_len) tuples."""
    import struct
    order = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    blob = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for sec, frac, data, orig_len in frames:
        blob += struct.pack(order + "IIII", sec, frac, len(data), orig_len) + data
    return blob


def _pcapng_block(block_type, body):
    import struct
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _pcapng_option(code, value):
    import struct
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def _pcapng_shb():
    import struct
    return _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def _pcapng_idb(linktype=1, tsresol=None, snaplen=65535):
    import struct
    body = struct.pack("<HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += _pcapng_option(9, bytes([tsresol])) + _pcapng_option(0, b"")
    return _pcapng_block(1, body)


def _pcapng_epb(interface, ts_units, data, orig_len=None):
    import struct
    head = struct.pack("<IIIII", interface, ts_units >> 32, ts_units & 0xFFFFFFFF,
                       len(data), orig_len or len(data))
    return _pcapng_block(6, head + data)


def _pcapng_bytes(*blocks):
    """A pcapng: one section header, then the given blocks in order."""
    return _pcapng_shb() + b"".join(blocks)


class PcapReadChecks(unittest.TestCase):
    def frames(self, blob, name="capture.pcapng"):
        import pcap_read
        reader = pcap_read.CaptureReader(_capture_file(blob, name))
        return list(reader.frames()), reader

    def test_detect_format_by_magic_not_extension(self):
        import pcap_read
        path = _capture_file(_pcap_bytes([(1, 0, b"x" * 20, 20)]), "pod-nginx-tcp.pcapng")
        self.assertEqual(pcap_read.detect_format(path), "pcap")
        self.assertEqual(pcap_read.detect_format(_capture_file(_pcapng_bytes(_pcapng_idb()))),
                         "pcapng")
        with self.assertRaisesRegex(ValueError, "unknown capture magic"):
            pcap_read.detect_format(_capture_file(b"garbage!"))

    def test_pcap_little_endian_micro(self):
        data = bytes(range(77))
        (frame,), _ = self.frames(_pcap_bytes([(1771545908, 877129, data, 77)]))
        self.assertEqual((frame.number, frame.ts_sec, frame.ts_frac, frame.ts_digits),
                         (1, 1771545908, 877129, 6))
        self.assertEqual((frame.orig_len, frame.data, frame.linktype), (77, data, 276))

    def test_pcap_nano_and_big_endian(self):
        data = bytes(range(60))
        (frame,), _ = self.frames(_pcap_bytes([(1771545908, 877129001, data, 60)],
                                              linktype=1, nano=True, big_endian=True))
        self.assertEqual((frame.ts_sec, frame.ts_frac, frame.ts_digits), (1771545908, 877129001, 9))
        self.assertEqual((frame.data, frame.linktype), (data, 1))

    def test_pcapng_nanosecond_resolution(self):
        blob = _pcapng_bytes(_pcapng_idb(tsresol=9),
                             _pcapng_epb(0, 1771545910906831300, b"y" * 71))
        (frame,), _ = self.frames(blob)
        self.assertEqual((frame.ts_sec, frame.ts_frac, frame.ts_digits),
                         (1771545910, 906831300, 9))
        self.assertEqual((frame.orig_len, frame.linktype), (71, 1))

    def test_pcapng_resolution_defaults_to_microseconds(self):
        (frame,), _ = self.frames(_pcapng_bytes(_pcapng_idb(), _pcapng_epb(0, 1771545910906831, b"z" * 60)))
        self.assertEqual((frame.ts_sec, frame.ts_frac, frame.ts_digits), (1771545910, 906831, 6))

    def test_second_idb_mid_file_sets_resolution(self):
        blob = _pcapng_bytes(_pcapng_idb(linktype=276, tsresol=6),
                             _pcapng_epb(0, 1771545910000001, b"a" * 40),
                             _pcapng_idb(linktype=1, tsresol=9),
                             _pcapng_epb(1, 1771545910000000002, b"b" * 40))
        first, second = self.frames(blob)[0]
        self.assertEqual((first.ts_digits, first.linktype), (6, 276))
        self.assertEqual((second.number, second.ts_digits, second.ts_frac, second.linktype),
                         (2, 9, 2, 1))

    def test_long_frame_is_cut_to_head_bytes(self):
        import pcap_read
        big = bytes(65535)
        frames, _ = self.frames(_pcap_bytes([(1, 0, big, 65549), (2, 0, b"next" * 10, 40)]))
        self.assertEqual(len(frames[0].data), pcap_read.HEAD_BYTES)
        self.assertEqual(frames[0].orig_len, 65549)
        self.assertEqual((frames[1].ts_sec, frames[1].data), (2, b"next" * 10))

    def test_truncated_tail_warns_and_keeps_complete_frames(self):
        blob = _pcap_bytes([(1, 0, b"a" * 100, 100), (2, 0, b"b" * 100, 100),
                            (3, 0, b"c" * 100, 100)])
        frames, reader = self.frames(blob[:-58])
        self.assertEqual([f.ts_sec for f in frames], [1, 2])
        self.assertEqual(reader.warnings, ["truncated after frame 2"])

    def test_truncated_pcapng_block_warns(self):
        blob = _pcapng_bytes(_pcapng_idb(), _pcapng_epb(0, 1, b"a" * 64), _pcapng_epb(0, 2, b"b" * 64))
        frames, reader = self.frames(blob[:-30])
        self.assertEqual(len(frames), 1)
        self.assertEqual(reader.warnings, ["truncated after frame 1"])

    def test_zero_filled_tail_drops_the_block_it_cuts(self):
        # injection attack node-child4-ptcp: real blocks end at 4.58 GB of a 10.8 GB file, the
        # rest is zeros, and the last packet block's closing length is one of those zeros.
        last = _pcapng_epb(0, 2, b"b" * 64)
        blob = _pcapng_bytes(_pcapng_idb(), _pcapng_epb(0, 1, b"a" * 64), last[:-4] + bytes(4))
        frames, reader = self.frames(blob + bytes(4096))
        self.assertEqual(len(frames), 1)
        self.assertEqual(reader.warnings, ["truncated after frame 1"])

    def test_pcap_zero_filled_tail_is_truncation_not_frames(self):
        # A classic pcap cut and zero-padded: zero record headers must not become ts=0 frames.
        blob = _pcap_bytes([(1, 0, b"a" * 100, 100), (2, 0, b"b" * 100, 100)])
        frames, reader = self.frames(blob + bytes(4096 - len(blob)))
        self.assertEqual([f.ts_sec for f in frames], [1, 2])
        self.assertEqual(reader.warnings, ["truncated after frame 2"])

    def test_pcap_record_longer_than_snaplen_is_truncation(self):
        import struct
        blob = _pcap_bytes([(1, 0, b"a" * 100, 100)], snaplen=1000)
        blob += struct.pack("<IIII", 2, 0, 5000, 5000) + bytes(5000)
        frames, reader = self.frames(blob)
        self.assertEqual((len(frames), reader.warnings), (1, ["truncated after frame 1"]))

    def test_malformed_pcapng_blocks_raise_naming_the_file(self):
        import struct
        import pcap_read
        short_epb = _pcapng_block(6, b"")
        bad_idb = _pcapng_block(1, b"")
        overlong = _pcapng_epb(0, 1, b"a" * 16)
        overlong = overlong[:20] + struct.pack("<I", 500) + overlong[24:]   # incl_len past the block
        empty_tsresol = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535) + _pcapng_option(9, b""))
        for name, blocks in (("short packet block", (_pcapng_idb(), short_epb)),
                             ("empty interface block", (bad_idb,)),
                             ("captured length past its block", (_pcapng_idb(), overlong)),
                             ("empty if_tsresol", (empty_tsresol,))):
            with self.subTest(name):
                path = _capture_file(_pcapng_bytes(*blocks))
                with self.assertRaisesRegex(ValueError, "malformed") as caught:
                    list(pcap_read.CaptureReader(path).frames())
                self.assertIn(str(path), str(caught.exception))

    def test_unsupported_linktype_raises_with_path(self):
        path = _capture_file(_pcap_bytes([(1, 0, b"x" * 20, 20)], linktype=101))
        import pcap_read
        with self.assertRaisesRegex(ValueError, "unsupported linktype 101") as caught:
            list(pcap_read.CaptureReader(path).frames())
        self.assertIn(str(path), str(caught.exception))

    def test_simple_packet_block_is_refused(self):
        import pcap_read
        path = _capture_file(_pcapng_bytes(_pcapng_idb(), _pcapng_block(3, b"\0" * 8)))
        with self.assertRaisesRegex(ValueError, "unsupported pcapng block type 3"):
            list(pcap_read.CaptureReader(path).frames())

    def test_reader_imports_without_local_paths(self):
        script = "import sys; sys.path.insert(0, '.'); import pcap_read; print(pcap_read.HEAD_BYTES)"
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)


# --- Frames built layer by layer, for the row dissection -------------------------------

def _mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def _ether(payload, ethertype, src="00:00:00:00:00:00", dst="00:00:00:00:00:00"):
    import struct
    return _mac(dst) + _mac(src) + struct.pack(">H", ethertype) + payload


def _sll2(payload, protocol):
    import struct
    return struct.pack(">HHIHBB8s", protocol, 0, 1, 772, 0, 6, bytes(8)) + payload


def _ipv4(payload, proto, src="10.0.0.1", dst="10.0.0.2", ttl=64, total_len=None):
    import ipaddress
    import struct
    total = total_len if total_len is not None else 20 + len(payload)
    return (struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, ttl, proto, 0,
                        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
            + payload)


def _ipv6(payload, next_header, src="::1", dst="::1", hop_limit=64):
    import ipaddress
    import struct
    return (struct.pack(">IHBB16s16s", 6 << 28, len(payload), next_header, hop_limit,
                        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
            + payload)


def _tcp(sport, dport, flags=0, payload=b"", header_len=20):
    import struct
    head = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, (header_len // 4) << 4, flags, 512, 0, 0)
    return head + bytes(header_len - 20) + payload


def _udp(sport, dport, payload=b""):
    import struct
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp(icmp_type, code, payload=b""):
    import struct
    return struct.pack(">BBHI", icmp_type, code, 0, 0) + payload


def _arp(op, sender_mac, sender_ip, target_mac, target_ip):
    import ipaddress
    import struct
    return (struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + _mac(sender_mac)
            + ipaddress.ip_address(sender_ip).packed + _mac(target_mac)
            + ipaddress.ip_address(target_ip).packed)


def _frame(data, linktype=1, orig_len=None, number=1, sec=1771545908, frac=877129, digits=6):
    import pcap_read
    return pcap_read.Frame(number, sec, frac, digits, orig_len or len(data),
                           data[:pcap_read.HEAD_BYTES], linktype)


class PcapRowChecks(unittest.TestCase):
    def row(self, data, linktype=1, orig_len=None):
        import pcap_rows
        return pcap_rows.frame_row(_frame(data, linktype, orig_len))

    def test_sll2_ipv6_udp_matches_sponsor_row1(self):
        # benign pod-nginx-tcp.csv row 1
        row = self.row(_sll2(_ipv6(_udp(53570, 8080, b"x" * 9), 17), 0x86DD), linktype=276)
        self.assertEqual((row["frame_len"], row["eth_src"], row["eth_dst"], row["eth_type"]),
                         (77, None, None, None))
        self.assertEqual((row["ip_version"], row["src_ip"], row["dst_ip"], row["proto"],
                          row["ttl_or_hlim"]), (6, "::1", "::1", "udp", 64))
        self.assertEqual((row["src_port"], row["dst_port"], row["is_http"], row["is_dns"],
                          row["is_https"]), (53570, 8080, 1, 0, 0))
        self.assertEqual((row["udp_length"], row["tcp_payload_len"], row["tcp_syn"],
                          row["icmp_type"]), (17, None, 0, None))

    def test_row_has_every_column_but_the_three_capture_wide_ones(self):
        import pcap_rows
        row = self.row(_ether(_ipv4(_udp(1, 2), 17), 0x0800))
        self.assertEqual(list(row), pcap_rows.COLUMNS[3:])

    def test_ethernet_loopback_zero_macs(self):
        row = self.row(_ether(_ipv6(_udp(1, 2), 17), 0x86DD))
        self.assertEqual((row["eth_src"], row["eth_dst"], row["eth_type"]),
                         ("00:00:00:00:00:00", "00:00:00:00:00:00", "0x86dd"))

    def test_ethernet_macs_are_lowercase(self):
        row = self.row(_ether(_ipv4(_udp(1, 2), 17), 0x0800, src="6C:F6:DA:C5:D5:B9"))
        self.assertEqual(row["eth_src"], "6c:f6:da:c5:d5:b9")

    def test_ipv4_tcp_payload_and_flags(self):
        row = self.row(_ether(_ipv4(_tcp(40000, 80, flags=0x12, payload=b"p" * 100), 6), 0x0800))
        self.assertEqual((row["ip_version"], row["src_ip"], row["dst_ip"], row["proto"]),
                         (4, "10.0.0.1", "10.0.0.2", "tcp"))
        self.assertEqual((row["tcp_syn"], row["tcp_ack"], row["tcp_fin"], row["tcp_rst"]),
                         (1, 1, 0, 0))
        self.assertEqual((row["tcp_payload_len"], row["udp_length"]), (100, None))

    def test_every_tcp_flag_bit(self):
        row = self.row(_ether(_ipv4(_tcp(1, 2, flags=0xFF), 6), 0x0800))
        self.assertEqual([row[c] for c in ("tcp_fin", "tcp_syn", "tcp_rst", "tcp_psh", "tcp_ack",
                                           "tcp_urg", "tcp_ece", "tcp_cwr")], [1] * 8)

    def test_tcp_without_payload_prints_zero(self):
        row = self.row(_ether(_ipv4(_tcp(1, 2, flags=0x10), 6), 0x0800))
        self.assertEqual(row["tcp_payload_len"], 0)

    def test_clipped_frame_uses_header_lengths(self):
        segment = _tcp(777, 2049, flags=0x18, payload=bytes(65160), header_len=32)
        data = _ether(_ipv4(segment, 6, total_len=65212), 0x0800)
        row = self.row(data)
        self.assertEqual((row["frame_len"], row["tcp_payload_len"]), (65226, 65160))

    def test_ports_either_side_set_flags(self):
        self.assertEqual(self.row(_ether(_ipv4(_udp(53, 5000), 17), 0x0800))["is_dns"], 1)
        self.assertEqual(self.row(_ether(_ipv4(_tcp(443, 5000), 6), 0x0800))["is_https"], 1)
        self.assertEqual(self.row(_ether(_ipv4(_tcp(5000, 8080), 6), 0x0800))["is_http"], 1)
        quiet = self.row(_ether(_ipv4(_tcp(5000, 5001), 6), 0x0800))
        self.assertEqual((quiet["is_dns"], quiet["is_http"], quiet["is_https"]), (0, 0, 0))

    def test_icmp_zero_type_and_code_are_blank(self):
        request = self.row(_sll2(_ipv4(_icmp(8, 0, bytes(56)), 1, "127.0.0.1", "127.0.0.1"), 0x0800), 276)
        reply = self.row(_sll2(_ipv4(_icmp(0, 0, bytes(56)), 1, "127.0.0.1", "127.0.0.1"), 0x0800), 276)
        self.assertEqual((request["proto"], request["icmp_type"], request["icmp_code"]), ("icmp", 8, None))
        self.assertEqual((reply["icmp_type"], reply["icmp_code"], reply["src_port"]), (None, None, None))
        self.assertEqual(request["frame_len"], 104)

    def test_icmpv6_error_takes_quoted_udp_ports(self):
        # benign pod-nginx-tcp.csv row 2: port unreachable quoting the row-1 datagram
        quoted = _ipv6(_udp(53570, 8080, b"x" * 9), 17)
        row = self.row(_sll2(_ipv6(_icmp(1, 4, quoted), 58), 0x86DD), linktype=276)
        self.assertEqual((row["frame_len"], row["proto"], row["icmp_type"], row["icmp_code"]),
                         (125, "58", 1, 4))
        self.assertEqual((row["src_port"], row["dst_port"], row["is_http"], row["udp_length"],
                          row["tcp_payload_len"]), (53570, 8080, 1, 17, None))

    def test_icmpv4_error_takes_quoted_tcp_ports_and_flags(self):
        quoted = _ipv4(_tcp(40000, 443, flags=0x02), 6)
        row = self.row(_ether(_ipv4(_icmp(3, 3, quoted), 1), 0x0800))
        self.assertEqual((row["src_port"], row["dst_port"], row["tcp_syn"], row["is_https"],
                          row["tcp_payload_len"]), (40000, 443, 1, 1, None))

    def test_igmp_proto_is_numeric_string(self):
        row = self.row(_ether(_ipv4(bytes(8), 2, "192.168.50.1", "224.0.0.1", ttl=1), 0x0800))
        self.assertEqual((row["proto"], row["ttl_or_hlim"], row["src_port"]), ("2", 1, None))

    def test_arp_fills_arp_columns_only(self):
        arp = _arp(1, "40:ae:30:a7:6f:f6", "192.168.50.1", "00:00:00:00:00:00", "192.168.50.22")
        row = self.row(_ether(arp, 0x0806, src="40:ae:30:a7:6f:f6", dst="ff:ff:ff:ff:ff:ff"))
        self.assertEqual((row["arp_opcode"], row["arp_sender_ip"], row["arp_target_ip"],
                          row["arp_sender_mac"], row["arp_target_mac"]),
                         (1, "192.168.50.1", "192.168.50.22", "40:ae:30:a7:6f:f6",
                          "00:00:00:00:00:00"))
        self.assertEqual((row["ip_version"], row["src_ip"], row["proto"], row["eth_type"]),
                         (None, None, None, "0x0806"))

    def test_ieee_802_3_length_field_is_not_an_ethertype(self):
        # benign node-child1-ptcp.csv frame 3587: an LLC frame whose type field is a length
        row = self.row(_ether(bytes(38), 0x0026, src="d2:8a:f5:39:9d:83", dst="ff:ff:ff:ff:ff:ff"))
        self.assertEqual((row["eth_src"], row["eth_dst"], row["eth_type"]),
                         ("d2:8a:f5:39:9d:83", "ff:ff:ff:ff:ff:ff", None))

    def test_zero_type_field_prints_as_hex(self):
        # lidar attack node-child1-ptcp.csv frame 11804: an SLL header stored as Ethernet
        row = self.row(_ether(_ipv4(_tcp(1, 2), 6), 0x0000))
        self.assertEqual((row["eth_type"], row["src_ip"]), ("0x0000", None))

    def test_port_80_is_http_too(self):
        # nginx attack pod-nginx-tcp.csv frame 23: a SYN to :80
        row = self.row(_sll2(_ipv4(_tcp(51148, 80, flags=0x02), 6), 0x0800), 276)
        self.assertEqual(row["is_http"], 1)

    def test_icmpv6_zero_code_is_printed(self):
        # benign pod-robot-hardware-ptcp.csv frame 234: router solicitation, code 0
        row = self.row(_ether(_ipv6(_icmp(133, 0), 58, "fe80::1", "ff02::2", 255), 0x86DD))
        self.assertEqual((row["icmp_type"], row["icmp_code"]), (133, 0))

    def test_icmpv6_behind_hop_by_hop_header(self):
        # nginx attack node-child2-tcp.csv frame 1396: MLDv2 report after a hop-by-hop header
        hop_by_hop = bytes([58, 0, 5, 2, 0, 0, 1, 0])
        packet = _ipv6(hop_by_hop + _icmp(143, 0, bytes(20)), 0, "::", "ff02::16", 1)
        row = self.row(_sll2(packet, 0x86DD), 276)
        self.assertEqual((row["proto"], row["icmp_type"], row["icmp_code"]), ("0", 143, 0))

    def test_tcp_behind_destination_options_header(self):
        options = bytes([6, 0, 1, 4, 0, 0, 0, 0])
        packet = _ipv6(options + _tcp(40000, 443, flags=0x10, payload=b"x" * 12), 60)
        row = self.row(_ether(packet, 0x86DD))
        self.assertEqual((row["proto"], row["dst_port"], row["is_https"], row["tcp_payload_len"]),
                         ("60", 443, 1, 12))

    def test_raw_ip_under_ethernet_blanks_ip_columns(self):
        packet = _ipv4(_udp(1, 2, bytes(360)), 17, "192.168.50.22", "192.168.50.140")
        row = self.row(packet)
        self.assertEqual(row["eth_type"], "0xc0a8")
        self.assertEqual((row["src_ip"], row["dst_ip"], row["dst_port"]), (None, None, None))

    def test_short_frame_leaves_missing_fields_blank(self):
        import pcap_rows
        data = _ether(_ipv4(_tcp(1, 2), 6), 0x0800)[:30]       # IPv4 header cut mid-way
        row, complete = pcap_rows.dissect(_frame(data, orig_len=54))
        self.assertFalse(complete)
        self.assertEqual((row["eth_type"], row["src_ip"], row["frame_len"]), ("0x0800", None, 54))

    def test_iat_first_row_int_zero_then_signed_float(self):
        import pcap_rows
        packet = _sll2(_ipv4(_udp(1, 2), 17), 0x0800)
        path = _capture_file(_pcap_bytes([(100, 500000, packet, len(packet)),
                                          (100, 750000, packet, len(packet)),
                                          (100, 700000, packet, len(packet))]))
        rows = list(pcap_rows.capture_rows(path))
        self.assertEqual([r[0] for r in rows], [1, 2, 3])
        iats = [r[2] for r in rows]
        self.assertEqual(pcap_rows.format_cell(iats[0]), "0")
        self.assertIsInstance(iats[0], int)
        self.assertGreater(iats[1], 0)
        self.assertLess(iats[2], 0)
        self.assertEqual(iats[2], rows[2][1] - rows[1][1])

    def test_ts_seconds_rules_differ_only_in_last_ulp(self):
        import pcap_rows
        add = pcap_rows.ts_seconds(1771545910, 906831167, 9, rule="add")
        div = pcap_rows.ts_seconds(1771545910, 906831167, 9, rule="div")
        self.assertLessEqual(abs(add - div), 2.4e-7)
        with self.assertRaises(ValueError):
            pcap_rows.ts_seconds(1, 0, 6, rule="other")

    def test_format_cell(self):
        import pcap_rows
        self.assertEqual([pcap_rows.format_cell(v) for v in (None, 0, 17, "udp", 8.58306884765625e-06)],
                         ["", "0", "17", "udp", "8.58306884765625e-06"])

    def test_written_csv_loads_through_data_io(self):
        import tempfile
        import pcap_rows
        packet = _ether(_ipv4(_tcp(40000, 8080, flags=0x02, payload=b"x" * 10), 6), 0x0800)
        source = _capture_file(_pcap_bytes([(100, 1, packet, len(packet)),
                                            (100, 2, packet, len(packet))], linktype=1))
        target = Path(tempfile.mkdtemp()) / "pod-nginx-ptcp.csv"
        result = pcap_rows.write_capture_rows(source, target)
        self.assertEqual(result, {"rows": 2, "warnings": []})
        raw = target.read_bytes()
        self.assertEqual(raw.split(b"\r\n")[0].decode().split(","), pcap_rows.COLUMNS)
        self.assertEqual(raw.count(b"\r\n"), 3)
        frame = data_io.load_capture(str(target))
        self.assertEqual(list(frame.columns), data_io.PACKET_COLUMNS)
        self.assertEqual(int(frame["dst_port"].iloc[0]), 8080)

    def test_reader_warnings_reach_the_writer(self):
        import tempfile
        import pcap_rows
        packet = _sll2(_ipv4(_udp(1, 2, bytes(50)), 17), 0x0800)
        blob = _pcap_bytes([(1, 0, packet, len(packet)), (2, 0, packet, len(packet))])
        target = Path(tempfile.mkdtemp()) / "x.csv"
        result = pcap_rows.write_capture_rows(_capture_file(blob[:-10]), target)
        self.assertEqual(result, {"rows": 1, "warnings": ["truncated after frame 1"]})


class PcapDiffChecks(unittest.TestCase):
    def tree(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        flat = root / "benign" / "pcapng files" / "pod-nginx-tcp.pcapng"
        nested = root / "nginx attack" / "pcapng files" / "ptcp" / "pod level" / "pod-nginx-ptcp.pcapng"
        for path in (flat, nested):
            path.parent.mkdir(parents=True)
            path.write_bytes(b"")
        return root, flat, nested

    def test_locate_pcap_flat_and_nested(self):
        import pcap_diff
        root, flat, nested = self.tree()
        self.assertEqual(pcap_diff.locate_pcap(root, "benign", "pod-nginx", "tcp"), flat)
        self.assertEqual(pcap_diff.locate_pcap(root, "nginx attack", "pod-nginx", "ptcp"), nested)

    def test_locate_pcap_missing_or_duplicate_raises(self):
        import pcap_diff
        root, flat, _ = self.tree()
        with self.assertRaisesRegex(ValueError, "benign/pod-lidar/tcp: 0 capture files"):
            pcap_diff.locate_pcap(root, "benign", "pod-lidar", "tcp")
        copy = flat.parent / "again" / flat.name
        copy.parent.mkdir()
        copy.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "benign/pod-nginx/tcp: 2 capture files"):
            pcap_diff.locate_pcap(root, "benign", "pod-nginx", "tcp")

    def pair(self, edit=None, cut=0):
        """A two-frame capture and its regenerated CSV, with one CSV cell optionally edited."""
        import csv
        import tempfile
        import pcap_rows
        packet = _ether(_ipv4(_tcp(40000, 8080, flags=0x02, payload=b"x" * 10), 6), 0x0800)
        blob = _pcap_bytes([(100, 1, packet, len(packet)), (101, 2, packet, len(packet))], linktype=1)
        pcap = _capture_file(blob[:len(blob) - cut])
        csv_path = Path(tempfile.mkdtemp()) / "pod-nginx-ptcp.csv"
        pcap_rows.write_capture_rows(pcap, csv_path)
        if edit:
            column, value = edit
            with open(csv_path, newline="") as handle:
                rows = list(csv.reader(handle))
            rows[1][pcap_rows.COLUMNS.index(column)] = value
            with open(csv_path, "w", newline="") as handle:
                csv.writer(handle).writerows(rows)
        return pcap, csv_path

    def test_compare_capture_counts_and_names_mismatch(self):
        import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(edit=("dst_port", "9999")))
        self.assertEqual((result["rows_sponsor"], result["rows_regen"]), (2, 2))
        self.assertEqual((result["tier_a_exact"], result["mismatch_cells"],
                          result["differing_columns"]), (False, 1, "dst_port:1"))
        self.assertEqual(result["first_mismatch"], "frame 1 dst_port 8080|9999")

    def test_compare_capture_tier_b_only_is_still_tier_a_exact(self):
        import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(edit=("eth_src", "aa:aa:aa:aa:aa:aa")))
        self.assertEqual((result["tier_a_exact"], result["differing_columns"], result["windows"]),
                         (True, "eth_src:1", "equal"))

    def test_identical_capture_is_exact_with_equal_windows(self):
        import pcap_diff
        result = pcap_diff.compare_capture(*self.pair())
        self.assertEqual((result["tier_a_exact"], result["mismatch_cells"], result["windows"],
                          result["warnings"]), (True, 0, "equal", ""))

    def test_truncation_warning_blocks_exact(self):
        import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(cut=10))
        self.assertEqual((result["rows_regen"], result["mismatch_cells"]), (1, 0))
        self.assertEqual((result["tier_a_exact"], result["warnings"]),
                         (False, "truncated after frame 1"))

    def test_row_count_difference_blocks_exact(self):
        import pcap_diff
        pcap, csv_path = self.pair()
        with open(csv_path, "a", newline="") as handle:
            handle.write("3" + "," * 33 + "\r\n")
        result = pcap_diff.compare_capture(pcap, csv_path)
        self.assertEqual((result["rows_sponsor"], result["rows_regen"], result["tier_a_exact"]),
                         (3, 2, False))

    def test_one_bad_capture_is_recorded_and_the_run_continues(self):
        import tempfile
        import pcap_diff
        root = Path(tempfile.mkdtemp())
        good_pcap, good_csv = self.pair()
        rows = []
        for label, pcap in (("pod-good", good_pcap), ("pod-bad", None)):
            target = root / "benign" / "pcapng files" / f"{label}-ptcp.pcapng"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(pcap.read_bytes() if pcap else b"not a capture")
            rows.append({"scenario": "benign", "label": label, "method": "ptcp",
                         "path": str(good_csv)})
        out = root / "pcap_diff.csv"
        results = pcap_diff.run(pd.DataFrame(rows), root, out_file=out)
        bad = results.set_index("label").loc["pod-bad"]
        self.assertRegex(bad["note"], "^error: .*unknown capture magic")
        self.assertTrue(bool(results.set_index("label").loc["pod-good", "tier_a_exact"]))
        self.assertEqual(len(pd.read_csv(out)), 2)
        self.assertIn("1 failed", pcap_diff.summarize(results))

    def test_summary_names_captures_cut_short_at_the_source(self):
        import pcap_diff
        results = pd.DataFrame([
            {"tier_a_exact": False, "mismatch_cells": 0, "rows_sponsor": 5, "rows_regen": 5,
             "windows": "equal", "differing_columns": "", "warnings": "truncated after frame 5",
             "note": ""},
            {"tier_a_exact": True, "mismatch_cells": 0, "rows_sponsor": 9, "rows_regen": 9,
             "windows": "equal", "differing_columns": "", "warnings": "", "note": ""}])
        self.assertIn("1 of 2 Tier-A exact; 1 more identical but cut short at the source",
                      pcap_diff.summarize(results))

    def test_menu_adds_pcap_diff_without_renumbering(self):
        names = [name for name, _, _ in demo.ITEMS]
        self.assertEqual((names[7], names[8], names[9]), ("Everything", "Tests", "Pcap diff"))
        # The full diff reads ~178 GB; "Everything" must not start it.
        self.assertNotIn("pcap_diff", demo.everything.__code__.co_names)

    def test_report_flag_reads_cached_output_without_drive(self):
        import tempfile
        out = Path(tempfile.mkdtemp()) / "pcap_diff.csv"
        pd.DataFrame([{"scenario": "benign", "label": "pod-nginx", "method": "tcp",
                       "tier_a_exact": True, "windows": "equal", "differing_columns": "",
                       "mismatch_cells": 0, "rows_sponsor": 4, "rows_regen": 4, "warnings": "",
                       "note": ""},
                      {"scenario": "benign", "label": "pod-lidar", "method": "tcp",
                       "tier_a_exact": False, "windows": "differ", "differing_columns": "eth_src:2;ts:1",
                       "mismatch_cells": 3, "rows_sponsor": 4, "rows_regen": 4, "warnings": "",
                       "note": ""}]).to_csv(out, index=False)
        run = subprocess.run([sys.executable, "pcap_diff.py", "--report", "--out", str(out)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("1 of 2 Tier-A exact; windows equal on 1", run.stdout)
        self.assertIn("eth_src:2", run.stdout)


# --- The converter against the sponsor's own CSVs, on the four smallest captures ---------

def _kubedata():
    """The dataset root from local_paths, or None when this machine has no copy."""
    try:
        import local_paths
    except ImportError:
        return None
    root = Path(getattr(local_paths, "KUBEDATA_ROOT", "") or "/nonexistent")
    return root if root.is_dir() else None


SMALL_CAPTURES = [("injection attack", "pod-nginx-tcp"), ("injection attack", "pod-nginx-ptcp"),
                  ("benign", "pod-nginx-tcp"), ("benign", "pod-nginx-ptcp")]


def _sponsor_pair(scenario, name):
    root = _kubedata() / scenario
    (pcap,) = (root / "pcapng files").rglob(f"{name}.pcapng")
    (csv_path,) = (root / "csv files").rglob(f"{name}.csv")
    return pcap, csv_path


@unittest.skipUnless(_kubedata(), "KUBEDATA_ROOT not set")
class PcapCorpusChecks(unittest.TestCase):
    def test_small_capture_matches_sponsor_csv(self):
        import csv
        import pcap_rows
        for scenario, name in SMALL_CAPTURES:
            with self.subTest(capture=f"{scenario}/{name}"):
                pcap, csv_path = _sponsor_pair(scenario, name)
                with open(csv_path, newline="") as handle:
                    theirs = list(csv.reader(handle))
                warnings = []
                ours = [[pcap_rows.format_cell(v) for v in row]
                        for row in pcap_rows.capture_rows(pcap, warnings)]
                self.assertEqual(theirs[0], pcap_rows.COLUMNS)
                self.assertEqual((len(ours), warnings), (len(theirs) - 1, []))
                mismatches = [(mine[0], column, a, b)
                              for mine, sponsor in zip(ours, theirs[1:])
                              for column, a, b in zip(pcap_rows.COLUMNS, mine, sponsor) if a != b]
                self.assertEqual(mismatches[:5], [], f"{len(mismatches)} cells differ")

    def test_small_capture_windows_match(self):
        import tempfile
        import pcap_rows
        for scenario, name in SMALL_CAPTURES:
            with self.subTest(capture=f"{scenario}/{name}"):
                pcap, csv_path = _sponsor_pair(scenario, name)
                regenerated = Path(tempfile.mkdtemp()) / f"{name}.csv"
                pcap_rows.write_capture_rows(pcap, regenerated)
                pd.testing.assert_frame_equal(make_windows(data_io.load_capture(str(regenerated))),
                                              make_windows(data_io.load_capture(str(csv_path))))


if __name__ == "__main__":
    unittest.main()