"""Run from this folder with: python -m unittest -v tests"""
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Run as `python dev/tests.py` from anywhere. dev/ holds experiments, verdicts and the
# statemachine shim; the Threat_Detection root holds core, methods, convert, viz and demo.
# Both go on the path, and the working directory becomes the root so the relative paths
# below (README.md, core/, dev/experiments/) resolve the same however the suite is started.
ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "dev"
for _folder in (ROOT, DEV):
    if str(_folder) not in sys.path:
        sys.path.insert(0, str(_folder))
os.chdir(ROOT)

import numpy as np
import pandas as pd

import demo
import statemachine

import core.data_io as data_io
import core.detectors as detectors
import core.evaluation as evaluation
import core.features as features
import core.reporting as reporting
from core.detectors import build
from core.features import make_windows, split_reference
from core.reporting import plot_detection_gap, threshold_table, to_events, write_events

from experiments import feature_value, flag_scores, metrics, sweep, windowed_scores
from verdicts import cv as cv_verdict
from verdicts import feature_set as feature_set_verdict
from verdicts import feature_set_hybrid as hybrid_verdict
from verdicts import flag as flag_verdict
from verdicts import load_behavior as load_behavior_verdict
from verdicts import root_count as root_verdict

from viz import cluster
from viz import layout
from viz import page as viz
from viz import sources

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
    detector = build("z_score", features=None).fit(benign)
    return detector.mean, detector.std


def _score_z(windows, mean, std, cutoff=None):
    """score against a given (mean, std) pair, as the old detect_anomalies() did.

    `cutoff` defaults to the module threshold; a fixture whose values sit near that
    threshold passes its own, so changing the constant cannot flip its expectations.
    """
    detector = build("z_score", features=None)
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
        import core.detectors
        self.assertEqual(set(detectors.REGISTRY), {"z_score", "isolation_forest", "one_class_svm"})

    def test_every_detector_flags_a_shift_and_spares_held_out_benign(self):
        import core.detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                det = make(features=None).fit(self.train).calibrate(self.holdout)
                flagged = det.flag(self.shifted)
                benign = det.flag(self.holdout)
                self.assertGreater(int(flagged.sum()), len(self.shifted) // 2)
                self.assertLessEqual(int(benign.sum()), max(1, len(self.holdout) // 8))

    def test_higher_score_means_more_anomalous_for_every_detector(self):
        """sklearn's decision_function runs the other way; the protocol must normalize it."""
        import core.detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                det = make(features=None).fit(self.train).calibrate(self.holdout)
                self.assertGreater(float(det.score(self.shifted).mean()),
                                   float(det.score(self.holdout).mean()),
                                   f"{name} scores the attack lower than benign")

    def test_flagging_before_calibration_is_an_error(self):
        import core.detectors
        for name, make in detectors.REGISTRY.items():
            with self.subTest(detector=name):
                with self.assertRaises(RuntimeError):
                    make(features=None).fit(self.train).flag(self.shifted)

    def test_z_score_uses_a_robust_baseline_for_a_lopsided_baseline(self):
        """A baseline with a few enormous windows must not turn ordinary held-out seconds into flags.

        Mean/std is the wrong summary when 8 of 47 benign windows carry the whole dynamic
        range: the standard deviation is set by those windows, so a window near either mode
        lands outside the cutoff and a third of held-out benign traffic flags. Median/MAD
        ignores them. This is the router-any shape.
        """
        import core.detectors
        # 40 quiet windows at 50, one 146 MB window, 6 held-out windows near the quiet mode.
        reference = pd.DataFrame({"payload_bytes": [50.0] * 40 + [146_000_000.0] + [50.0] * 6})
        detector = detectors.build("z_score", features=None).fit(reference).calibrate(reference)
        quiet = detector.annotate(reference.tail(6))
        self.assertEqual(int(quiet["anomaly"].sum()), 0,
                         "held-out windows in the dominant mode must not flag")
        bulk = detector.annotate(pd.DataFrame({"payload_bytes": [146_000_000.0]}))
        self.assertEqual(int(bulk["anomaly"].sum()), 1,
                         "the bulk-transfer window is still the thing that flags")

    def test_constant_feature_is_marked_degenerate_and_does_not_flag_everything(self):
        """MAD is 0 for a constant feature, and dividing by that 0 would flag every window."""
        import core.detectors
        reference = pd.DataFrame({"packet_count": [3.0] * 12})
        detector = detectors.build("z_score", features=None).fit(reference).calibrate(reference)
        # A constant feature has no scale, so it IS degenerate -- recorded, not hidden.
        self.assertTrue(bool(detector.degenerate["packet_count"]))
        same = detector.annotate(pd.DataFrame({"packet_count": [3.0]}))
        self.assertEqual(int(same["anomaly"].sum()), 0,
                         "an unchanged window on a constant feature is not a flag")
        moved = detector.annotate(pd.DataFrame({"packet_count": [9.0]}))
        self.assertEqual(int(moved["anomaly"].sum()), 1,
                         "movement on a scale-less feature is infinitely far from normal")

    def test_only_z_score_explains_which_feature_moved(self):
        import core.detectors
        self.assertIsNotNone(detectors.REGISTRY["z_score"]().explain)
        for name in ("isolation_forest", "one_class_svm"):
            with self.subTest(detector=name):
                self.assertIsNone(detectors.REGISTRY[name]().explain,
                                  "learned detectors report no attribution by design")

    def test_z_score_explain_names_the_feature_and_its_baseline(self):
        import core.detectors
        # Real baseline spread, so the strongest feature is decided by magnitude, not by a
        # zero-std tie (a zero std scores infinite the moment its feature moves at all).
        reference = pd.DataFrame({"packet_count": [9, 10, 11, 10],
                                  "total_bytes": [90, 100, 110, 100]})
        windows = pd.DataFrame({"packet_count": [10, 10], "total_bytes": [100, 400]})
        det = detectors.build("z_score", features=None).fit(reference)
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
        import core.detectors
        flags = pd.Series([False, True, True, True, True, False])
        self.assertEqual(detectors.persistent_mask(flags).tolist(),
                         [False, False, False, True, True, False])
        # a run of exactly PERSISTENCE_WINDOW marks only its final window
        exact = pd.Series([True, True, True, False, False])
        self.assertEqual(detectors.persistent_mask(exact).tolist(),
                         [False, False, True, False, False])

    def test_insufficient_baseline_is_rejected(self):
        import core.detectors
        for name in detectors.REGISTRY:
            with self.subTest(detector=name), self.assertRaisesRegex(ValueError, "Insufficient"):
                detectors.build(name, features=None).fit(pd.DataFrame({"packet_count": [1]}))


class LayeringChecks(unittest.TestCase):
    """The four pipeline layers depend one way, and the core never reaches outward.

    data_io -> features -> detectors -> reporting. Nothing downstream reaches back upstream.
    Enforced by reading the import statements, so a new import that breaks the rule fails
    here rather than surfacing as a surprise circular dependency later.
    """

    # The pipeline layers, in dependency order: a layer may import only earlier ones.
    LAYERS = ["data_io", "evaluation", "features", "detectors", "reporting"]

    def path_of(self, name):
        root = Path("core") if name in self.LAYERS else Path("dev/experiments")
        return root / f"{name}.py"

    def imported_modules(self, name):
        import ast
        tree = ast.parse(self.path_of(name).read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                # "from core.features import ..." is an intra-core edge; key it by the
                # layer name so the ordering rule still applies inside the package.
                parts = node.module.split(".")
                found.add(parts[1] if parts[0] == "core" and len(parts) > 1 else parts[0])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
        return found

    def test_a_layer_imports_only_layers_below_it(self):
        local = set(self.LAYERS)
        for position, layer in enumerate(self.LAYERS):
            allowed = set(self.LAYERS[:position])
            used = self.imported_modules(layer) & local
            self.assertLessEqual(used, allowed,
                                 f"{layer}.py imports {sorted(used - allowed)}, "
                                 f"which sit above it in {self.LAYERS}")

    def test_no_layer_imports_local_paths(self):
        # local_paths is the machine's own dataset location; only entry points read it, so
        # the layers stay portable and testable on any machine.
        for layer in self.LAYERS:
            self.assertNotIn("local_paths", self.imported_modules(layer),
                             f"{layer}.py must not import local_paths")

    def test_metrics_imports_nothing_from_the_project(self):
        # metrics is shared by every experiment; it must stay a leaf.
        project = ({p.stem for p in Path(".").glob("*.py")}
                   | {p.stem for p in Path("dev").glob("*.py")}
                   | {p.stem for p in Path("core").glob("*.py")}
                   | {p.stem for p in Path("dev/experiments").glob("*.py")})
        self.assertEqual(self.imported_modules("metrics") & project, set())

    def test_core_imports_nothing_from_the_outer_packages(self):
        """core/ is the product; experiments, verdicts, viz and convert are evidence.

        The dependency arrow points one way. If core ever imports an experiment, the
        "what ships" question stops having an answer.
        """
        outer = {"experiments", "verdicts", "viz", "convert", "demo", "metrics",
                 "statemachine", "methods", "local_paths"}
        for layer in self.LAYERS:
            used = self.imported_modules(layer) & outer
            self.assertEqual(used, set(), f"core/{layer}.py imports {sorted(used)}")

    def test_core_exports_a_resolvable_front_door(self):
        """`from core import X` is the documented way in; every advertised name must work."""
        import core
        missing = [name for name in core.__all__ if not hasattr(core, name)]
        self.assertEqual(missing, [], f"core.__all__ advertises undefined names: {missing}")
        self.assertIn("make_windows", core.__all__)
        self.assertIn("build_detector", core.__all__)

    def test_importing_reporting_does_not_load_matplotlib(self):
        # reporting carries console tables and the event stream; only its plotting needs
        # matplotlib. Loading it eagerly cost ~0.5 s on every import of the core.
        script = ("import sys; sys.path.insert(0, '.'); import core.reporting; "
                  "print('matplotlib' in sys.modules)")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "False")

    def test_reporting_still_plots_after_the_lazy_import(self):
        import tempfile
        path = Path(tempfile.mkdtemp()) / "gap.png"
        frame = pd.DataFrame({"group": ["all", "all"], "method": ["tcp", "tcp"],
                              "label": ["pod-nginx", "pod-nginx"],
                              "scenario": ["benign", "nginx attack"],
                              "flagged_fraction": [0.1, 0.6], "windows": [20, 20]})
        reporting.plot_detection_gap(frame, path=str(path))
        self.assertGreater(path.stat().st_size, 0)

    def test_the_layers_import_without_matplotlib(self):
        # reporting pins Agg and imports pyplot; importing it must not be required to use
        # the rest of the core. This guards the P1-5 move of matplotlib out of module scope.
        script = ("import sys; sys.path[:0] = ['.', 'dev']; "
                  "import core.data_io, core.features, core.detectors, experiments.metrics; "
                  "print('matplotlib' in sys.modules)")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "False")


class EntryPointChecks(unittest.TestCase):
    """A script run by path has its own directory as sys.path[0], so every entry point
    that lives in a subpackage has to put the project root back; one under dev/experiments
    also needs dev/ itself, for experiments and verdicts."""

    ENTRY_POINTS = {
        "viz/page.py": "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
        "viz/serve.py": "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
        **{f"dev/experiments/{name}.py":
           "sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]"
           for name in ("compare", "cv_calibration", "feature_set", "feature_value", "flag_scores",
                        "load_behavior", "pcap_diff", "pdfa_sweep", "sweep", "windowed_scores")},
    }

    def test_each_entry_point_bootstraps_the_project_root(self):
        for path, bootstrap in self.ENTRY_POINTS.items():
            with self.subTest(path=path):
                source = Path(path).read_text(encoding="utf-8")
                self.assertIn(bootstrap, source,
                              f"{path} cannot run as 'python {path}': add the bootstrap")


class DocumentationChecks(unittest.TestCase):
    """README.md (shipped code) and dev/README.md (development material) are the file maps a
    reader opens first; every module must be named in one of them."""

    SKIP = {"local_paths.py", "local_paths.example.py", "__init__.py"}

    def test_every_module_appears_in_the_readme(self):
        readme = (Path("README.md").read_text(encoding="utf-8")
                  + Path("dev/README.md").read_text(encoding="utf-8"))
        missing = []
        for path in sorted(Path(".").rglob("*.py")):
            if {".venv", "__pycache__", ".worktrees"} & set(path.parts):
                continue
            if path.name in self.SKIP:
                continue
            if str(path) not in readme:
                missing.append(str(path))
        self.assertEqual(missing, [], "neither README names: " + ", ".join(missing))


class FeatureLayerChecks(unittest.TestCase):
    def test_features_module_does_not_import_local_paths(self):
        script = "import sys; sys.path.insert(0, '.'); import core.features as f; print(f.WINDOW_SIZE)"
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_windows_keep_empty_seconds_and_leave_averages_undefined(self):
        import core.features
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
        import core.features
        packets = pd.DataFrame({"ts": [10.0, 10.5], "frame_len": [100, 200], "iat": [0.0, 0.5],
                                "dst_ip": ["a", "b"], "dst_port": [80, 443],
                                "tcp_syn": [1, 0], "tcp_rst": [0, 1]})
        windows = features.make_windows(packets)
        self.assertEqual(windows.loc[0, "syn_count"], 1)
        self.assertEqual(windows.loc[0, "rst_count"], 1)

    def test_payload_and_protocol_features_are_summed_per_window(self):
        """Payload and app-protocol columns are read on purpose; the 34-column set is a pool."""
        import core.features
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
        import core.features
        grouped = {f for members in features.FEATURE_GROUPS.values() for f in members}
        self.assertEqual(grouped, set(features.FEATURE_LABELS))

    def test_split_reference_holds_out_the_last_thirty_percent(self):
        import core.features
        windows = pd.DataFrame({"packet_count": range(100)})
        reference, holdout = features.split_reference(windows)
        self.assertEqual(len(reference), 70)
        self.assertEqual(len(holdout), 30)
        self.assertEqual(holdout.index.tolist(), list(range(70, 100)))


class DataIoChecks(unittest.TestCase):
    def test_io_layer_does_not_need_local_paths(self):
        """data_io must import with no machine-specific path file present."""
        script = ("import sys; sys.path.insert(0, '.');"
                  " import core.data_io as d; print(len(d.PACKET_COLUMNS))")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_load_capture_normalizes_headers_and_keeps_needed_columns(self):
        import tempfile
        import core.data_io
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
        import core.data_io
        path = Path(tempfile.mkdtemp()) / "pod-nginx-tcp.csv"
        path.write_text("ts,iat,frame_len,dst_ip,dst_port\n10.0,0.1,100,::1,8080\n")
        with self.assertRaisesRegex(ValueError, "Missing packet columns"):
            data_io.load_capture(str(path))

    def test_output_path_is_anchored_to_the_module_not_the_cwd(self):
        import core.data_io
        self.assertTrue(data_io.OUTPUT_DIR.is_absolute())
        self.assertEqual(data_io.OUTPUT_DIR.parent,
                         Path(data_io.__file__).resolve().parent.parent)


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
        results = sweep.run_sweep(described, groups=("full",))   # the fake captures carry no protocol columns
        attack = results[results["scenario"].eq("nginx attack")].iloc[0]
        benign = results[results["scenario"].eq("benign")].iloc[0]
        self.assertGreater(attack["flagged_fraction"], 0.9)   # 8x rate shift, same view
        self.assertLess(benign["flagged_fraction"], 0.2)       # holdout windows, matched reference
        self.assertEqual(attack["group"], "full")
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
        results = sweep.run_sweep(described, groups=("full",))
        attack = results[results["scenario"].eq("nginx attack")].iloc[0]
        self.assertIn("excluded", attack["note"])
        self.assertEqual(int(attack["windows"]), 0)


class FeatureValueChecks(unittest.TestCase):
    def test_auc_and_budget_detection_behave(self):
        from experiments import feature_value
        self.assertEqual(feature_value.separation_auc([1, 2, 3], [4, 5, 6]), 1.0)
        self.assertEqual(feature_value.separation_auc([4, 5, 6], [1, 2, 3]), 0.0)
        self.assertEqual(feature_value.separation_auc([1, 2, 3], [1, 2, 3]), 0.5)
        self.assertTrue(pd.isna(feature_value.separation_auc([1], [2])))
        # a clean shift is flagged; attack windows that look benign are not
        benign = list(range(100, 120))
        self.assertGreater(feature_value.detection_at_budget(benign, benign, [1000, 1050, 1100]), 0.9)
        self.assertLess(feature_value.detection_at_budget(benign, benign, benign[8:11]), 0.5)


class AdoptedFeatureChecks(unittest.TestCase):
    """The detectors read the nine adopted features by default, and say so."""

    def test_the_list_is_the_candidate_the_rule_judged(self):
        from core.features import DETECTION_FEATURES
        self.assertEqual(set(DETECTION_FEATURES), set(hybrid_verdict.CANDIDATE))
        self.assertEqual(len(DETECTION_FEATURES), 9)

    def test_default_detector_reads_the_nine_and_ignores_the_rest(self):
        from core.features import DETECTION_FEATURES
        rng = np.random.default_rng(0)
        frame = pd.DataFrame(rng.normal(10, 1, (40, 13)),
                             columns=list(DETECTION_FEATURES) + ["total_bytes", "payload_bytes",
                                                                 "mean_packet_size", "mean_iat"])
        detector = detectors.build("z_score").pipeline(frame.iloc[:28], frame.iloc[28:])
        self.assertEqual(list(detector.mean.index), list(DETECTION_FEATURES))
        wild = frame.copy()
        wild["total_bytes"] = 1e9          # a volume feature the detector must not read
        pd.testing.assert_series_equal(detector.flag(wild), detector.flag(frame))

    def test_features_none_reads_every_column(self):
        frame = pd.DataFrame({"a": [1.0, 2.0, 3.0, 2.0, 1.0, 2.0], "b": [5.0, 6, 5, 6, 5, 6]})
        detector = detectors.build("z_score", features=None).fit(frame)
        self.assertEqual(list(detector.mean.index), ["a", "b"])


class DetectorComparisonChecks(unittest.TestCase):
    def setUp(self):
        self.train = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 10, 11, 9, 10, 10, 11, 12]})
        self.holdout = pd.DataFrame({"packet_count": [10, 11, 9, 10, 12, 11, 10, 9]})
        self.shifted = pd.DataFrame({"packet_count": [900, 950, 1000, 920, 880, 970, 910, 990, 930]})

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_every_learned_detector_separates_a_shifted_rate_from_held_out_benign(self):
        import core.detectors
        learned = [name for name in detectors.REGISTRY if name != "z_score"]
        self.assertEqual(set(learned), {"isolation_forest", "one_class_svm"})
        for name in learned:
            with self.subTest(detector=name):
                detector = detectors.build(name, features=None).pipeline(self.train, self.holdout)
                flagged = detector.flag(self.shifted)
                benign = detector.flag(self.holdout)
                self.assertGreater(int(flagged.sum()), len(self.shifted) // 2)
                self.assertLessEqual(int(benign.sum()), 1)

    @unittest.skipUnless(importlib.util.find_spec("sklearn"), "scikit-learn not installed")
    def test_compare_detectors_scores_every_detector_on_the_same_windows(self):
        from experiments import compare
        comparison = compare.compare_detectors(described_from(fake_stratum(active=40)), features=None)
        self.assertEqual(set(comparison["detector"]),
                         {"z_score", "isolation_forest", "one_class_svm"})
        per_detector = comparison.groupby("detector")["windows"].apply(list)
        self.assertTrue(all(values == per_detector.iloc[0] for values in per_detector),
                        "every detector must see the same windows")
        self.assertEqual(len(comparison), 2 * 3)  # two scenarios x three detectors

    def test_chart_name_carries_the_svm_nu(self):
        import inspect
        import core.detectors
        import core.data_io
        import core.reporting
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
        from experiments import compare
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
        from core.reporting import write_report
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
        import core.data_io
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

    def test_score_terms_sum_to_score(self):
        scored = statemachine.WindowedFrequencyScorer(self.pdfa, 3.0)
        termed = statemachine.WindowedFrequencyScorer(self.pdfa, 3.0)
        traces = [("a", "b", "c"), ("a", "b", "b"), ("c", "a"), ("b", "b")] * 6
        for when, trace in enumerate(traces):
            terms, _ = termed.score_terms(trace, when * 0.7)
            self.assertEqual(sum(map(sum, terms)), scored.score(trace, when * 0.7))
            self.assertEqual(len(terms), len(statemachine.trace_states(self.pdfa, trace)))

    def test_score_terms_report_expiry(self):
        scorer = statemachine.WindowedFrequencyScorer(self.pdfa, forget_seconds=2.0)
        _, expired = scorer.score_terms(("a", "b", "b"), 0.0)
        self.assertEqual(expired, [])
        _, expired = scorer.score_terms(("c", "a"), 5.0)
        self.assertEqual(len(expired), 3)
        self.assertTrue(all(when == 0.0 for when, _ in expired))

    def test_frequency_cutoff_flags_top_budget(self):
        scores = np.arange(100.0)
        self.assertEqual(statemachine.frequency_cutoff(scores), np.quantile(scores, 0.95))
        with_nan = np.append(scores, np.nan)
        self.assertEqual(statemachine.frequency_cutoff(with_nan), np.quantile(scores, 0.95))

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

    LEARN_TRACES = ([("a", "b", "c")] * 12 + [("a", "b", "b")] * 12 + [("c", "a")] * 12
                    + [("b", "a", "c")] * 5)

    @staticmethod
    def transitions(pdfa):
        ids = {id(node): i for i, node in enumerate(statemachine.pdfa_states_in_order(pdfa))}
        return sorted((ids[id(node)], symbol, prob) for node, out in pdfa.probs.values()
                      for symbol, (_, prob) in out.items())

    def test_learn_trace_does_not_change_the_machine(self):
        plain = statemachine.learn_pdfa(self.LEARN_TRACES)
        traced = statemachine.learn_pdfa(self.LEARN_TRACES, trace=[])
        self.assertEqual(plain.n_states, traced.n_states)
        self.assertEqual(self.transitions(plain), self.transitions(traced))

    def test_learn_trace_records_pta_then_steps(self):
        events = []
        pdfa = statemachine.learn_pdfa(self.LEARN_TRACES, trace=events)
        self.assertEqual(events[0][0], "pta")
        self.assertIsInstance(events[0][1], statemachine._Node)
        kinds = [step["kind"] for step in events[1:]]
        self.assertTrue(set(kinds) <= {"merge", "promote"})
        self.assertEqual(1 + kinds.count("promote"), pdfa.n_states)
        self.assertIn("merge", kinds)

    def test_learn_trace_bound_matches_hoeffding(self):
        events = []
        statemachine.learn_pdfa(self.LEARN_TRACES, trace=events)
        for step in events[1:]:
            self.assertEqual(step["bound"], statemachine._hoeffding(step["red_visits"],
                                                                    step["blue_visits"]))
            if step["kind"] == "merge":
                self.assertTrue(all(abs(p_red - p_blue) < step["bound"]
                                    for _, p_red, p_blue in step["tests"]))
            self.assertIsInstance(step["path"], tuple)

    def test_learn_trace_paths_exist_in_the_prefix_tree(self):
        """After a fold, a red state owns children from other branches; paths stay original."""
        rng = np.random.default_rng(0)
        weights = np.array([0.5 ** i for i in range(8)])
        stream = list(rng.choice(list("abcdefgh"), size=150, p=weights / weights.sum()))
        traces = statemachine.make_traces(stream)
        events = []
        statemachine.learn_pdfa(traces, trace=events)
        prefixes = {tuple(trace[:i]) for trace in traces for i in range(len(trace) + 1)}
        self.assertGreater(len(events), 5)
        for step in events[1:]:
            self.assertTrue(step["path"] in prefixes, step["path"])
            self.assertTrue(step["red_path"] in prefixes, step["red_path"])

    def test_learn_trace_records_every_red_tried(self):
        """A promotion failed against every kept state; a merge failed against the earlier ones."""
        rng = np.random.default_rng(0)
        weights = np.array([0.5 ** i for i in range(8)])
        stream = list(rng.choice(list("abcdefgh"), size=150, p=weights / weights.sum()))
        events = []
        statemachine.learn_pdfa(statemachine.make_traces(stream), trace=events)
        reds = 1
        for step in events[1:]:
            attempts = step["attempts"]
            passed = [all(abs(a - b) < attempt["bound"] for _, a, b in attempt["tests"])
                      for attempt in attempts]
            self.assertEqual(step["red_path"], attempts[-1]["red_path"])
            if step["kind"] == "promote":
                self.assertEqual(len(attempts), reds)
                self.assertFalse(any(passed))
                reds += 1
            else:
                self.assertTrue(passed[-1])
                self.assertFalse(any(passed[:-1]))
        self.assertGreaterEqual(reds, 2)
        self.assertTrue(any(len(step["attempts"]) > 1 for step in events[1:]))

    def test_learn_trace_pta_is_unmerged(self):
        """The recorded prefix tree keeps one node per distinct prefix, before any fold."""
        events = []
        statemachine.learn_pdfa(self.LEARN_TRACES, trace=events)
        prefixes = {trace[:i] for trace in self.LEARN_TRACES for i in range(len(trace) + 1)}
        count, stack = 0, [events[0][1]]
        while stack:
            node = stack.pop()
            count += 1
            stack.extend(node.children.values())
        self.assertEqual(count, len(prefixes))

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
            self.assertEqual(set(event), {"version", "detector", "t", "severity", "locations"})
        first = events[0]
        self.assertEqual(first["version"], "LogV1")
        self.assertEqual(first["detector"], "z_score")
        self.assertEqual(first["locations"], {"pods": ["pod-nginx"]})

    def test_events_carry_the_window_second_so_they_can_be_ordered(self):
        # LogV0 had no time, so a consumer could not order, dedupe or expire an incident.
        events = to_events(self.flagged_frame(), detector="z_score", pods=["pod-nginx"])
        self.assertEqual([e["t"] for e in events], [3, 5, 6])
        for event in events:
            self.assertIsInstance(event["t"], int)
        self.assertEqual([e["t"] for e in events], sorted(e["t"] for e in events))

    def test_the_pair_demo_actually_writes_the_event_stream(self):
        # to_events/write_events were tested but never called: the contract was documented
        # and consumed downstream while nothing produced it, so outputs/events.jsonl went
        # stale. Pin the call site, not just the functions.
        source = Path("demo.py").read_text(encoding="utf-8")
        self.assertIn("write_events(", source)
        self.assertIn("to_events(", source)

    def test_event_lines_are_valid_json(self):
        import json
        events = to_events(self.flagged_frame(), detector="z_score", pods=["pod-nginx"])
        for event in events:
            json.dumps(event, allow_nan=False)
        import tempfile
        path = Path(tempfile.mkdtemp()) / "events.jsonl"
        write_events(events, path=str(path))
        self.assertEqual(len(path.read_text().strip().split("\n")), 3)


class MetricsChecks(unittest.TestCase):
    """One statistic, one implementation, and an explicit policy for thin strata."""

    def test_both_policies_agree_wherever_both_accept(self):
        # The old copies drifted only on thin input; everywhere else they must be identical.
        rng = np.random.default_rng(3)
        for benign, attack in ((rng.normal(0, 1, 60), rng.normal(1, 1, 45)),
                               (np.round(rng.normal(0, 1, 40), 0), np.round(rng.normal(1, 1, 30), 0)),
                               ([1.0, 2.0, 3.0], [4.0, 5.0, 6.0])):
            self.assertAlmostEqual(metrics.auroc(benign, attack),
                                   metrics.auroc_ranked(benign, attack), places=12)

    def test_ranked_returns_nan_on_a_thin_stratum(self):
        # One attack point against one benign point ranks 1.0 by construction, which would
        # flatter a mean over strata. The feature ranking wants NaN here.
        self.assertTrue(np.isnan(metrics.auroc_ranked([1.0], [2.0])))
        self.assertEqual(metrics.auroc([1.0], [2.0]), 1.0)

    def test_pairwise_raises_when_a_side_is_empty(self):
        with self.assertRaises(ValueError):
            metrics.auroc([], [1.0])
        with self.assertRaises(ValueError):
            metrics.auroc([1.0], [])

    def test_auroc_ignores_unscored_windows(self):
        self.assertEqual(metrics.auroc([np.nan, 0.0], [1.0, np.inf]), 1.0)
        self.assertTrue(np.isnan(metrics.auroc_ranked([np.nan], [np.inf, 1.0])))

    def test_detection_reports_the_rate_it_actually_cost(self):
        detection, realised = metrics.detection_at_rate([0.0, 1.0, 2.0, 3.0, 4.0], [4.0, 5.0], 0.2)
        self.assertEqual(realised, 0.2)
        self.assertEqual(detection, 1.0)

    def test_the_old_public_names_delegate_to_the_one_implementation(self):
        # feature_value and flag_scores keep their names for their callers, but there is
        # now exactly one implementation behind each policy.
        for benign, attack in (([1.0, 2.0, 3.0], [4.0, 5.0]), ([1.0, 2.0, 3.0], [0.0, 1.0])):
            self.assertEqual(feature_value.separation_auc(benign, attack),
                             metrics.auroc_ranked(benign, attack))
            self.assertEqual(flag_scores.auroc(benign, attack), metrics.auroc(benign, attack))
        self.assertTrue(np.isnan(feature_value.separation_auc([1.0], [2.0])))


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


class HybridFeatureSetChecks(unittest.TestCase):
    """The hybrid candidate and the guarantee that it is judged by the same rule."""

    def test_candidate_is_the_eight_plus_packet_count(self):
        self.assertEqual(set(hybrid_verdict.CANDIDATE),
                         set(hybrid_verdict.PREVIOUS_CANDIDATE) | {"packet_count"})
        self.assertEqual(len(hybrid_verdict.CANDIDATE), len(set(hybrid_verdict.CANDIDATE)))

    def test_candidate_columns_are_real_features(self):
        from core.features import FEATURE_GROUPS
        known = {f for group in FEATURE_GROUPS.values() for f in group}
        self.assertLessEqual(set(hybrid_verdict.CANDIDATE), known)

    def test_thresholds_are_the_previous_rules(self):
        for name in ("MIN_ALERT_REDUCTION", "MAX_AUROC_LOSS", "MAX_DETECTION_LOSS",
                     "MIN_BENIGN_WINDOWS"):
            self.assertIs(getattr(hybrid_verdict, name), getattr(feature_set_verdict, name))
        self.assertIs(hybrid_verdict.decide, feature_set_verdict.decide)


class FeatureSetVerdictChecks(unittest.TestCase):
    """The eight-feature rule, fixed before the experiment that judges it."""

    def summary(self, alerts=(20, 5), auroc=(0.65, 0.65), detection=(0.2, 0.2), windows=200):
        method = {"benign_windows": windows,
                  "persistent": {"all": alerts[0], "candidate": alerts[1]}}
        for scenario in feature_set_verdict.SCENARIOS:
            method[scenario] = {"auroc": {"all": auroc[0], "candidate": auroc[1]},
                                "detection": {"all": detection[0], "candidate": detection[1]}}
        return {m: {k: (dict(v) if isinstance(v, dict) else v) for k, v in method.items()}
                for m in feature_set_verdict.METHODS}

    def test_keep_when_alerts_fall_and_attacks_hold(self):
        self.assertEqual(feature_set_verdict.decide(self.summary())[0], "keep")

    def test_drop_when_alerts_barely_fall(self):
        verdict, reasons = feature_set_verdict.decide(self.summary(alerts=(20, 15)))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("persistent alerts" in r for r in reasons))

    def test_drop_when_one_scenario_loses_ranking(self):
        summary = self.summary()
        summary["tcp"]["lidar attack"]["auroc"]["candidate"] = 0.50
        verdict, reasons = feature_set_verdict.decide(summary)
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("tcp/lidar attack" in r for r in reasons))

    def test_drop_when_one_method_fails(self):
        summary = self.summary()
        summary["ptcp"]["nginx attack"]["detection"]["candidate"] = 0.0
        self.assertEqual(feature_set_verdict.decide(summary)[0], "drop")

    def test_loss_at_the_limit_is_allowed(self):
        summary = self.summary(auroc=(0.70, 0.60))
        self.assertEqual(feature_set_verdict.decide(summary)[0], "keep")

    def test_undecidable_without_windows_or_baseline_alerts(self):
        self.assertEqual(feature_set_verdict.decide(self.summary(windows=10))[0], "undecidable")
        self.assertEqual(feature_set_verdict.decide(self.summary(alerts=(0, 0)))[0], "undecidable")


class LoadBehaviorVerdictChecks(unittest.TestCase):
    """The load-versus-behavior rule, fixed before the comparison was measured."""

    def bulk(self, behavior=0.5, control=0.95, n=20, taps=3):
        return [{"label": f"tap-{i}", "behavior_auroc": behavior, "z_auroc": control,
                 "n_pre": n, "n_post": n} for i in range(taps)]

    def attacks(self, z=40, behavior=30):
        return [{"scenario": s, "warm": 100, "z_flagged": z, "behavior_flagged": behavior}
                for s in load_behavior_verdict.SCENARIOS]

    def benign(self, z=40, behavior=5):
        return [{"windows": 100, "z_flagged": z, "behavior_flagged": behavior}]

    def test_separate_when_both_claims_hold(self):
        verdict, _ = load_behavior_verdict.decide(self.bulk(), self.attacks(), self.benign())
        self.assertEqual(verdict, "separate")

    def test_tag_when_behavior_misses_attacks(self):
        verdict, reasons = load_behavior_verdict.decide(
            self.bulk(), self.attacks(z=60, behavior=10), self.benign())
        self.assertEqual(verdict, "tag")
        self.assertTrue(any("injection" in r for r in reasons))

    def test_tag_when_behavior_is_not_quieter_on_benign(self):
        verdict, _ = load_behavior_verdict.decide(
            self.bulk(), self.attacks(), self.benign(z=10, behavior=10))
        self.assertEqual(verdict, "tag")

    def test_drop_when_behavior_sees_the_regime_change(self):
        verdict, _ = load_behavior_verdict.decide(
            self.bulk(behavior=0.9), self.attacks(), self.benign())
        self.assertEqual(verdict, "drop")

    def test_blind_control_sets_a_tap_aside(self):
        rows = self.bulk(taps=2) + self.bulk(control=0.55, behavior=0.95, taps=1)
        verdict, _ = load_behavior_verdict.claim_a(rows)
        self.assertEqual(verdict, "pass")

    def test_undecidable_with_too_few_bulk_taps(self):
        verdict, _ = load_behavior_verdict.decide(
            self.bulk(taps=1), self.attacks(), self.benign())
        self.assertEqual(verdict, "undecidable")

    def test_undecidable_scenario_with_too_few_windows(self):
        attacks = self.attacks()
        attacks[0]["warm"] = 5
        verdict, _ = load_behavior_verdict.claim_b(attacks, self.benign())
        self.assertEqual(verdict, "undecidable")


class RootVerdictChecks(unittest.TestCase):
    """The start-state count rule, fixed before either variant's AUROC was computed."""

    def rows(self, changes, group="steady"):
        rows = []
        for index, change in enumerate(changes):
            for counts, auroc in (("visits", 0.70), ("entries", 0.70 + change)):
                rows.append({"label": f"tap-{index}", "scenario": "lidar attack",
                             "method": "tcp", "group": group, "train_counts": counts,
                             "auroc": auroc})
        return rows

    def test_keep_when_nothing_loses(self):
        verdict, reasons = root_verdict.decide(self.rows([0.0] * 12))
        self.assertEqual(verdict, "keep")
        self.assertTrue(reasons)

    def test_keep_at_the_exact_boundaries(self):
        changes = [-0.05] + [0.0] * 4 + [0.0] * 5          # mean exactly -0.005, worst -0.05
        self.assertEqual(root_verdict.decide(self.rows(changes))[0], "keep")

    def test_drop_when_one_stratum_loses_too_much(self):
        verdict, reasons = root_verdict.decide(self.rows([-0.06] + [0.01] * 11))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("tap-0" in reason for reason in reasons))

    def test_drop_when_the_mean_falls(self):
        verdict, reasons = root_verdict.decide(self.rows([-0.02] * 12))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("mean AUROC change" in reason for reason in reasons))

    def test_bulk_and_unpaired_rows_never_decide(self):
        rows = self.rows([-0.5] * 12, group="bulk") + self.rows([0.0] * 9)
        rows.append({"label": "lonely", "scenario": "lidar attack", "method": "tcp",
                     "group": "steady", "train_counts": "visits", "auroc": 0.9})
        rows.append({"label": "nan", "scenario": "lidar attack", "method": "tcp",
                     "group": "steady", "train_counts": "visits", "auroc": float("nan")})
        verdict, reasons = root_verdict.decide(rows)
        self.assertEqual(verdict, "undecidable")
        self.assertTrue(any("9 paired" in reason for reason in reasons))


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


def packets(rows):
    """Packet frame from (src_ip, dst_ip, src_port, dst_port) tuples, all tcp."""
    return pd.DataFrame(rows, columns=["src_ip", "dst_ip", "src_port", "dst_port"]
                        ).assign(proto="tcp")


class ClusterChecks(unittest.TestCase):
    """The cluster drawing is inferred from traffic, so each inference rule is pinned here."""

    CONTROL, WORKER = "192.168.50.32", "192.168.50.29"

    def captures(self):
        return {
            # a node capture on the worker: its own address and its pod subnet dominate
            "node-child1": packets(
                [(self.WORKER, self.CONTROL, 40000, 6443)] * 30
                + [("10.42.3.4", "10.43.0.10", 41000, 53)] * 10
                + [("10.42.3.7", self.CONTROL, 41001, 2049)] * 4
                + [(self.WORKER, "192.168.50.1", 41002, 53)] * 3
                + [("127.0.0.1", "127.0.0.1", 5000, 5001)] * 50),
            # a node capture on the control plane
            "node-child4": packets(
                [(self.CONTROL, self.CONTROL, 40001, 2049)] * 60
                + [("10.42.0.56", "8.8.8.8", 42000, 53)] * 8
                + [(self.CONTROL, "224.0.0.1", 1, 1)] * 3),
            # a pod with its own address
            "pod-nginx": packets([("10.42.0.56", "10.43.0.10", 43000, 53)] * 20
                                 + [("::1", "::1", 1, 8080)] * 5),
            # a host-network pod: no pod address of its own, looks like the worker
            "pod-lidar": packets([(self.WORKER, self.CONTROL, 40000, 6443)] * 20
                                 + [("10.42.3.4", "10.43.0.10", 41000, 53)] * 3),
            "router-flannel": packets([("10.42.0.56", "10.42.3.4", 44000, 53)] * 5),
            "router-any": packets([(self.WORKER, self.CONTROL, 40000, 6443)] * 30
                                  + [("10.42.9.5", "1.1.1.1", 45000, 443)] * 2),
        }

    def test_pod_named_from_pod_capture(self):
        pods = {pod["id"]: pod for pod in cluster.infer_cluster(self.captures())["pods"]}
        self.assertEqual(pods["pod:10.42.0.56"]["name"], "pod-nginx")
        self.assertFalse(pods["pod:10.42.0.56"]["host_network"])

    def test_host_network_pod_lands_on_its_host(self):
        pods = {pod["id"]: pod for pod in cluster.infer_cluster(self.captures())["pods"]}
        lidar = pods["pod:pod-lidar"]
        self.assertTrue(lidar["host_network"])
        self.assertEqual(lidar["host"], f"host:{self.WORKER}")
        self.assertEqual(lidar["name"], "pod-lidar")

    def test_node_capture_claims_pod_subnet(self):
        found = cluster.infer_cluster(self.captures())
        hosts = {host["id"]: host for host in found["hosts"]}
        self.assertEqual(hosts[f"host:{self.WORKER}"]["pod_cidr"], "10.42.3.0/24")
        self.assertEqual(hosts[f"host:{self.WORKER}"]["name"], "child1")
        self.assertEqual(hosts[f"host:{self.CONTROL}"]["pod_cidr"], "10.42.0.0/24")
        pods = {pod["id"]: pod for pod in found["pods"]}
        self.assertEqual(pods["pod:10.42.3.7"]["host"], f"host:{self.WORKER}")

    def test_each_node_capture_claims_exactly_one_host(self):
        found = cluster.infer_cluster(self.captures())
        named = [host["name"] for host in found["hosts"] if host["name"]]
        self.assertEqual(sorted(named), ["child1", "child4"])

    def test_broadcast_is_not_a_host(self):
        captures = self.captures()
        captures["node-child1"] = pd.concat([captures["node-child1"], packets(
            [(self.WORKER, "255.255.255.255", 68, 67)] * 2
            + [(self.WORKER, "192.168.50.255", 137, 137)] * 2)])
        found = cluster.infer_cluster(captures)
        everything = {e["id"] for kind in ("hosts", "external") for e in found[kind]}
        self.assertFalse(any(m.endswith(".255") for m in everything))

    def test_control_plane_from_apiserver_port(self):
        hosts = {h["id"]: h for h in cluster.infer_cluster(self.captures())["hosts"]}
        self.assertIn("control-plane", hosts[f"host:{self.CONTROL}"]["roles"])
        self.assertIn("nfs", hosts[f"host:{self.CONTROL}"]["roles"])
        self.assertEqual(hosts[f"host:{self.WORKER}"]["roles"], ["worker"])

    def test_unclaimed_subnet_is_unattributed(self):
        pods = {pod["id"]: pod for pod in cluster.infer_cluster(self.captures())["pods"]}
        self.assertIsNone(pods["pod:10.42.9.5"]["host"])

    def test_loopback_multicast_and_public_are_not_cluster_members(self):
        found = cluster.infer_cluster(self.captures())
        members = {e["id"] for kind in ("hosts", "pods", "services", "external")
                   for e in found[kind]}
        self.assertFalse(any("127.0.0.1" in m or "::1" in m or "224.0.0.1" in m
                             for m in members))
        self.assertIn("internet", members)
        self.assertNotIn("pod:8.8.8.8", members)
        services = {s["id"]: s for s in found["services"]}
        self.assertEqual(services["svc:10.43.0.10"]["port_names"], ["dns"])

    def test_router_vantages_attach_by_suffix(self):
        vantages = {v["label"]: v for v in cluster.infer_cluster(self.captures())["vantages"]}
        self.assertEqual(vantages["router-flannel"]["element"], "overlay")
        self.assertEqual(vantages["router-any"]["element"], "uplink")
        self.assertEqual(vantages["node-child4"]["element"], f"host:{self.CONTROL}")
        self.assertEqual(vantages["pod-nginx"]["element"], "pod:10.42.0.56")
        self.assertEqual(vantages["pod-lidar"]["level"], "pod")

    def test_edges_take_the_best_vantage_not_the_sum(self):
        edges = cluster.infer_cluster(self.captures())["edges"]
        api = [e for e in edges if {e["src"], e["dst"]} == {f"host:{self.WORKER}",
                                                            f"host:{self.CONTROL}"}]
        self.assertEqual(len(api), 1)
        self.assertEqual(api[0]["packets"], 30)
        self.assertEqual(api[0]["ports"], ["kube-apiserver"])

    def test_vantage_without_pods_still_builds(self):
        found = cluster.infer_cluster({"router-any": self.captures()["router-any"]})
        self.assertEqual([v["label"] for v in found["vantages"]], ["router-any"])
        self.assertTrue(found["hosts"])

    def test_api_client_is_not_promoted_to_host(self):
        captures = self.captures()
        captures["router-any"] = pd.concat([captures["router-any"], packets(
            [("192.168.50.77", self.CONTROL, 50000, 6443)] * 4)])
        found = cluster.infer_cluster(captures)
        self.assertNotIn("host:192.168.50.77", {h["id"] for h in found["hosts"]})
        lan = {e["id"]: e for e in found["external"]}
        self.assertIn("lan:192.168.50.77", lan)
        self.assertIn("kube-apiserver", lan["lan:192.168.50.77"]["note"])

    def test_host_network_pod_ignores_a_few_remote_pod_packets(self):
        captures = self.captures()
        captures["pod-lidar"] = packets([(self.WORKER, self.CONTROL, 40000, 6443)] * 40
                                        + [(self.WORKER, "10.42.0.56", 40001, 80)] * 3)
        pods = {p["id"]: p for p in cluster.infer_cluster(captures)["pods"]}
        self.assertEqual(pods["pod:pod-lidar"]["host"], f"host:{self.WORKER}")

    def test_host_network_pod_is_not_named_after_its_peer(self):
        captures = self.captures()
        captures["pod-lidar"] = packets([(self.WORKER, "10.42.3.4", 40000, 53)] * 30)
        found = cluster.infer_cluster(captures)
        pods = {p["id"]: p for p in found["pods"]}
        self.assertIsNone(pods["pod:10.42.3.4"]["name"])
        self.assertTrue(pods["pod:pod-lidar"]["host_network"])

    def test_pod_subnet_claims_are_one_to_one(self):
        captures = self.captures()
        captures["node-child2"] = packets([("192.168.50.22", self.CONTROL, 40000, 6443)] * 30
                                          + [("192.168.50.22", "10.42.0.56", 40001, 80)] * 25)
        hosts = {h["id"]: h for h in cluster.infer_cluster(captures)["hosts"]}
        self.assertEqual(hosts[f"host:{self.CONTROL}"]["pod_cidr"], "10.42.0.0/24")
        self.assertIsNone(hosts["host:192.168.50.22"]["pod_cidr"])

    def test_locate_places_addresses_benign_never_showed(self):
        found = cluster.infer_cluster(self.captures())
        self.assertEqual(cluster.locate(found, "10.42.3.99"),
                         {"id": "pod:10.42.3.99", "ip": "10.42.3.99", "kind": "pod",
                          "host": f"host:{self.WORKER}", "name": None, "host_network": False,
                          "new": True})
        self.assertEqual(cluster.locate(found, "192.168.50.88")["id"], "lan:192.168.50.88")
        self.assertEqual(cluster.locate(found, "10.43.0.99")["id"], "svc:10.43.0.99")
        self.assertEqual(cluster.locate(found, "9.9.9.9")["id"], "internet")
        self.assertIsNone(cluster.locate(found, "127.0.0.1"))

    def test_element_of_maps_addresses(self):
        found = cluster.infer_cluster(self.captures())
        element_of = cluster.element_index(found)
        self.assertEqual(element_of("10.42.0.56"), "pod:10.42.0.56")
        self.assertEqual(element_of(self.WORKER), f"host:{self.WORKER}")
        self.assertEqual(element_of("10.43.0.10"), "svc:10.43.0.10")
        self.assertEqual(element_of("9.9.9.9"), "internet")
        self.assertIsNone(element_of("127.0.0.1"))


class LayoutChecks(unittest.TestCase):
    """Positions are computed, so they must be deterministic and stay inside the canvas."""

    TRACES = ([("a", "b", "c")] * 12 + [("a", "b", "b")] * 12 + [("c", "a")] * 12
              + [("b", "a", "c")] * 5 + [("a",)] * 3)

    def learned(self):
        events = []
        pdfa = statemachine.learn_pdfa(self.TRACES, trace=events)
        return pdfa, events[0][1]

    def test_icicle_children_tile_parent(self):
        _, root = self.learned()
        nodes = layout.icicle(root)
        by_id = {node["id"]: node for node in nodes}
        self.assertEqual((nodes[0]["x0"], nodes[0]["x1"]), (0.0, 1.0))
        for parent in nodes:
            children = [n for n in nodes if n["parent"] == parent["id"]]
            if not children:
                continue
            span = parent["x1"] - parent["x0"]
            covered = sum(c["x1"] - c["x0"] for c in children)
            ended = span * parent["final"] / parent["visits"]
            self.assertAlmostEqual(covered + ended, span, places=12)
            self.assertAlmostEqual(min(c["x0"] for c in children), parent["x0"], places=12)
            self.assertTrue(all(by_id[c["parent"]]["depth"] == c["depth"] - 1 for c in children))

    def test_icicle_is_deterministic_and_breadth_first(self):
        _, root = self.learned()
        first, second = layout.icicle(root), layout.icicle(root)
        self.assertEqual(first, second)
        self.assertEqual([n["id"] for n in first], list(range(len(first))))
        self.assertEqual([n["depth"] for n in first], sorted(n["depth"] for n in first))
        self.assertEqual(first[0]["path"], ())

    def test_layered_root_is_leftmost(self):
        pdfa, _ = self.learned()
        states = layout.layered(pdfa)["states"]
        self.assertEqual(states[0]["x"], min(s["x"] for s in states))

    def test_layered_is_deterministic(self):
        pdfa, _ = self.learned()
        self.assertEqual(layout.layered(pdfa), layout.layered(pdfa))

    def test_layered_coordinates_in_unit_square(self):
        pdfa, _ = self.learned()
        for state in layout.layered(pdfa)["states"]:
            self.assertTrue(0.0 <= state["x"] <= 1.0 and 0.0 <= state["y"] <= 1.0)

    def test_layered_has_every_transition(self):
        pdfa, _ = self.learned()
        edges = layout.layered(pdfa)["edges"]
        self.assertEqual(len(edges), sum(len(out) for _, out in pdfa.probs.values()))
        self.assertTrue(all(0.0 < e["prob"] <= 1.0 for e in edges))

    def test_layered_single_state(self):
        pdfa = statemachine.learn_pdfa([("a",)] * 4)
        states = layout.layered(pdfa)["states"]
        self.assertTrue(all(0.0 <= s["x"] <= 1.0 and 0.0 <= s["y"] <= 1.0 for s in states))

    def settled_case(self):
        rng = np.random.default_rng(0)
        weights = np.array([0.5 ** i for i in range(8)])
        stream = list(rng.choice(list("abcdefgh"), size=150, p=weights / weights.sum()))
        events = []
        pdfa = statemachine.learn_pdfa(statemachine.make_traces(stream), trace=events)
        nodes = layout.icicle(events[0][1])
        by_path = {n["path"]: n["id"] for n in nodes}
        steps = [{"kind": e["kind"], "red": by_path[e["red_path"]], "blue": by_path[e["path"]]}
                 for e in events[1:]]
        return pdfa, nodes, steps

    def test_settled_steps_never_show_a_state_before_it_exists(self):
        pdfa, nodes, steps = self.settled_case()
        settled = layout.settled_steps(nodes, steps)
        state_of = {i: s for s, ids in layout.pta_to_pdfa_map(pdfa, nodes).items() for i in ids}
        red_since = {0: 0}
        red_since.update({step["blue"]: k for k, step in enumerate(steps, start=1)
                          if step["kind"] == "promote"})
        red_of_state = {state_of[r]: r for r in red_since}
        self.assertEqual(settled[0], 0)
        self.assertEqual(set(settled), {n["id"] for n in nodes})
        self.assertTrue(all(0 <= k <= len(steps) for k in settled.values()))
        for node_id, k in settled.items():
            self.assertGreaterEqual(k, red_since[red_of_state[state_of[node_id]]], node_id)

    def test_settling_is_not_simply_the_merged_subtree(self):
        """The old replay coloured a merged candidate's whole subtree at once; that leaked."""
        pdfa, nodes, steps = self.settled_case()
        settled = layout.settled_steps(nodes, steps)
        children = {}
        for n in nodes:
            children.setdefault(n["parent"], []).append(n["id"])

        def subtree(i):
            out, stack = [], [i]
            while stack:
                j = stack.pop()
                out.append(j)
                stack.extend(children.get(j, []))
            return out
        later = [i for k, step in enumerate(steps, start=1) if step["kind"] == "merge"
                 for i in subtree(step["blue"]) if settled[i] > k]
        self.assertTrue(later)

    def test_every_pta_node_lands_in_a_state(self):
        pdfa, root = self.learned()
        nodes = layout.icicle(root)
        mapping = layout.pta_to_pdfa_map(pdfa, nodes)
        landed = sorted(i for ids in mapping.values() for i in ids)
        self.assertEqual(landed, [n["id"] for n in nodes])
        self.assertEqual(mapping[0][0], 0)          # the root state holds the PTA root


def flow_capture(seconds=60, burst=None, proto="tcp", start=1000.0, vary=False):
    """Packets for a request/response pair each second, each flow its own 5-tuple.

    `burst=(first, last)` repeats the pair six times a second in [first, last): the benign
    pattern hammered, which SEQUENT scores high because it visits known states too often.
    `vary` cycles the response through three sizes, so learning takes several red-blue steps.
    """
    rows, port = [], 30000
    for second in range(seconds):
        pairs = 6 if burst and burst[0] <= second < burst[1] else 1
        for pair in range(pairs):
            # binary-exact times: 0.1-style offsets round, and a rounded start can land a flow
            # across a window boundary, where segment_flows drops it
            t = start + second + 0.125 + pair / 8
            reply = (150, 900, 4000, 900, 150)[second % 5] if vary else 150
            for offset, size, duration, src, dst in ((0.0, 100, 0.015625, "10.42.3.4", "10.43.0.10"),
                                                     (0.0625, reply, 0.03125, "10.43.0.10", "10.42.3.4")):
                port += 1
                for ts in (t + offset, t + offset + duration):
                    rows.append({"ts": ts, "frame_len": size, "src_ip": src, "dst_ip": dst,
                                 "src_port": port, "dst_port": 53, "proto": proto})
    return pd.DataFrame(rows)


class VizBundleChecks(unittest.TestCase):
    """The page shows only what the bundle says, so the bundle must say what the pipeline did."""

    @classmethod
    def setUpClass(cls):
        cls.benign = flow_capture()
        cls.attack = flow_capture(burst=(20, 25))
        cls.bundle = viz.build_page(cls.benign, {"flood": cls.attack},
                                      {"pod-lidar": cls.benign}, "pod-lidar")
        cls.captures = {c["scenario"]: c for c in cls.bundle["playback"]["captures"]}

    def model_and_flows(self, packets):
        flows, _ = statemachine.segment_flows(statemachine.make_flows(packets),
                                              packets["ts"].min())
        return flows

    def test_make_flows_keeps_endpoints(self):
        flows = statemachine.make_flows(self.benign)
        self.assertEqual(set(flows["src_ip"]), {"10.42.3.4", "10.43.0.10"})

    def test_fit_model_trace_is_the_detector_model(self):
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        events = []
        traced = statemachine.fit_model(train, trace=events)
        self.assertEqual(traced["pdfa"].n_states, statemachine.fit_model(train)["pdfa"].n_states)
        self.assertEqual(len(self.bundle["learning"]["pdfa"]["states"]), traced["pdfa"].n_states)
        self.assertEqual(events[0][0], "pta")

    def test_held_out_benign_comes_first(self):
        names = [c["scenario"] for c in self.bundle["playback"]["captures"]]
        self.assertEqual(names, ["benign (held out)", "flood"])

    def test_bundle_scores_match_pipeline(self):
        flows = self.model_and_flows(self.attack)
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        model = statemachine.fit_model(train)
        t0 = self.attack["ts"].min()
        n = statemachine.n_windows_for(self.attack)
        expected = statemachine.frequency_scores_by_window(
            model, flows, t0, n, forget_seconds=statemachine.FORGET_SECONDS)
        capture = self.captures["flood"]
        got = np.full(n, np.nan)
        for trace in capture["traces"]:
            w = int(trace["t"] // features.WINDOW_SIZE)
            got[w] = trace["windowed"] if np.isnan(got[w]) else max(got[w], trace["windowed"])
        np.testing.assert_allclose(got, expected, equal_nan=True)

    def test_bundle_likelihood_matches_score_flows(self):
        flows = self.model_and_flows(self.attack)
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        expected = [s for _, s in statemachine.score_flows(statemachine.fit_model(train), flows)]
        got = [t["likelihood"] for t in self.captures["flood"]["traces"]]
        np.testing.assert_allclose(got, expected)

    def test_replaying_expiry_reconstructs_counts(self):
        from collections import Counter
        flows = self.model_and_flows(self.attack)
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        model = statemachine.fit_model(train)
        ids = {id(n): i for i, n in enumerate(statemachine.pdfa_states_in_order(model["pdfa"]))}
        scorer = statemachine.WindowedFrequencyScorer(model["pdfa"])
        symbols = list(statemachine.encode(flows, model["enc"]))
        t0 = self.attack["ts"].min()
        for i in range(len(symbols) - model["trace_len"] + 1):
            scorer.score(tuple(symbols[i:i + model["trace_len"]]),
                         flows["start_ts"].iloc[i + model["trace_len"] - 1] - t0)
        counts = Counter()
        for trace in self.captures["flood"]["traces"]:
            for _, state in trace["expired"]:
                counts[state] -= 1
            counts.update(trace["states"])
        self.assertEqual(+counts, Counter({ids[k]: v for k, v in scorer.counts.items()}))

    def test_burst_alerts_then_releases(self):
        windows = self.captures["flood"]["windows"]
        alerts = [w["index"] for w in windows if w["alert"]]
        released = [w["index"] for w in windows if w["released"]]
        self.assertTrue(alerts)
        self.assertTrue(released and released[0] > alerts[0])
        self.assertFalse(windows[-1]["flagged"])
        last = self.captures["flood"]["traces"][-1]
        # the burst's extra visits never leave the cumulative score: at the end it is still
        # above anything benign reached by the same age
        reference = self.captures["flood"]["cutoffs"]["cumulative_reference"]
        self.assertGreater(last["cumulative"], reference[int(last["t"] // features.WINDOW_SIZE)])
        self.assertFalse(any(w["alert"] for w in self.captures["benign (held out)"]["windows"]))

    def test_quiet_replay_never_alerts(self):
        """Control: the benign pattern replayed with no burst must not alert."""
        built = viz.build_page(self.benign, {"quiet": flow_capture()}, {}, "pod-lidar")
        windows = built["playback"]["captures"][1]["windows"]
        self.assertFalse(any(w["alert"] for w in windows))
        self.assertFalse(any(w["forgetting_shown"] for w in windows))

    def test_release_follows_the_burst_by_the_clock(self):
        windows = self.captures["flood"]["windows"]
        released = [w["index"] for w in windows if w["released"]]
        forget = statemachine.FORGET_SECONDS
        # the last burst flow starts before 25 s; it leaves the clock 8 s later, and the
        # release then waits for CLEAR_WINDOWS clean windows
        self.assertTrue(released)
        self.assertGreaterEqual(released[-1], 25)
        self.assertLessEqual(released[-1], 25 + forget + reporting.CLEAR_WINDOWS)

    def test_window_status_names_the_strongest_verdict(self):
        statuses = {w["status"] for w in self.captures["flood"]["windows"]}
        self.assertIn("alert", statuses)
        self.assertIn("released", statuses)
        unseen = viz.build_page(self.benign, {"udp": flow_capture(seconds=20, proto="udp")},
                                   {}, "pod-lidar")["playback"]["captures"][1]["windows"]
        self.assertIn("unseen", {w["status"] for w in unseen})
        self.assertTrue(all(w["status"] in viz.WINDOW_STATUSES for w in unseen))

    def test_forgetting_is_shown_only_after_an_alert(self):
        windows = self.captures["flood"]["windows"]
        first_alert = min(w["index"] for w in windows if w["alert"])
        shown = [w["index"] for w in windows if w["forgetting_shown"]]
        self.assertTrue(shown)
        self.assertTrue(all(i > first_alert for i in shown))
        self.assertFalse(any(windows[i]["flagged"] for i in shown))

    def test_template_is_read_as_utf8_whatever_the_locale(self):
        code = ("import warnings, tempfile, pathlib, tests; "
                "import viz.page as viz; "
                "warnings.simplefilter('error', EncodingWarning); "
                "viz.write_html(viz.build_page(tests.flow_capture(), {}, {}, 'pod-lidar'), "
                "pathlib.Path(tempfile.mkdtemp()) / 'p.html')")
        result = subprocess.run([sys.executable, "-X", "warn_default_encoding", "-c", code],
                                cwd=Path(__file__).resolve().parent, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def full_benign_scores(self, forget):
        flows = self.model_and_flows(self.benign)
        train, _ = statemachine.split_flows(flows)
        model = statemachine.fit_model(train)
        n = statemachine.n_windows_for(self.benign)
        return statemachine.frequency_scores_by_window(model, flows, self.benign["ts"].min(),
                                                        n, forget), train, flows

    def test_cumulative_reference_is_benign_at_the_same_age(self):
        scores, _, _ = self.full_benign_scores(None)
        reference = self.captures["flood"]["cutoffs"]["cumulative_reference"]
        expected = pd.Series(scores).cummax().to_numpy()
        np.testing.assert_allclose(np.array(reference, dtype=float), expected, equal_nan=True)

    def test_quiet_replay_stays_under_its_age_matched_reference(self):
        """Capture length alone must not lift the cumulative score over its reference."""
        built = viz.build_page(self.benign, {"quiet": flow_capture()}, {}, "pod-lidar")
        quiet = built["playback"]["captures"][1]
        reference = np.array(quiet["cutoffs"]["cumulative_reference"], dtype=float)
        for trace in quiet["traces"]:
            w = int(trace["t"] // features.WINDOW_SIZE)
            self.assertLessEqual(trace["cumulative"], reference[w] + 1e-9)

    def test_windowed_cutoff_is_calibrated_on_a_warm_clock(self):
        scores, train, flows = self.full_benign_scores(statemachine.FORGET_SECONDS)
        _, holdout = statemachine.split_flows(flows)
        first = int((holdout["start_ts"].iloc[0] - self.benign["ts"].min()) // features.WINDOW_SIZE)
        expected = statemachine.frequency_cutoff(scores[first + 1:])
        self.assertAlmostEqual(self.captures["flood"]["cutoffs"]["windowed"], expected)
        held = self.captures[viz.HELD_OUT]["windows"]
        peaks = np.array([w["peak"] for w in held[first + 1:]], dtype=float)
        np.testing.assert_allclose(peaks, scores[first + 1:], equal_nan=True)

    def test_cutoffs_disclose_the_sample_they_rest_on(self):
        """A 95th percentile of a handful of windows is close to their maximum: say how many."""
        scores, train, flows = self.full_benign_scores(statemachine.FORGET_SECONDS)
        _, holdout = statemachine.split_flows(flows)
        first = int((holdout["start_ts"].iloc[0] - self.benign["ts"].min()) // features.WINDOW_SIZE)
        held = scores[first + 1:]
        held = held[np.isfinite(held)]
        cutoffs = self.captures["flood"]["cutoffs"]
        calibration = cutoffs["calibration"]
        self.assertEqual(calibration["windowed_windows"], len(held))
        self.assertAlmostEqual(calibration["windowed_benign_rate"],
                               float(np.mean(held > cutoffs["windowed"])))
        model = statemachine.fit_model(train)
        self.assertEqual(calibration["likelihood_traces"],
                         len(statemachine.score_flows(model, holdout)))
        self.assertEqual(calibration["nominal_rate"], statemachine.BENIGN_QUANTILE)

    def test_capture_counts_its_scored_windows(self):
        for capture in self.captures.values():
            self.assertEqual(capture["scored_windows"],
                             sum(w["status"] != "nodata" for w in capture["windows"]))
        # one second holds two flows, fewer than a trace needs
        empty = viz.build_page(self.benign, {"silent": flow_capture(seconds=1)}, {}, "pod-lidar")
        self.assertEqual(empty["playback"]["captures"][1]["scored_windows"], 0)

    def test_capture_text_cannot_become_markup(self):
        """Scenario names, labels and protocol strings come from files; the page inserts them
        as HTML, so the bundle carries them escaped."""
        import tempfile
        hostile = "<img src=x onerror=alert(1)>"
        attack = flow_capture(burst=(20, 25))
        attack.loc[attack.index[:40], "proto"] = "<b>tcp</b>"
        built = viz.build_page(self.benign, {hostile: attack}, {}, "pod-lidar")
        parsed = json.loads(viz.to_json(built))
        self.assertEqual(parsed["playback"]["captures"][1]["scenario"],
                         "&lt;img src=x onerror=alert(1)&gt;")
        page = viz.write_html(built, Path(tempfile.mkdtemp()) / "p.html").read_text()
        self.assertNotIn("<img", page)
        self.assertNotIn("<b>tcp", page)

    def test_windows_without_traces_say_no_data(self):
        gap = flow_capture()
        gap = gap[~gap["ts"].between(gap["ts"].min() + 30, gap["ts"].min() + 40)]
        built = viz.build_page(self.benign, {"gap": gap}, {}, "pod-lidar")
        windows = built["playback"]["captures"][1]["windows"]
        self.assertTrue(all(windows[w]["status"] == "nodata" for w in range(31, 40)))

    def test_attack_warm_up_is_never_called_normal(self):
        warm = int(np.ceil(statemachine.FORGET_SECONDS / features.WINDOW_SIZE))
        for w in self.captures["flood"]["windows"][:warm]:
            self.assertIn(w["status"], {"warmup", "nodata", "flagged", "alert", "unseen"})
        self.assertEqual(self.captures["flood"]["warmup_s"], statemachine.FORGET_SECONDS)
        self.assertEqual(self.captures[viz.HELD_OUT]["warmup_s"], 0.0)

    def test_release_needs_clear_scored_windows(self):
        windows = self.captures["flood"]["windows"]
        releases = [w["index"] for w in windows if w["released"]]
        self.assertTrue(releases)
        for r in releases:
            # empty windows neither count toward the clean run nor reset it
            scored = [w for w in windows[:r + 1] if w["status"] != "nodata"]
            self.assertEqual(scored[-1]["index"], r)
            self.assertTrue(all(not w["flagged"] for w in scored[-reporting.CLEAR_WINDOWS:]))
            self.assertTrue(any(w["alert"] for w in windows[:r]))
        # a gap straight after the alert is not a release, and does not hurry one
        gap = flow_capture(burst=(20, 25))
        gap = gap[~gap["ts"].between(gap["ts"].min() + 25, gap["ts"].min() + 27)]
        built = viz.build_page(self.benign, {"gap": gap}, {}, "pod-lidar")
        windows = built["playback"]["captures"][1]["windows"]
        self.assertFalse(any(w["released"] for w in windows[25:28]))
        self.assertTrue(any(w["released"] for w in windows[28:]))

    def test_trace_visit_counts_are_exact_integers(self):
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        pdfa = statemachine.fit_model(train)["pdfa"]
        # the training count the page shows is the one the scorer uses, whatever its source
        counts = statemachine.state_train_counts(pdfa)
        visits = [counts[id(n)] for n in statemachine.pdfa_states_in_order(pdfa)]
        parsed = json.loads(viz.to_json(self.bundle))
        for trace in parsed["playback"]["captures"][1]["traces"]:
            self.assertEqual(len(trace["visits"]), len(trace["states"]))
            for (clock, trained), state in zip(trace["visits"], trace["states"]):
                self.assertIsInstance(clock, int)
                self.assertEqual(trained, visits[state])

    def test_states_carry_training_entries(self):
        states = self.bundle["learning"]["pdfa"]["states"]
        edges = self.bundle["learning"]["pdfa"]["edges"]
        for state in states:
            entered = sum(e["count"] for e in edges if e["dst"] == state["id"])
            self.assertEqual(state["entries"], entered)
        root = states[0]
        self.assertEqual(root["visits"] - root["entries"], self.bundle["learning"]["traces"])

    def test_capture_shows_conversations_benign_never_had(self):
        attack = flow_capture(burst=(20, 25))
        rows = attack[attack["src_ip"].eq("10.42.3.4")].head(4).copy()
        rows["dst_ip"] = "10.42.3.99"
        attack = pd.concat([attack, rows]).sort_values("ts")
        built = viz.build_page(self.benign, {"lateral": attack},
                                  {"pod-lidar": self.benign}, "pod-lidar")
        capture = built["playback"]["captures"][1]
        self.assertIn("pod:10.42.3.99", {e["id"] for e in capture["new_elements"]})
        pairs = {tuple(sorted((e["src"], e["dst"]))) for e in capture["new_edges"]}
        self.assertIn(("pod:10.42.3.4", "pod:10.42.3.99"), pairs)
        self.assertIn(["pod:10.42.3.4", "pod:10.42.3.99"], capture["flow_edges"])

    def test_dropped_flows_are_reported_per_capture(self):
        for capture in self.bundle["playback"]["captures"]:
            self.assertIsInstance(capture["dropped_flows"], int)
        self.assertGreater(self.bundle["meta"]["holdout_span_s"], 0)

    def test_trace_flows_map_to_cluster_elements(self):
        capture = self.captures["flood"]
        self.assertIn(["pod:10.42.3.4", "svc:10.43.0.10"], capture["flow_edges"])
        self.assertEqual(capture["traces"][0]["i"], 0)

    def test_json_has_no_nonfinite(self):
        def refuse(constant):
            raise ValueError(constant)
        parsed = json.loads(viz.to_json(self.bundle), parse_constant=refuse)
        self.assertEqual(parsed["meta"]["vantage"], "pod-lidar")
        self.assertEqual(parsed["meta"]["forget_seconds"], statemachine.FORGET_SECONDS)

    def test_all_unseen_attack_falls_off_first_symbol(self):
        unseen = flow_capture(seconds=20, proto="udp")
        built = viz.build_page(self.benign, {"udp": unseen}, {}, "pod-lidar")
        traces = built["playback"]["captures"][1]["traces"]
        self.assertTrue(traces)
        self.assertTrue(all(t["fell_off_at"] == 0 and t["states"] == [] for t in traces))
        self.assertTrue(all(np.isfinite(t["likelihood"]) for t in traces))

    def test_step_detail_is_capped(self):
        original = viz.MAX_STEP_DETAIL
        viz.MAX_STEP_DETAIL = 2
        try:
            built = viz.build_page(flow_capture(vary=True), {}, {}, "pod-lidar")
        finally:
            viz.MAX_STEP_DETAIL = original
        self.assertEqual(len(built["learning"]["steps"]), 2)
        self.assertGreater(built["learning"]["steps_total"], 2)

    def test_html_is_self_contained(self):
        import re
        import tempfile
        out = viz.write_html(self.bundle, Path(tempfile.mkdtemp()) / "page.html")
        page = out.read_text()
        self.assertNotRegex(page, r'(src|href)="https?:')
        self.assertIn("window.VIZ = ", page)
        self.assertIn("d3js.org v7.9.0", page)
        self.assertLess(out.stat().st_size, 15 * 1024 * 1024)
        # the bundle is inlined inside a script, so a "</" in it would end the script early
        bundle = re.search(r"window\.VIZ = (.*?);\n", page, re.S).group(1)
        self.assertNotIn("</", bundle)
        self.assertNotRegex(page, r"/\*__[A-Z0-9]+__\*/")

    def test_meta_carries_train_span(self):
        train, _ = statemachine.split_flows(self.model_and_flows(self.benign))
        self.assertAlmostEqual(self.bundle["meta"]["train_span_s"],
                               train["start_ts"].max() - train["start_ts"].min())

    def test_steps_point_at_pta_nodes(self):
        learning = self.bundle["learning"]
        ids = {node["id"] for node in learning["pta"]}
        for step in learning["steps"]:
            self.assertIn(step["blue"], ids)
            self.assertIn(step["red"], ids)
        merged = [i for state in learning["pdfa"]["states"] for i in state["pta_ids"]]
        self.assertEqual(sorted(merged), sorted(ids))

    def two_vantages(self):
        other = flow_capture(vary=True, start=1003.0)
        inputs = {"pod-lidar": (self.benign, {"flood": self.attack}),
                  "pod-nginx": (other, {"flood": flow_capture(burst=(30, 35), start=1002.0)})}
        captures = {"pod-lidar": self.benign, "pod-nginx": other}
        return viz.build_pages(inputs, captures, selected="pod-nginx"), inputs, captures

    def test_vantage_block_is_build_page_for_that_vantage(self):
        bundle, inputs, captures = self.two_vantages()
        self.assertEqual(list(bundle["vantages"]), ["pod-lidar", "pod-nginx"])
        for vantage, (benign, targets) in inputs.items():
            alone = viz.build_page(benign, targets, captures, vantage)
            block = bundle["vantages"][vantage]
            self.assertEqual(set(block), set(viz.VANTAGE_PARTS))
            for part in viz.VANTAGE_PARTS:
                got, expected = json.loads(viz.to_json(block[part])), json.loads(viz.to_json(alone[part]))
                if part == "meta":
                    got.pop("generated"), expected.pop("generated")
                self.assertEqual(got, expected, f"{vantage} {part}")

    def test_cluster_is_shared_once(self):
        bundle, _, captures = self.two_vantages()
        self.assertEqual(json.loads(viz.to_json(bundle["cluster"])),
                         json.loads(viz.to_json(cluster.infer_cluster(captures))))
        self.assertTrue(all("cluster" not in block for block in bundle["vantages"].values()))
        self.assertEqual(bundle["selected"], "pod-nginx")
        self.assertEqual(bundle["trimmed"], [])

    def test_absent_taps_say_why(self):
        """A tap left off the page is either a bulk-transfer tap or simply not chosen; the page
        must not blame bulk transfer for a tap the builder just did not pick."""
        bulk = next(iter(evaluation.BULK_LABELS))
        captures = {"pod-lidar": self.benign, "pod-nginx": self.benign, bulk: self.benign}
        inputs = {"pod-lidar": (self.benign, {"flood": self.attack})}
        bundle = viz.build_pages(inputs, captures)
        self.assertEqual(bundle["absent"], {"pod-nginx": "not chosen", bulk: "bulk transfer"})

    def test_thin_tap_is_left_off_not_fatal(self):
        """A benign capture with a handful of long-lived connections (a redis pool) has too few
        flows to learn from; the page drops that tap with the reason instead of failing, and
        only fails when no tap at all can be learned."""
        thin = self.benign[self.benign["ts"] < self.benign["ts"].min() + 0.5].head(3)
        captures = {"pod-lidar": self.benign, "pod-redis": thin}
        inputs = {"pod-lidar": (self.benign, {"flood": self.attack}), "pod-redis": (thin, {})}
        bundle = viz.build_pages(inputs, captures)
        self.assertEqual(list(bundle["vantages"]), ["pod-lidar"])
        self.assertEqual(bundle["absent"].get("pod-redis"), "too few flows")
        with self.assertRaisesRegex(ValueError, "No tap could be learned"):
            viz.build_pages({"pod-redis": (thin, {})}, captures)

    def test_captures_carry_their_first_packet_time(self):
        """Taps record side by side; the page lines one scenario up across them on t0."""
        bundle, inputs, _ = self.two_vantages()
        for vantage, (benign, targets) in inputs.items():
            held, flood = bundle["vantages"][vantage]["playback"]["captures"]
            self.assertAlmostEqual(held["t0"], benign["ts"].min())
            self.assertAlmostEqual(flood["t0"], targets["flood"]["ts"].min())

    def test_trim_drops_detail_only_from_other_vantages(self):
        bundle, _, _ = self.two_vantages()
        trimmed = viz.trim(bundle, "pod-nginx")
        self.assertEqual(trimmed["trimmed"], ["pod-lidar"])
        for vantage, block in trimmed["vantages"].items():
            for capture, original in zip(block["playback"]["captures"],
                                         bundle["vantages"][vantage]["playback"]["captures"]):
                for trace, full in zip(capture["traces"], original["traces"]):
                    dropped = vantage != "pod-nginx"
                    self.assertEqual("terms" in trace, not dropped)
                    self.assertEqual("expired" in trace, not dropped)
                    # scores, states and visits stay, so every verdict still reads the same
                    self.assertEqual({k: v for k, v in full.items() if k not in viz.TRIMMED_KEYS},
                                     {k: v for k, v in trace.items() if k not in viz.TRIMMED_KEYS})
                self.assertEqual(capture["windows"], original["windows"])
        self.assertIn("terms", bundle["vantages"]["pod-lidar"]["playback"]["captures"][0]["traces"][0])

    def test_page_over_the_limit_is_trimmed_then_refused(self):
        import tempfile
        bundle, _, _ = self.two_vantages()
        full = len(viz.page_html(bundle).encode("utf-8"))
        out = viz.write_html(bundle, Path(tempfile.mkdtemp()) / "page.html", limit=full - 1)
        self.assertLess(out.stat().st_size, full)
        self.assertEqual(page_bundle(out)["trimmed"], ["pod-lidar"])
        with self.assertRaisesRegex(ValueError, "fewer --vantages"):
            viz.write_html(bundle, Path(tempfile.mkdtemp()) / "page.html", limit=1000)

    def test_one_vantage_page_is_drawn_as_a_one_tap_page(self):
        import tempfile
        out = viz.write_html(self.bundle, Path(tempfile.mkdtemp()) / "page.html")
        parsed = page_bundle(out)
        self.assertEqual(list(parsed["vantages"]), ["pod-lidar"])
        self.assertEqual(parsed["selected"], "pod-lidar")


def page_bundle(path):
    """The bundle a written page carries, parsed back from its inline script."""
    import re
    page = Path(path).read_text(encoding="utf-8")
    return json.loads(re.search(r"window\.VIZ = (.*?);\n", page, re.S).group(1))


class VizEntryChecks(unittest.TestCase):
    """The page is reachable from the menu and the CLI, from the manifest alone."""

    def manifest(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        rows = []
        for scenario, label, usable, burst in (
                ("benign", "pod-lidar", True, None), ("benign", "pod-nginx", True, None),
                ("benign", "pod-camera", False, None),
                ("lidar attack", "pod-lidar", True, (20, 25)),
                ("nginx attack", "pod-lidar", True, (30, 35)),
                ("lidar attack", "pod-nginx", True, (20, 25))):
            path = root / f"{scenario}-{label}.csv"
            flow_capture(burst=burst).to_csv(path, index=False)
            rows.append({"scenario": scenario, "level": "pod", "label": label, "method": "tcp",
                         "path": str(path), "usable": usable})
        return pd.DataFrame(rows)

    def test_viz_is_menu_item_10(self):
        names = [name for name, _, _ in demo.ITEMS]
        self.assertEqual(names[:9], ["Pair demo", "Walkthrough", "State machine", "Sweep",
                                     "Ablation", "Compare", "Feature value", "Everything",
                                     "Tests"])
        self.assertEqual(names[9], "Visualization")

    def test_inputs_pick_the_vantage_and_every_attack(self):
        benign, targets, cluster_captures = viz.page_inputs(self.manifest(), "pod-lidar")
        self.assertEqual(sorted(targets), ["lidar attack", "nginx attack"])
        self.assertEqual(sorted(cluster_captures), ["pod-lidar", "pod-nginx"])   # unusable skipped
        self.assertTrue(benign.equals(cluster_captures["pod-lidar"]))

    def test_inputs_filter_scenarios(self):
        _, targets, _ = viz.page_inputs(self.manifest(), "pod-lidar", scenarios=["nginx attack"])
        self.assertEqual(list(targets), ["nginx attack"])

    def test_unknown_vantage_says_which_exist(self):
        with self.assertRaisesRegex(ValueError, "pod-lidar"):
            viz.page_inputs(self.manifest(), "pod-nowhere")

    def test_bulk_vantage_needs_explicit_consent(self):
        bulk = next(iter(evaluation.BULK_LABELS))
        manifest = self.manifest()
        manifest.loc[manifest["label"].eq("pod-nginx"), "label"] = bulk
        with self.assertRaisesRegex(ValueError, "bulk"):
            viz.page_inputs(manifest, bulk)
        benign, _, _ = viz.page_inputs(manifest, bulk, allow_bulk=True)
        built = viz.build_page(benign, {}, {}, bulk)
        self.assertIn("bulk", built["meta"]["calibration_warning"])
        self.assertIsNone(viz.build_page(benign, {}, {}, "pod-lidar")["meta"]["calibration_warning"])

    def test_bad_timebase_is_skipped_without_a_usable_column(self):
        manifest = self.manifest().drop(columns="usable")
        broken = pd.read_csv(manifest.loc[3, "path"])
        broken.loc[:5, "ts"] = 0.0
        broken.to_csv(manifest.loc[3, "path"], index=False)
        _, targets, captures = viz.page_inputs(manifest, "pod-lidar")
        self.assertNotIn("lidar attack", targets)
        self.assertIn("pod-camera", captures)          # no usable column: judged by timebase

    def test_main_writes_the_page(self):
        import tempfile
        out = Path(tempfile.mkdtemp()) / "viz.html"
        written = viz.main(["--vantage", "pod-lidar", "--out", str(out)], manifest=self.manifest())
        self.assertEqual(written, out)
        self.assertIn("window.VIZ = ", out.read_text())

    def test_main_draws_every_steady_vantage_by_default(self):
        import tempfile
        out = viz.main(["--out", str(Path(tempfile.mkdtemp()) / "viz.html")],
                         manifest=self.manifest())
        bundle = page_bundle(out)
        self.assertEqual(list(bundle["vantages"]), ["pod-lidar", "pod-nginx"])   # camera unusable
        self.assertEqual(bundle["selected"], viz.DEFAULT_VANTAGE)
        scenarios = lambda v: [c["scenario"] for c in bundle["vantages"][v]["playback"]["captures"]]
        self.assertEqual(scenarios("pod-nginx"), [viz.HELD_OUT, "lidar attack"])
        self.assertLess(out.stat().st_size, viz.PAGE_LIMIT)

    def test_bulk_vantages_are_left_out_by_default(self):
        import tempfile
        bulk = sorted(evaluation.BULK_LABELS)[0]
        manifest = self.manifest()
        manifest.loc[manifest["label"].eq("pod-nginx"), "label"] = bulk
        captures = viz.benign_captures(manifest)
        self.assertEqual(viz.steady_vantages(captures), ["pod-lidar"])
        self.assertEqual(viz.steady_vantages(captures, allow_bulk=True), sorted(["pod-lidar", bulk]))
        out = Path(tempfile.mkdtemp()) / "viz.html"
        self.assertEqual(list(page_bundle(viz.main(["--out", str(out)], manifest=manifest))["vantages"]),
                         ["pod-lidar"])
        with_bulk = page_bundle(viz.main(["--out", str(out), "--allow-bulk"], manifest=manifest))
        self.assertIn("bulk", with_bulk["vantages"][bulk]["meta"]["calibration_warning"])
        with self.assertRaisesRegex(ValueError, "bulk"):
            viz.main(["--out", str(out), "--vantages", "pod-lidar", bulk], manifest=manifest)

    def test_opening_vantage_joins_an_explicit_list(self):
        import tempfile
        out = viz.main(["--out", str(Path(tempfile.mkdtemp()) / "viz.html"),
                          "--vantages", "pod-lidar", "--vantage", "pod-nginx"],
                         manifest=self.manifest())
        bundle = page_bundle(out)
        self.assertEqual(list(bundle["vantages"]), ["pod-lidar", "pod-nginx"])
        self.assertEqual(bundle["selected"], "pod-nginx")

    def test_cluster_captures_are_loaded_once_for_every_vantage(self):
        captures = viz.benign_captures(self.manifest())
        benign, _, shared = viz.page_inputs(self.manifest(), "pod-nginx", cluster_captures=captures)
        self.assertIs(shared, captures)
        self.assertIs(benign, captures["pod-nginx"])


class WindowedSweepChecks(unittest.TestCase):
    """The windowed score's sweep: viz.py's calibration, and missing windows kept missing."""

    @classmethod
    def setUpClass(cls):
        cls.benign = flow_capture(vary=True)
        cls.attack = flow_capture(burst=(20, 25), vary=True)
        cls.rows = windowed_scores.label_rows("pod-lidar", "tcp", cls.benign,
                                              {"flood": cls.attack})

    def row(self, scenario, variant="visits", rows=None):
        match = [r for r in rows or self.rows
                 if r["scenario"] == scenario and r["train_counts"] == variant]
        self.assertEqual(len(match), 1)
        return match[0]

    def test_cutoff_is_the_pages_cutoff(self):
        bundle = viz.build_page(self.benign, {"flood": self.attack},
                                   {"pod-lidar": self.benign}, "pod-lidar")
        expected = bundle["playback"]["captures"][0]["cutoffs"]["windowed"]
        page_counts = bundle["meta"]["train_counts"]
        self.assertEqual(page_counts, statemachine.TRAIN_COUNTS)
        self.assertEqual(self.row("benign", page_counts)["cutoff"], expected)
        self.assertEqual(self.row("flood", page_counts)["cutoff"], expected)
        # the page's per-state training count is the scorer's, so the start state shows entries
        entries = {s["id"]: s["entries"] for s in bundle["learning"]["pdfa"]["states"]}
        for trace in bundle["playback"]["captures"][1]["traces"]:
            for state, (_, trained) in zip(trace["states"], trace["visits"]):
                self.assertEqual(trained, entries[state])

    def test_held_out_windows_are_scored_on_a_warm_clock(self):
        flows, _ = statemachine.segment_flows(statemachine.make_flows(self.benign),
                                              self.benign["ts"].min())
        train, holdout = statemachine.split_flows(flows)
        model = statemachine.fit_model(train)
        t0 = self.benign["ts"].min()
        n = statemachine.n_windows_for(self.benign)
        held = windowed_scores.held_out_scores(model, flows, holdout, t0, n)
        cold = statemachine.frequency_scores_by_window(model, holdout, t0, n,
                                                       statemachine.FORGET_SECONDS)
        first_held = int((holdout["start_ts"].iloc[0] - t0) // features.WINDOW_SIZE)
        self.assertEqual(len(held), n - first_held - 1)
        # the cold clock starts empty at the split: it needs a whole trace before it scores
        # at all, and its first scored window counts fewer visits than the warm clock's
        cold = cold[first_held + 1:]
        self.assertTrue(np.isfinite(held[:3]).all() and np.isnan(cold[0]))
        first = int(np.flatnonzero(np.isfinite(cold))[0])
        self.assertGreater(held[first], cold[first])
        self.assertEqual(self.row("benign")["cutoff_windows"], int(np.isfinite(held).sum()))

    def test_missing_windows_are_not_counted_as_normal(self):
        held = np.array([1.0, 2.0, 3.0, np.nan])
        attack = np.array([9.0, np.nan, np.nan, 9.0, np.nan, 0.0])
        row = windowed_scores.attack_fields(held, attack, cutoff=5.0, first_warm=1)
        self.assertEqual(row["missing_windows"], 3)
        self.assertEqual(row["warm_scored"], 2)              # windows 3 and 5
        self.assertEqual(row["detection"], 0.5)               # not 1 of 5
        self.assertEqual(row["warmup_flagged"], 1)
        self.assertEqual(row["n_benign"], 3)
        self.assertEqual(row["auroc"], flag_scores.auroc([1.0, 2.0, 3.0], [9.0, 0.0]))
        benign = windowed_scores.benign_fields(held, cutoff=2.5)
        self.assertEqual(benign["cutoff_windows"], 3)
        self.assertAlmostEqual(benign["realised_benign_rate"], 1 / 3)

    def test_a_capture_with_no_warm_window_has_no_detection(self):
        row = windowed_scores.attack_fields([1.0, 2.0], [9.0, 9.0, np.nan], 5.0, first_warm=2)
        self.assertTrue(np.isnan(row["detection"]))
        self.assertTrue(np.isnan(row["auroc"]))
        self.assertEqual(row["warmup_flagged"], 2)

    def test_bulk_tap_sets_no_cutoff(self):
        label = sorted(evaluation.BULK_LABELS)[0]
        rows = windowed_scores.label_rows(label, "tcp", self.benign, {"flood": self.attack},
                                          variants=("visits",))
        for row in rows:
            self.assertEqual(row["group"], "bulk")
            self.assertTrue(np.isnan(row["cutoff"]))
            self.assertTrue(np.isnan(row["flagged_fraction"]))
        self.assertTrue(np.isnan(self.row("flood", rows=rows)["detection"]))
        self.assertTrue(np.isfinite(self.row("flood", rows=rows)["auroc"]))

    def test_entries_differ_from_visits_only_at_the_start_state(self):
        traces = [("a", "b", "c")] * 12 + [("a", "b", "b")] * 12 + [("c", "a")] * 12
        pdfa = statemachine.learn_pdfa(traces)
        visits = statemachine.state_train_counts(pdfa, "visits")
        entries = statemachine.state_train_counts(pdfa, "entries")
        root = id(pdfa.root)
        self.assertEqual(visits[root] - entries[root], len(traces))
        self.assertEqual({k: v for k, v in visits.items() if k != root},
                         {k: v for k, v in entries.items() if k != root})
        with self.assertRaises(ValueError):
            statemachine.state_train_counts(pdfa, "starts")

    def test_both_count_sources_are_reported(self):
        self.assertEqual({r["train_counts"] for r in self.rows}, set(windowed_scores.VARIANTS))
        self.assertEqual(self.row("benign")["start_visits"] - self.row("benign")["start_entries"],
                         self.row("benign", "entries")["start_visits"]
                         - self.row("benign", "entries")["start_entries"])


class CvVerdictChecks(unittest.TestCase):
    """The cross-validated calibration rule, judged on rows made to pass or fail each clause."""

    def rows(self, taps=4, gain=5.0, flagged=3, windows=60, ratio=0.1, change=0.0,
             one_loss=0.0, tap_rate=None):
        rows = []
        for t in range(taps):
            label = f"pod-{t}"
            for method in ("tcp", "ptcp"):
                common = {"label": label, "method": method, "group": "steady"}
                rows.append(dict(common, scenario="benign", calibration="split", cutoff_windows=10))
                hit = tap_rate if (tap_rate is not None and t == 0) else flagged
                rows.append(dict(common, scenario="benign", calibration="cv5",
                                 cutoff_windows=int(10 * gain), oos_flagged=hit,
                                 oos_windows=windows, scale_ratio=ratio))
                for k, scenario in enumerate(("lidar attack", "nginx attack")):
                    loss = one_loss if (t == 0 and k == 0 and method == "tcp") else 0.0
                    rows.append(dict(common, scenario=scenario, calibration="split", auroc=0.7))
                    rows.append(dict(common, scenario=scenario, calibration="cv5",
                                     auroc=0.7 + change - loss))
        rows.append({"label": "router-any", "method": "tcp", "group": "bulk",
                     "scenario": "lidar attack", "calibration": "cv5", "auroc": 0.0})
        return rows

    def test_keep_when_every_clause_holds(self):
        verdict, reasons = cv_verdict.decide(self.rows())
        self.assertEqual(verdict, "keep", reasons)

    def test_undecidable_with_too_few_strata(self):
        self.assertEqual(cv_verdict.decide(self.rows(taps=2))[0], "undecidable")

    def test_drop_when_the_sample_barely_grows(self):
        verdict, reasons = cv_verdict.decide(self.rows(gain=2.0))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("sample gain" in r for r in reasons))

    def test_drop_when_out_of_fold_rate_leaves_the_band(self):
        for flagged in (0, 9):                          # 0% and 15% of 60
            verdict, reasons = cv_verdict.decide(self.rows(flagged=flagged))
            self.assertEqual(verdict, "drop", flagged)
            self.assertTrue(any("out-of-fold benign rate" in r for r in reasons))

    def test_drop_when_one_tap_flags_too_much(self):
        verdict, reasons = cv_verdict.decide(self.rows(tap_rate=20))   # 20 of 60 on one tap
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("pod-0/" in r and "above 0.25" in r for r in reasons))

    def test_drop_when_fold_and_full_scores_disagree(self):
        verdict, reasons = cv_verdict.decide(self.rows(ratio=0.4))
        self.assertEqual(verdict, "drop")
        self.assertTrue(any("scale shift" in r for r in reasons))

    def test_drop_on_a_stratum_loss_or_a_mean_loss(self):
        self.assertEqual(cv_verdict.decide(self.rows(one_loss=0.06))[0], "drop")
        self.assertEqual(cv_verdict.decide(self.rows(change=-0.02))[0], "drop")
        self.assertEqual(cv_verdict.decide(self.rows(one_loss=0.05))[0], "keep")

    def test_bulk_rows_decide_nothing(self):
        rows = self.rows()
        rows.append({"label": "router-any", "method": "tcp", "group": "bulk", "scenario": "benign",
                     "calibration": "cv5", "cutoff_windows": 1, "oos_flagged": 50,
                     "oos_windows": 50, "scale_ratio": 9.0})
        self.assertEqual(cv_verdict.decide(rows)[0], "keep")


class CvCalibrationChecks(unittest.TestCase):
    """Cross-validated calibration: every benign window held out once, scored out of fold."""

    @classmethod
    def setUpClass(cls):
        from experiments import cv_calibration
        cls.cv = cv_calibration
        cls.benign = flow_capture(vary=True)
        cls.t0 = cls.benign["ts"].min()
        cls.flows, _ = statemachine.segment_flows(statemachine.make_flows(cls.benign), cls.t0)
        cls.n = statemachine.n_windows_for(cls.benign)
        cls.result = cls.cv.calibrate(cls.flows, cls.t0, cls.n)

    def test_fold_blocks_tile_the_recording(self):
        blocks = self.cv.fold_blocks(self.n)
        self.assertEqual(len(blocks), cv_verdict.CV_FOLDS)
        self.assertEqual(blocks[0][0], 0)
        self.assertEqual(blocks[-1][1], self.n)
        self.assertTrue(all(a[1] == b[0] for a, b in zip(blocks, blocks[1:])))

    def test_segments_never_make_a_trace_across_the_gap(self):
        half = len(self.flows) // 2
        segments = [self.flows.iloc[:half], self.flows.iloc[half + 7:]]
        events = []
        statemachine.fit_segments(segments, trace=events)
        root = events[0][1]
        length = statemachine.TRACE_LEN
        self.assertEqual(root.visits, sum(len(seg) - length + 1 for seg in segments))
        alone = statemachine.fit_segments([self.flows])
        whole = statemachine.fit_model(self.flows)
        self.assertEqual(alone["pdfa"].n_states, whole["pdfa"].n_states)

    def test_every_benign_window_is_held_out_once(self):
        kept = [w for fold in self.result["folds"] for w in fold["windows"]]
        self.assertEqual(len(kept), len(set(kept)))
        warm = int(np.ceil(statemachine.FORGET_SECONDS / features.WINDOW_SIZE))
        excluded = {start for start, _ in self.cv.fold_blocks(self.n)} | set(range(warm))
        self.assertEqual(set(kept), set(range(self.n)) - excluded)
        for fold in self.result["folds"]:
            start, end = fold["block"]
            self.assertTrue(all(start < w < end for w in fold["windows"]))

    def test_out_of_fold_rate_uses_cutoffs_set_without_the_fold(self):
        folds = self.result["folds"]
        flagged = windows = 0
        for k, fold in enumerate(folds):
            others = np.concatenate([f["scores"] for j, f in enumerate(folds) if j != k])
            cutoff = statemachine.frequency_cutoff(others)
            scores = fold["scores"][np.isfinite(fold["scores"])]
            flagged += int((scores > cutoff).sum())
            windows += len(scores)
        self.assertEqual((self.result["oos_flagged"], self.result["oos_windows"]), (flagged, windows))
        pooled = np.concatenate([f["scores"] for f in folds])
        self.assertEqual(self.result["cutoff_windows"], int(np.isfinite(pooled).sum()))
        self.assertAlmostEqual(self.result["cutoff"], statemachine.frequency_cutoff(pooled))

    def test_rows_carry_what_the_verdict_reads(self):
        rows = self.cv.label_rows("pod-lidar", "tcp", self.benign,
                                  {"flood": flow_capture(burst=(20, 25), vary=True)})
        by = {(r["calibration"], r["scenario"]): r for r in rows}
        self.assertEqual(set(by), {("split", "benign"), ("split", "flood"),
                                   ("cv5", "benign"), ("cv5", "flood")})
        cv = by[("cv5", "benign")]
        for key in ("cutoff_windows", "oos_flagged", "oos_windows", "scale_ratio"):
            self.assertIn(key, cv)
        self.assertGreater(cv["cutoff_windows"], by[("split", "benign")]["cutoff_windows"])
        self.assertIn(cv_verdict.decide(rows)[0], {"keep", "drop", "undecidable"})
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
        from convert import read as pcap_read
        reader = pcap_read.CaptureReader(_capture_file(blob, name))
        return list(reader.frames()), reader

    def test_detect_format_by_magic_not_extension(self):
        from convert import read as pcap_read
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
        from convert import read as pcap_read
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
        from convert import read as pcap_read
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
        from convert import read as pcap_read
        with self.assertRaisesRegex(ValueError, "unsupported linktype 101") as caught:
            list(pcap_read.CaptureReader(path).frames())
        self.assertIn(str(path), str(caught.exception))

    def test_simple_packet_block_is_refused(self):
        from convert import read as pcap_read
        path = _capture_file(_pcapng_bytes(_pcapng_idb(), _pcapng_block(3, b"\0" * 8)))
        with self.assertRaisesRegex(ValueError, "unsupported pcapng block type 3"):
            list(pcap_read.CaptureReader(path).frames())

    def test_reader_imports_without_local_paths(self):
        script = "import sys; sys.path.insert(0, '.'); from convert import read as pcap_read; print(pcap_read.HEAD_BYTES)"
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
    from convert import read as pcap_read
    return pcap_read.Frame(number, sec, frac, digits, orig_len or len(data),
                           data[:pcap_read.HEAD_BYTES], linktype)


class PcapRowChecks(unittest.TestCase):
    def row(self, data, linktype=1, orig_len=None):
        from convert import rows as pcap_rows
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
        from convert import rows as pcap_rows
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
        from convert import rows as pcap_rows
        data = _ether(_ipv4(_tcp(1, 2), 6), 0x0800)[:30]       # IPv4 header cut mid-way
        row, complete = pcap_rows.dissect(_frame(data, orig_len=54))
        self.assertFalse(complete)
        self.assertEqual((row["eth_type"], row["src_ip"], row["frame_len"]), ("0x0800", None, 54))

    def test_iat_first_row_int_zero_then_signed_float(self):
        from convert import rows as pcap_rows
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
        from convert import rows as pcap_rows
        add = pcap_rows.ts_seconds(1771545910, 906831167, 9, rule="add")
        div = pcap_rows.ts_seconds(1771545910, 906831167, 9, rule="div")
        self.assertLessEqual(abs(add - div), 2.4e-7)
        with self.assertRaises(ValueError):
            pcap_rows.ts_seconds(1, 0, 6, rule="other")

    def test_format_cell(self):
        from convert import rows as pcap_rows
        self.assertEqual([pcap_rows.format_cell(v) for v in (None, 0, 17, "udp", 8.58306884765625e-06)],
                         ["", "0", "17", "udp", "8.58306884765625e-06"])

    def test_written_csv_loads_through_data_io(self):
        import tempfile
        from convert import rows as pcap_rows
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
        from convert import rows as pcap_rows
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
        from experiments import pcap_diff
        root, flat, nested = self.tree()
        self.assertEqual(pcap_diff.locate_pcap(root, "benign", "pod-nginx", "tcp"), flat)
        self.assertEqual(pcap_diff.locate_pcap(root, "nginx attack", "pod-nginx", "ptcp"), nested)

    def test_locate_pcap_missing_or_duplicate_raises(self):
        from experiments import pcap_diff
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
        from convert import rows as pcap_rows
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
        from experiments import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(edit=("dst_port", "9999")))
        self.assertEqual((result["rows_sponsor"], result["rows_regen"]), (2, 2))
        self.assertEqual((result["tier_a_exact"], result["mismatch_cells"],
                          result["differing_columns"]), (False, 1, "dst_port:1"))
        self.assertEqual(result["first_mismatch"], "frame 1 dst_port 8080|9999")

    def test_compare_capture_tier_b_only_is_still_tier_a_exact(self):
        from experiments import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(edit=("eth_src", "aa:aa:aa:aa:aa:aa")))
        self.assertEqual((result["tier_a_exact"], result["differing_columns"], result["windows"]),
                         (True, "eth_src:1", "equal"))

    def test_identical_capture_is_exact_with_equal_windows(self):
        from experiments import pcap_diff
        result = pcap_diff.compare_capture(*self.pair())
        self.assertEqual((result["tier_a_exact"], result["mismatch_cells"], result["windows"],
                          result["warnings"]), (True, 0, "equal", ""))

    def test_truncation_warning_blocks_exact(self):
        from experiments import pcap_diff
        result = pcap_diff.compare_capture(*self.pair(cut=10))
        self.assertEqual((result["rows_regen"], result["mismatch_cells"]), (1, 0))
        self.assertEqual((result["tier_a_exact"], result["warnings"]),
                         (False, "truncated after frame 1"))

    def test_row_count_difference_blocks_exact(self):
        from experiments import pcap_diff
        pcap, csv_path = self.pair()
        with open(csv_path, "a", newline="") as handle:
            handle.write("3" + "," * 33 + "\r\n")
        result = pcap_diff.compare_capture(pcap, csv_path)
        self.assertEqual((result["rows_sponsor"], result["rows_regen"], result["tier_a_exact"]),
                         (3, 2, False))

    def test_one_bad_capture_is_recorded_and_the_run_continues(self):
        import tempfile
        from experiments import pcap_diff
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
        from experiments import pcap_diff
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
        self.assertEqual((names[7], names[8], names[9], names[10]),
                         ("Everything", "Tests", "Visualization", "Pcap diff"))
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
        run = subprocess.run([sys.executable, "dev/experiments/pcap_diff.py", "--report", "--out", str(out)],
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
        from convert import rows as pcap_rows
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
        from convert import rows as pcap_rows
        for scenario, name in SMALL_CAPTURES:
            with self.subTest(capture=f"{scenario}/{name}"):
                pcap, csv_path = _sponsor_pair(scenario, name)
                regenerated = Path(tempfile.mkdtemp()) / f"{name}.csv"
                pcap_rows.write_capture_rows(pcap, regenerated)
                pd.testing.assert_frame_equal(make_windows(data_io.load_capture(str(regenerated))),
                                              make_windows(data_io.load_capture(str(csv_path))))


# --- The harness: profiles, sources, the local server --------------------------------------

def _write_csv(frame, folder, name):
    path = Path(folder) / name
    frame.to_csv(path, index=False)
    return path


def _strip_volatile(bundle):
    """A bundle as JSON with build times and provenance removed, for equality checks."""
    parsed = json.loads(viz.to_json(bundle))
    parsed.pop("source", None)
    for block in parsed["vantages"].values():
        block["meta"].pop("generated", None)
    return parsed


class _OutputsInTemp:
    """Point outputs/ (uploads, converted captures, the exported page) at a temp folder."""

    def setUp(self):
        import tempfile
        from unittest import mock
        from viz import sources
        self.out = Path(tempfile.mkdtemp())
        resolve = lambda name=None: self.out / name if name else self.out
        self.patches = [mock.patch.object(sources, "resolve_output", resolve),
                        mock.patch.object(viz, "resolve_output", resolve)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()


class ClusterProfileChecks(unittest.TestCase):
    """The k3s address plan became a profile; the default must change nothing."""

    def test_default_profile_is_todays_inference(self):
        captures = ClusterChecks().captures()
        found = cluster.infer_cluster(captures)
        again = cluster.infer_cluster(captures, cluster.K3S)
        self.assertEqual(found, again)
        self.assertEqual(found["profile"]["name"], "k3s")
        self.assertEqual(found["networks"], cluster.NETWORKS)

    def test_kubeadm_preset_moves_the_pod_range(self):
        self.assertEqual(cluster.classify("10.244.1.5", cluster.KUBEADM), "pod")
        self.assertEqual(cluster.classify("10.42.1.5", cluster.KUBEADM), "private")
        self.assertEqual(cluster.classify("10.96.0.10", cluster.KUBEADM), "service")
        self.assertEqual(cluster.classify("10.42.1.5"), "pod")

    def test_profile_round_trips_and_validates(self):
        for profile in cluster.PROFILES.values():
            self.assertEqual(cluster.profile_from_dict(profile.to_dict()), profile)
        custom = cluster.profile_from_dict({"pod_cidrs": "10.1.0.0/16, 10.2.0.0/16",
                                            "control_plane_ports": "6443 2379"})
        self.assertEqual(custom.pod_cidrs, ("10.1.0.0/16", "10.2.0.0/16"))
        self.assertEqual(custom.control_plane_ports, (6443, 2379))
        with self.assertRaises(ValueError):
            cluster.profile_from_dict({"pod_cidrs": ["10.300.0.0/16"]})
        with self.assertRaises(ValueError):
            cluster.profile_from_dict({"pods": ["10.1.0.0/16"]})

    def test_locate_uses_the_profile_the_cluster_was_built_with(self):
        captures = {"pod-a": flow_capture()}
        found = cluster.infer_cluster(captures, cluster.KUBEADM)
        self.assertEqual(cluster.locate(found, "10.244.3.9")["kind"], "pod")
        self.assertEqual(cluster.locate(found, "10.42.3.9")["kind"], "lan")


class SourceChecks(_OutputsInTemp, unittest.TestCase):
    """Files in: what scan reports, what load accepts, and how assignments become a page."""

    def test_scan_tells_captures_by_magic_and_guesses_roles(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        (root / "benign" / "csv files").mkdir(parents=True)
        (root / "nginx attack" / "csv files").mkdir(parents=True)
        _write_csv(flow_capture(), root / "benign" / "csv files", "pod-web-tcp.csv")
        _write_csv(flow_capture(), root / "nginx attack" / "csv files", "pod-web-tcp.csv")
        (root / "odd.csv").write_bytes(_pcap_bytes([(1, 0, b"x" * 20, 20)]))   # a pcap named .csv
        rows = {(Path(r["path"]).parent.parent.name, r["name"]): r for r in sources.scan(root)}
        benign = rows[("benign", "pod-web-tcp.csv")]
        attack = rows[("nginx attack", "pod-web-tcp.csv")]
        self.assertEqual((benign["role"], benign["vantage"], benign["level"], benign["method"]),
                         ("benign", "web", "pod", "tcp"))
        self.assertEqual((attack["role"], attack["scenario"]), ("attack", "nginx attack"))
        odd = next(r for r in rows.values() if r["name"] == "odd.csv")
        self.assertEqual(odd["kind"], "pcap")
        with self.assertRaises(ValueError):
            sources.scan(root / "missing")

    def test_a_csv_without_flow_columns_is_named_not_crashed(self):
        import tempfile
        folder = Path(tempfile.mkdtemp())
        path = _write_csv(flow_capture().drop(columns=["dst_port"]), folder, "short.csv")
        self.assertIn("dst_port", sources.describe_file(path)["problem"])
        with self.assertRaisesRegex(ValueError, "dst_port"):
            sources.load_packets(path)

    def test_header_spelling_is_forgiven(self):
        import tempfile
        frame = flow_capture().rename(columns={"src_ip": "Src IP", "frame_len": "Frame Len"})
        path = _write_csv(frame, tempfile.mkdtemp(), "spelled.csv")
        loaded = sources.load_packets(path)
        self.assertEqual(list(loaded.columns), statemachine.FLOW_COLUMNS)

    def test_a_pcap_is_converted_then_loaded(self):
        frames = [(1000 + s, 0, _sll2(_ipv4(_tcp(40000 + s, 80), 6, "10.42.0.5", "10.43.0.1"), 0x0800), 60)
                  for s in range(5)]
        path = _capture_file(_pcap_bytes(frames), "pod-x-tcp.pcapng")
        loaded = sources.load_packets(path)
        self.assertEqual(len(loaded), 5)
        self.assertEqual(set(loaded["dst_ip"]), {"10.43.0.1"})
        self.assertTrue(any((self.out / sources.CONVERTED_DIR).iterdir()))

    def test_build_records_what_it_was_built_from(self):
        import tempfile
        folder = Path(tempfile.mkdtemp())
        benign = _write_csv(flow_capture(), folder, "b.csv")
        attack = _write_csv(flow_capture(burst=(20, 25)), folder, "a.csv")
        rows = [{"path": str(benign), "role": "benign", "vantage": "web", "level": "pod"},
                {"path": str(attack), "role": "attack", "vantage": "web", "level": "pod",
                 "scenario": "flood"}]
        bundle = sources.build(rows, profile=cluster.KUBEADM)
        self.assertEqual(list(bundle["vantages"]), ["pod-web"])
        scenarios = [c["scenario"] for c in bundle["vantages"]["pod-web"]["playback"]["captures"]]
        self.assertEqual(scenarios, [viz.HELD_OUT, "flood"])
        self.assertEqual([(f["role"], f["tap"]) for f in bundle["source"]["files"]],
                         [("benign", "pod-web"), ("attack", "pod-web")])
        self.assertEqual(bundle["cluster"]["profile"]["name"], "kubeadm")

    def test_attack_only_and_ambiguous_input_is_refused(self):
        import tempfile
        path = str(_write_csv(flow_capture(), tempfile.mkdtemp(), "a.csv"))
        with self.assertRaisesRegex(ValueError, "No benign capture"):
            sources.build([{"path": path, "role": "attack", "vantage": "web", "scenario": "x"}])
        with self.assertRaisesRegex(ValueError, "two captures"):
            sources.build([{"path": path, "role": "benign", "vantage": "web"}] * 2)
        with self.assertRaisesRegex(ValueError, "tap name"):
            sources.build([{"path": path, "role": "benign", "vantage": "a b"}])

    def test_upload_names_cannot_leave_their_folder(self):
        for bad in ("../x.csv", "a/b.csv", ".hidden", "", "..", "a\\b.csv"):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                sources.safe_upload_name(bad)
        self.assertEqual(sources.safe_upload_name("pod-a (1).csv"), "pod-a (1).csv")

    def test_replay_windows_every_second_in_order(self):
        import tempfile
        path = _write_csv(flow_capture(seconds=6), tempfile.mkdtemp(), "r.csv")
        waits = []
        windows = list(sources.ReplaySource(path, speed=4, sleep=waits.append).windows())
        self.assertEqual([w["t"] for w in windows], list(range(6)))
        self.assertEqual(sum(w["packets"] for w in windows), len(flow_capture(seconds=6)))
        self.assertEqual(windows[0]["new_endpoints"], 2)
        self.assertEqual(windows[1]["new_endpoints"], 0)
        self.assertEqual(waits, [0.25] * 5)
        with self.assertRaises(NotImplementedError):
            next(sources.TapSource().windows())


class HarnessParityChecks(unittest.TestCase):
    """The harness must reproduce today's page: the same manifest gives the same bundle."""

    def test_manifest_build_matches_the_static_page_path(self):
        import tempfile
        folder = Path(tempfile.mkdtemp())
        bulk = sorted(evaluation.BULK_LABELS)[0]
        rows = []
        for scenario, label, frame in (
                ("benign", "pod-lidar", flow_capture(vary=True)),
                ("benign", "pod-nginx", flow_capture(start=1000.5)),
                ("benign", bulk, flow_capture()),
                ("flood attack", "pod-lidar", flow_capture(burst=(20, 25))),
                ("flood attack", "pod-nginx", flow_capture(burst=(10, 30))),
                ("udp attack", "pod-lidar", flow_capture(proto="udp", seconds=30))):
            path = _write_csv(frame, folder, f"{scenario}-{label}-tcp.csv".replace(" ", "_"))
            rows.append({"scenario": scenario, "level": data_io.level_from_label(label),
                         "label": label, "method": "tcp", "path": str(path), "usable": True})
        manifest = pd.DataFrame(rows)

        captures = viz.benign_captures(manifest)
        inputs = {}
        for vantage in viz.steady_vantages(captures):
            benign, targets, _ = viz.page_inputs(manifest, vantage, cluster_captures=captures)
            inputs[vantage] = (benign, targets)
        static = viz.build_pages(inputs, captures, selected=viz.DEFAULT_VANTAGE)
        harness = sources.build(sources.manifest_assignments(manifest))

        self.assertEqual(sorted(harness["vantages"]), ["pod-lidar", "pod-nginx"])
        self.assertEqual(_strip_volatile(harness), _strip_volatile(static))


class BakedPageChecks(unittest.TestCase):
    """baked_demo/ is what a clone with no dataset opens on, so it must load and carry no local path."""

    def test_baked_files_load_and_carry_no_local_path(self):
        from viz import bake
        bundle_path = bake.BAKED_DIR / bake.BUNDLE_FILE
        page_path = bake.BAKED_DIR / bake.PAGE_FILE
        if not bundle_path.exists():
            self.skipTest("baked_demo/ not built (run viz/bake.py)")
        bundle = bake.load_bundle(bundle_path)
        self.assertTrue(bundle["vantages"])
        self.assertIn(bundle["selected"], bundle["vantages"])
        for f in bundle["source"]["files"]:
            self.assertTrue(f["path"].startswith("KUBEDATA/"), f["path"])
        self.assertEqual(bake.leaks(json.dumps(bundle)), [])
        self.assertEqual(bake.leaks(page_path.read_text(encoding="utf-8")), [])

    def test_scrub_rewrites_paths_under_the_root(self):
        import tempfile
        from viz import bake
        root = Path(tempfile.mkdtemp()) / "KUBEDATA-somewhere"
        inside = root / "benign" / "csv files" / "pod-web-tcp.csv"
        bundle = {"source": {"files": [{"name": inside.name, "path": str(inside)},
                                       {"name": "x.csv", "path": "/elsewhere/x.csv"}],
                             "notes": [f"read {root}/benign"]},
                  "vantages": {}}
        clean = bake.scrub(bundle, str(root))
        self.assertEqual(clean["source"]["files"][0]["path"],
                         "KUBEDATA/benign/csv files/pod-web-tcp.csv")
        self.assertEqual(clean["source"]["files"][1]["path"], "x.csv")
        self.assertNotIn(str(root), json.dumps(clean))
        self.assertTrue(bake.leaks(str(Path.home() / "x")))

    def test_harness_opens_on_a_saved_bundle(self):
        import gzip
        import tempfile
        import threading
        import urllib.request
        from viz import serve
        folder = Path(tempfile.mkdtemp())
        saved = folder / "bundle.json.gz"
        bundle = sources.build([{"path": str(_write_csv(flow_capture(), folder, "pod-web-tcp.csv")),
                                 "role": "benign", "level": "pod", "vantage": "pod-web"}])
        saved.write_bytes(gzip.compress(viz.to_json(bundle).encode("utf-8")))
        harness = serve.Harness(quiet=True)
        harness.load(saved)
        server = serve.serve(harness, port=0, host="127.0.0.1")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with urllib.request.urlopen(base + "/api/state", timeout=30) as response:
                state = json.loads(response.read().decode("utf-8"))
            self.assertTrue(state["has_bundle"])
            self.assertEqual(state["source"]["drawn"], ["pod-web"])
            with urllib.request.urlopen(base + "/", timeout=30) as response:
                self.assertNotIn("window.VIZ = null;", response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
        with self.assertRaises(ValueError):
            (folder / "not.json").write_text("{}", encoding="utf-8")
            harness.load(folder / "not.json")


class HarnessServerChecks(_OutputsInTemp, unittest.TestCase):
    """The local server: one request per route, on a free port, against fixture captures."""

    def setUp(self):
        super().setUp()
        import tempfile
        import threading
        from viz import serve
        self.folder = Path(tempfile.mkdtemp())
        self.benign = _write_csv(flow_capture(), self.folder, "pod-web-tcp.csv")
        self.server = serve.serve(serve.Harness(quiet=True), port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def call(self, path, body=None, headers=None, raw=None):
        import urllib.error
        import urllib.request
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers or {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8")

    def test_page_is_served_in_server_mode(self):
        status, text = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn("window.VIZ = null;", text)
        self.assertIn("window.VIZ_SERVER = true;", text)
        self.assertIn('data-act="data"', text)

    def test_scan_build_and_export(self):
        status, text = self.call("/api/scan", {"paths": [str(self.folder)]})
        self.assertEqual(status, 200)
        (row,) = json.loads(text)["files"]
        self.assertEqual(row["path"], str(self.benign))
        row["role"] = "benign"
        status, text = self.call("/api/build", {"assignments": [row], "profile": {"name": "k3s"}})
        self.assertEqual(status, 200, text)
        self.assertEqual(list(json.loads(text)["vantages"]), ["pod-web"])
        status, text = self.call("/api/state")
        self.assertEqual(json.loads(text)["source"]["drawn"], ["pod-web"])
        status, text = self.call("/api/export")
        self.assertEqual(status, 200)
        self.assertIn("window.VIZ_SERVER = false;", text)
        self.assertTrue((self.out / "harness_export.html").exists())
        self.assertFalse((self.out / viz.PAGE_HTML).exists())

    def test_errors_come_back_as_messages(self):
        status, text = self.call("/api/build", {"assignments": []})
        self.assertEqual(status, 400)
        self.assertIn("No benign capture", json.loads(text)["error"])
        status, text = self.call("/api/scan", {"paths": [str(self.folder / "nope")]})
        self.assertEqual(status, 400)
        self.assertEqual(self.call("/api/nothing")[0], 404)

    def test_upload_lands_in_the_session_folder_and_refuses_escapes(self):
        body = self.benign.read_bytes()
        status, text = self.call("/api/upload", raw=body, headers={"X-Filename": "up.csv"})
        self.assertEqual(status, 200, text)
        stored = Path(json.loads(text)["file"]["path"])
        self.assertEqual(stored.read_bytes(), body)
        self.assertEqual(stored.parent.parent, self.out / sources.UPLOAD_DIR)
        status, _ = self.call("/api/upload", raw=body, headers={"X-Filename": "../x.csv"})
        self.assertEqual(status, 400)

    def test_live_streams_windows_then_ends(self):
        import urllib.parse
        query = urllib.parse.urlencode({"path": str(self.benign), "speed": 10000})
        status, text = self.call(f"/api/live?{query}")
        self.assertEqual(status, 200)
        events = [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: {\"t\"")]
        self.assertEqual([e["t"] for e in events], list(range(60)))
        self.assertIn("event: end", text)
        self.assertEqual(self.call("/api/live?path=/nonexistent")[0], 400)


class StaticPageModeChecks(unittest.TestCase):
    def test_static_page_is_not_server_mode(self):
        import tempfile
        built = viz.build_page(flow_capture(), {}, {}, "pod-lidar")
        page = viz.write_html(built, Path(tempfile.mkdtemp()) / "p.html").read_text()
        self.assertIn("window.VIZ_SERVER = false;", page)
        self.assertNotIn("window.VIZ = null;", page)


# --- The local cluster that records new captures ------------------------------------------

def _collect():
    spec = importlib.util.spec_from_file_location("collect", "localcluster/collect.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LocalClusterChecks(unittest.TestCase):
    """localcluster/collect.py without a cluster: profiles, rendering, layout, commands."""

    @classmethod
    def setUpClass(cls):
        cls.collect = _collect()
        cls.profiles = {name: cls.collect.load_profile(name) for name in cls.collect.profile_names()}

    def test_both_profiles_exist(self):
        self.assertEqual(sorted(self.profiles), ["general", "lab"])

    def test_recording_names_its_harness_preset(self):
        """The harness opens a recording on the address plan its profile.json names, so a
        general run is not mapped with the k3s plan; an unknown or missing one is ignored."""
        import tempfile
        from viz import serve
        for name, profile in self.profiles.items():
            self.assertIn(profile["harness_profile"], cluster.PROFILES, name)
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(serve.recorded_preset(root))
            (Path(root) / "profile.json").write_text(json.dumps({"harness_profile": "kubeadm"}))
            self.assertEqual(serve.recorded_preset(root), "kubeadm")
            (Path(root) / "profile.json").write_text(json.dumps({"harness_profile": "nope"}))
            self.assertIsNone(serve.recorded_preset(root))
            (Path(root) / "profile.json").write_text("not json")
            self.assertIsNone(serve.recorded_preset(root))

    def test_lab_taps_are_kubedata_labels(self):
        labels = {t["label"] for t in self.collect.taps(self.profiles["lab"])}
        self.assertEqual(labels, {"pod-nginx", "pod-lidar", "pod-camera", "pod-robot-controller",
                                  "pod-robot-hardware", "node-child1", "node-child2", "node-child4",
                                  "node-gchild9", "router-any", "router-flannel"})

    def test_every_tap_is_a_level_name_label(self):
        for name, profile in self.profiles.items():
            for tap in self.collect.taps(profile):
                with self.subTest(profile=name, tap=tap["label"]):
                    self.assertEqual(data_io.level_from_label(tap["label"]), tap["level"])
                    sources.assignment_label({"vantage": tap["label"], "level": tap["level"]})

    def test_profile_address_plans_match_the_harness_presets(self):
        for name, profile in self.profiles.items():
            preset = cluster.PROFILES[profile["harness_profile"]]
            with self.subTest(profile=name):
                self.assertEqual(profile["cidrs"]["pod"], preset.pod_cidrs[0])
                self.assertEqual(profile["cidrs"]["service"], preset.service_cidrs[0])
        k3d = Path("localcluster/profiles/general/k3d.yaml").read_text()
        self.assertIn("--cluster-cidr=10.244.0.0/16", k3d)
        self.assertIn("--service-cidr=10.96.0.0/12", k3d)

    def test_workloads_render_with_sidecars_on_tapped_pods_only(self):
        for name, profile in self.profiles.items():
            objects = self.collect.render_workloads(profile)
            deployments = {o["metadata"]["name"]: o for o in objects if o["kind"] == "Deployment"}
            for w in profile["workloads"]:
                with self.subTest(profile=name, workload=w["name"]):
                    pod = deployments[w["name"]]["spec"]["template"]["spec"]
                    names = [c["name"] for c in pod["containers"]]
                    self.assertEqual(names, ["app", "capture"] if w.get("tap") else ["app"])
                    self.assertEqual(pod["nodeSelector"]["rtct/name"], w["node"])
                    self.assertIn(w["node"], profile["nodes"].values())
        controller = next(o for o in self.collect.render_workloads(self.profiles["lab"])
                          if o["metadata"]["name"] == "robot-controller" and o["kind"] == "Deployment")
        spec = controller["spec"]["template"]["spec"]
        self.assertTrue(spec["hostNetwork"])
        self.assertEqual(spec["dnsPolicy"], "ClusterFirstWithHostNet")

    def test_every_mode_a_profile_names_exists_in_traffic(self):
        spec = importlib.util.spec_from_file_location("traffic", "localcluster/traffic.py")
        traffic = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(traffic)
        for name, profile in self.profiles.items():
            modes = [w["mode"] for w in profile["workloads"] if "mode" in w]
            modes += [a["mode"] for a in profile["attacks"].values() if "mode" in a]
            for mode in modes:
                with self.subTest(profile=name, mode=mode):
                    self.assertIn(mode, traffic.MODES)

    def test_scans_stay_inside_the_cluster(self):
        import ipaddress
        for name, profile in self.profiles.items():
            ranges = [ipaddress.ip_network(c) for c in profile["cidrs"].values()]
            for target in profile["attacks"]["scan"]["targets"]:
                with self.subTest(profile=name, target=target):
                    net = ipaddress.ip_network(target)
                    self.assertTrue(any(net.subnet_of(r) for r in ranges))

    def test_attacks_render(self):
        for name, profile in self.profiles.items():
            for scenario, spec in profile["attacks"].items():
                with self.subTest(profile=name, scenario=scenario):
                    if spec["kind"] == "exec":
                        workload, argv = self.collect.attack_exec_args(profile, scenario, 49)
                        self.assertIn(workload, [w["name"] for w in profile["workloads"]])
                        self.assertIn("seconds=49", argv)
                    else:
                        job = self.collect.render_attack_job(profile, scenario, 49)
                        pod = job["spec"]["template"]["spec"]
                        self.assertEqual(pod["nodeSelector"]["rtct/name"], profile["attack_node"])
                        self.assertIn("49", " ".join(pod["containers"][0]["command"]))
        with self.assertRaises(ValueError):
            self.collect.attack_seconds(60, 60)
        self.assertEqual(self.collect.attack_seconds(60, 10), 50)

    def test_every_tap_gets_a_bounded_tcpdump(self):
        profile = self.profiles["lab"]
        for tap in self.collect.taps(profile):
            with self.subTest(tap=tap["label"]):
                argv = self.collect.capture_argv(profile, tap, 60, "/stage", "pod-x", "br-abc")
                self.assertEqual(argv[argv.index("timeout"):argv.index("timeout") + 4],
                                 ["timeout", "-s", "INT", "60"])
                self.assertIn(f"{tap['label']}-tcp.pcap", argv[argv.index("-w") + 1])
                if tap["label"] == "router-flannel":
                    self.assertEqual(argv[-1], "udp port 8472")
                if tap["level"] == "node":
                    self.assertIn(f"container:{tap['container']}", argv)

    def test_a_run_is_laid_out_like_kubedata(self):
        """A fake run's CSVs read as a manifest, and its pcaps scan with the right roles."""
        import tempfile
        out = Path(tempfile.mkdtemp())
        profile = self.profiles["lab"]
        frame = flow_capture(seconds=5)
        for scenario in ("benign", "http-flood"):
            for label in ("pod-nginx", "node-child4"):
                csv_file = self.collect.csv_path(out, scenario, label)
                csv_file.parent.mkdir(parents=True, exist_ok=True)
                frame.to_csv(csv_file, index=False)
                pcap = self.collect.pcap_path(out, scenario, label)
                pcap.parent.mkdir(parents=True, exist_ok=True)
                pcap.write_bytes(_pcap_bytes([(1, 0, b"x" * 20, 20)]))
        manifest = data_io.build_manifest(out)
        self.assertEqual(set(manifest["scenario"]), {"benign", "http-flood attack"})
        self.assertEqual(set(manifest["label"]), {"pod-nginx", "node-child4"})
        rows = sources.manifest_assignments(manifest.assign(usable=True))
        self.assertEqual(sorted(r["role"] for r in rows), ["attack", "attack", "benign", "benign"])
        scanned = [r for r in sources.scan(out) if r["kind"] == "pcap"]
        by = {(r["scenario"], r["vantage"], r["level"]): r["role"] for r in scanned}
        self.assertEqual(by, {("benign", "nginx", "pod"): "benign", ("benign", "child4", "node"): "benign",
                              ("http-flood attack", "nginx", "pod"): "attack",
                              ("http-flood attack", "child4", "node"): "attack"})


class SettledStepsChecks(unittest.TestCase):
    """viz/layout.settled_steps replays ALERGIA's folds on prefix-tree ids. It must follow the
    learner exactly, child insertion order and self-folds included, or it loses a state."""

    @staticmethod
    def replay(traces):
        events = []
        statemachine.learn_pdfa(traces, trace=events)
        nodes = layout.icicle(events[0][1])
        by_path = {n["path"]: n["id"] for n in nodes}
        steps = [{"kind": e["kind"], "red": by_path[e["red_path"]], "blue": by_path[e["path"]]}
                 for e in events[1:]]
        return nodes, layout.settled_steps(nodes, steps, root=events[0][1])

    def test_a_fold_that_adds_a_symbol_twice_follows_insertion_order(self):
        # found by node-child4 of a local recording: sorted child order loses state 'b'
        traces = [("b", "c", "b", "b", "b"), ("b", "b", "c", "a", "c"), ("a", "b", "a", "a", "c"),
                  ("b", "c", "c", "c", "a"), ("b", "a", "c", "a", "c"), ("b", "b", "c", "a", "b"),
                  ("b", "b", "c", "c", "a")]
        nodes, settled = self.replay(traces)
        self.assertEqual(set(settled), {n["id"] for n in nodes})

    def test_random_traces_always_replay(self):
        import random
        rng = random.Random(0)
        for trial in range(400):
            alphabet = rng.choice(["ab", "abc", "abcd", "a"])
            traces = [tuple(rng.choice(alphabet) for _ in range(5))
                      for _ in range(rng.randint(5, 80))]
            with self.subTest(trial=trial):
                nodes, settled = self.replay(traces)
                self.assertEqual(set(settled), {n["id"] for n in nodes})


class LiveChecks(unittest.TestCase):
    """viz/live.py: the stream path agrees with the recording path wherever a stream can."""

    @staticmethod
    def rows(frame):
        return [{k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in r.items()}
                for r in frame.to_dict("records")]

    def test_pcap_stream_reads_what_the_file_reader_reads(self):
        import io
        from convert.read import CaptureReader
        from viz import live
        datas = [_sll2(_ipv4(_tcp(40000 + i, 80, payload=bytes(i * 10)), 6,
                             src="10.244.0.5", dst="10.96.0.7"), 0x0800) for i in range(12)]
        frames = [(1771545908 + i // 3, (i * 125000) % 1000000, data, len(data) + 4)
                  for i, data in enumerate(datas)]
        blob = _pcap_bytes(frames)
        tee = bytearray()
        streamed = list(live.PcapStream(io.BytesIO(blob), tee=tee.extend).frames())
        read = list(CaptureReader(str(_capture_file(blob, "s.pcap"))).frames())
        self.assertEqual(streamed, read)
        self.assertEqual(bytes(tee), blob)       # Record writes the same pcap that arrived
        row = live.packet_row(streamed[3])
        self.assertEqual((row["src_ip"], row["dst_ip"], row["dst_port"], row["proto"]),
                         ("10.244.0.5", "10.96.0.7", 80, "tcp"))
        # a stream cut mid-record ends cleanly with the frames that were whole
        self.assertEqual(len(list(live.PcapStream(io.BytesIO(blob[:-5])).frames())), 11)

    def test_windower_keeps_the_flows_segment_flows_keeps(self):
        """With no 5-tuple reused, the causal rule and the offline rule keep the same flows."""
        from viz import live
        packets = flow_capture(vary=True)
        offline, _ = statemachine.segment_flows(statemachine.make_flows(packets), packets["ts"].min())
        online = live.live_flows(self.rows(packets))
        columns = ["start_ts", "bytes", "duration"]
        self.assertEqual(offline[columns].astype(float).values.tolist(),
                         online[columns].astype(float).values.tolist())

    def test_windower_drops_a_flow_that_spans_seconds(self):
        from viz import live
        base = {"frame_len": 60, "src_ip": "a", "dst_ip": "b", "dst_port": 53, "proto": "udp"}
        rows = [dict(base, ts=t, src_port=port) for t, port in
                ((0.25, 1), (1.25, 1),            # one 5-tuple across two seconds: dropped
                 (0.5, 2), (0.6, 2),              # wholly inside second 0: kept
                 (2.5, 3), (12.5, 3))]            # reused ten seconds later: first kept, reuse not
        windower = live.Windower(lateness=2)
        closed = [c for r in rows for c in windower.add(r)] + windower.flush()
        kept = {c["t"]: list(c["flow_rows"]["start_ts"]) for c in closed if len(c["flow_rows"])}
        self.assertEqual(kept, {0: [0.5], 2: [2.5]})
        # each closed second also says who talked to whom, for the live map
        self.assertEqual(closed[0]["pairs"], [["a", "b", 3]])
        self.assertEqual(closed[5]["pairs"], [])
        self.assertEqual([c["t"] for c in closed], list(range(13)))   # quiet seconds still close

    def test_live_detector_reproduces_the_page(self):
        """The same capture, streamed, gets the page's per-window peaks and statuses."""
        from viz import live
        benign, attack = flow_capture(vary=True), flow_capture(burst=(20, 30), vary=True)
        calibration = viz.calibrate(benign)
        page = viz.build_page(benign, {"flood": attack}, {}, "pod-web")
        windows = page["playback"]["captures"][1]["windows"]
        detector, windower = live.LiveDetector(calibration), live.Windower()
        verdicts = []
        for row in self.rows(attack):
            verdicts += [detector.window(c, windower.t0) for c in windower.add(row)]
        verdicts += [detector.window(c, windower.t0) for c in windower.flush()]
        self.assertEqual([w["status"] for w in windows], [v["status"] for v in verdicts])
        for w, v in zip(windows, verdicts):
            if v["peak"] is None:
                self.assertTrue(np.isnan(w["peak"]))
            else:
                self.assertAlmostEqual(w["peak"], v["peak"])
        self.assertTrue(any(v["alert"] for v in verdicts))

    def test_live_calibration_learns_from_live_cut_flows(self):
        from viz import live
        benign = flow_capture(vary=True)
        calibration = live.calibrate_live(benign)
        self.assertEqual(len(calibration["flows"]), len(live.live_flows(self.rows(benign))))
        self.assertIn("windowed", calibration["cutoffs"])

    def test_wrong_address_plan_is_named(self):
        """k3s traffic built under kubeadm draws every pod as a LAN device; the build says so."""
        from viz import sources
        k3s = flow_capture()      # its pods are 10.42.x
        self.assertIsNone(sources.better_preset({"pod-a": k3s}, cluster.K3S))
        self.assertEqual(sources.better_preset({"pod-a": k3s}, cluster.KUBEADM)[0], "k3s")

    def test_cross_site_posts_are_refused(self):
        import threading
        import urllib.error
        import urllib.request
        from viz import serve
        server = serve.serve(serve.Harness(quiet=True), port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            def post(path, origin):
                headers = {"Content-Type": "application/json"}
                if origin:
                    headers["Origin"] = origin
                request = urllib.request.Request(base + path, data=b"{}", headers=headers)
                try:
                    with urllib.request.urlopen(request, timeout=10) as response:
                        return response.status
                except urllib.error.HTTPError as error:
                    return error.code
            for path in ("/api/attack", "/api/monitor/start", "/api/scan", "/api/baseline"):
                self.assertEqual(post(path, "http://evil.example"), 403, path)
            self.assertEqual(post("/api/scan", base), 200)
            self.assertEqual(post("/api/scan", None), 200)   # curl and tests send no Origin
        finally:
            server.shutdown()
            server.server_close()

    def test_stream_commands_write_pcap_to_stdout(self):
        collect = _collect()
        profile = collect.load_profile("general")
        for tap in collect.taps(profile):
            argv = collect.stream_argv(profile, tap, pod="api-x", bridge="br-123")
            self.assertEqual(argv[argv.index("-w") + 1], "-", tap["label"])
            self.assertIn("-U", argv)
            self.assertNotIn("timeout", argv)
            if tap["level"] == "pod":
                self.assertEqual(argv[:3], ["kubectl", "--context", "k3d-rtct-general"])
            else:   # a named container, so stopping the monitor can remove it
                self.assertEqual(argv[argv.index("--name") + 1], collect.live_container(tap))

    def test_cluster_summary_from_kubectl_json(self):
        collect = _collect()
        profile = collect.load_profile("general")
        listed = [{"name": "rtct-general", "serversRunning": 1, "serversCount": 1,
                   "agentsRunning": 2, "agentsCount": 2}]
        node = lambda name, label, ready: {"metadata": {"name": name, "labels": {"rtct/name": label}},
                                           "status": {"conditions": [{"type": "Ready", "status": ready}]}}
        nodes = {"items": [node("k3d-a", "agent1", "True"), node("k3d-s", "server", "True")]}
        pods = {"items": [{"metadata": {"name": "api-1", "labels": {"app": "api", "rtct/role": "workload"}},
                           "status": {"phase": "Running", "podIP": "10.244.1.5",
                                      "containerStatuses": [{"ready": True}, {"ready": True}]},
                           "spec": {"nodeName": "k3d-a"}}]}
        services = {"items": [{"metadata": {"name": "api", "namespace": "rtct"},
                               "spec": {"clusterIP": "10.96.4.4", "ports": [{"name": "http", "port": 8080}]}},
                              {"metadata": {"name": "headless", "namespace": "rtct"}, "spec": {"clusterIP": "None"}}]}
        found = collect.summarize_cluster(profile, listed, nodes, pods, services)
        self.assertEqual([(x["name"], x["ip"]) for x in found["services"]], [("api", "10.96.4.4")])
        self.assertEqual(found["pods"][0]["namespace"], None)
        self.assertFalse(found["pods"][0]["host_network"])
        self.assertTrue(found["running"])
        self.assertEqual([n["name"] for n in found["nodes"]], ["agent1", "server"])
        self.assertEqual(found["pods"][0]["ip"], "10.244.1.5")
        nodes["items"][1]["status"]["conditions"][0]["status"] = "False"
        self.assertFalse(collect.summarize_cluster(profile, listed, nodes, pods)["running"])
        self.assertFalse(collect.summarize_cluster(profile, [], nodes, pods)["running"])


if __name__ == "__main__":
    unittest.main()