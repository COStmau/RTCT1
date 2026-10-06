"""Run from this folder with: python -m unittest -v test_mvp"""
import unittest

import numpy as np
import pandas as pd

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


if __name__ == "__main__":
    unittest.main()
