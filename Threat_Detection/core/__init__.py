"""The detection subsystem. Four layers, one direction, nothing else in here.

    data_io    read captures, resolve output paths, build the capture manifest
    features   packets -> one row per second (13 features, 9 of them read by the detectors; no baseline, no thresholds)
    detectors  the detector protocol (fit/calibrate/score/flag) and the z-score
    reporting  render results: tables, charts, the event stream

`data_io -> features -> detectors -> reporting`. Nothing downstream reaches back upstream,
and none of the four import `local_paths`, so they are portable and testable on their own.

The common path, in six calls:

    from core import load_capture, make_windows, build_detector, split_reference

    windows   = make_windows(load_capture(path))
    reference, held_out = split_reference(windows)
    detector  = build_detector("z_score").pipeline(reference, held_out)
    results   = detector.annotate(windows)       # score, flag, status, evidence

Everything outside `core` is experiment, presentation, or capture conversion.
"""
from core.data_io import (MANIFEST_NAME, PACKET_COLUMNS, PACKET_REQUIRED, build_manifest,
                          describe_captures, level_from_label, load_capture, load_manifest,
                          parse_capture, resolve_output, timebase_issues)
from core.detectors import (BENIGN_QUANTILE, PERSISTENCE_WINDOW, THRESHOLD, Detector,
                            REGISTRY, ZScoreDetector, build as build_detector, flag_stats,
                            persistent_mask)
from core.evaluation import BULK_LABELS, TRAIN_FRACTION, WARMUP_WINDOWS
from core.features import (DETECTION_FEATURES, FEATURE_GROUPS, FEATURE_LABELS, WINDOW_SIZE, load_all_windows,
                           make_windows, split_reference)
from core.reporting import to_events, write_events, write_report

__all__ = [
    # io
    "MANIFEST_NAME", "PACKET_COLUMNS", "PACKET_REQUIRED", "build_manifest", "describe_captures",
    "level_from_label", "load_capture", "load_manifest", "parse_capture", "resolve_output",
    "timebase_issues",
    # windows
    "DETECTION_FEATURES", "FEATURE_GROUPS", "FEATURE_LABELS", "WINDOW_SIZE", "load_all_windows", "make_windows",
    "split_reference",
    # detectors
    "BENIGN_QUANTILE", "PERSISTENCE_WINDOW", "THRESHOLD", "Detector", "REGISTRY",
    "ZScoreDetector", "build_detector", "flag_stats", "persistent_mask",
    # policy
    "BULK_LABELS", "TRAIN_FRACTION", "WARMUP_WINDOWS",
    # reporting
    "to_events", "write_events", "write_report",
]
