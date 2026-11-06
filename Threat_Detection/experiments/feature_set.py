"""All 13 features against the eight-feature candidate, judged by verdicts/feature_set.py.

Both sets run the same z-score detector, split and cutoff; only the columns differ. For every
steady tap and capture method the detector is fitted on the first 70% of the benign windows,
calibrated on the rest, and scored on the held-out benign windows and on each attack capture.

Per stratum it records persistent alerts on held-out benign windows, and for each attack the
AUROC against the held-out benign scores and the detection at a 5% benign budget (the
realised benign rate is stored beside it: on 15-20 windows it is not 5%). Bulk taps are
scored and reported but decide nothing.

`--rule hybrid` swaps in the nine-feature candidate of verdicts/feature_set_hybrid.py, which
is judged by the same decide(); each rule writes its own CSV.

Run it with:  .venv/bin/python experiments/feature_set.py [--rule eight|hybrid]
"""
import sys
from pathlib import Path

# A script run as `python experiments/feature_set.py` gets experiments/ as sys.path[0].
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse

import numpy as np
import pandas as pd

from core import (BULK_LABELS, build_detector, load_manifest, persistent_mask, resolve_output,
                  split_reference)
from core.data_io import MANIFEST_NAME
from core.features import load_all_windows
from experiments import metrics
from verdicts import feature_set as verdict
from verdicts import feature_set_hybrid as hybrid

FEATURE_SET_CSV = "feature_set.csv"
BUDGET = 0.05
CANDIDATE = ["unique_dst_ips", "unique_dst_ports", "syn_count", "rst_count",
             "http_count", "dns_count", "https_count", "http_frac"]


def _finite(scores):
    return scores.replace([np.inf, -np.inf], np.nan).dropna().to_numpy()


def rows_for(label, method, benign, attacks, columns, name):
    """The held-out benign row and one row per attack for one tap under one feature set."""
    reference, held = split_reference(benign[columns])
    detector = build_detector("z_score", features=None).pipeline(reference, held)   # the columns are the arm
    held_scores, held_flags = detector.score(held), detector.flag(held)
    group = "bulk" if label in BULK_LABELS else "steady"
    rows = [{"set": name, "method": method, "label": label, "group": group,
             "scenario": "benign", "windows": len(held), "flagged": int(held_flags.sum()),
             "persistent": int(persistent_mask(held_flags).sum())}]
    for scenario, windows in attacks.items():
        scores, flags = detector.score(windows[columns]), detector.flag(windows[columns])
        row = {"set": name, "method": method, "label": label, "group": group,
               "scenario": scenario, "windows": len(windows), "flagged": int(flags.sum()),
               "persistent": int(persistent_mask(flags).sum()),
               "auroc": np.nan, "detection": np.nan, "realised_benign_rate": np.nan}
        benign_side, attack_side = _finite(held_scores), _finite(scores)
        if len(benign_side) and len(attack_side):
            row["auroc"] = metrics.auroc(benign_side, attack_side)
            row["detection"], row["realised_benign_rate"] = metrics.detection_at_rate(
                benign_side, attack_side, BUDGET)
        rows.append(row)
    return rows


def sweep(manifest, candidate=CANDIDATE):
    windows, notes = load_all_windows(manifest)
    every = None
    rows = []
    for (scenario, label, method), benign in windows.items():
        if scenario != "benign" or benign is None:
            continue
        if every is None:
            every = list(benign.columns)
        attacks = {s: windows[(s, label, method)] for s in sorted({k[0] for k in windows})
                   if s != "benign" and windows.get((s, label, method)) is not None}
        for name, columns in (("all", every), ("candidate", candidate)):
            try:
                rows += rows_for(label, method, benign, attacks, columns, name)
            except ValueError:
                continue
    return pd.DataFrame(rows)


def summarize(frame):
    """The pooled summaries verdicts.feature_set.decide reads, from steady strata only."""
    steady = frame[frame["group"].eq("steady")]
    out = {}
    for method in verdict.METHODS:
        at = steady[steady["method"].eq(method)]
        benign = at[at["scenario"].eq("benign")]
        out[method] = {
            "benign_windows": int(benign[benign["set"].eq("all")]["windows"].sum()),
            "persistent": {s: int(benign[benign["set"].eq(s)]["persistent"].sum())
                           for s in ("all", "candidate")}}
        for scenario in verdict.SCENARIOS:
            attack = at[at["scenario"].eq(scenario)]
            out[method][scenario] = {
                key: {s: float(attack[attack["set"].eq(s)][key].mean())
                      for s in ("all", "candidate")} for key in ("auroc", "detection")}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    parser.add_argument("--rule", choices=("eight", "hybrid"), default="eight")
    args = parser.parse_args()
    candidate, out = ((CANDIDATE, FEATURE_SET_CSV) if args.rule == "eight"
                      else (hybrid.CANDIDATE, "feature_set_hybrid.csv"))

    import local_paths
    frame = sweep(load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest), candidate)
    frame.to_csv(resolve_output(out), index=False)
    summary = summarize(frame)
    print(f"Wrote {out} | rows={len(frame)} | candidate: {', '.join(candidate)}")
    for method, s in summary.items():
        print(f"\n{method} | steady held-out benign windows {s['benign_windows']} | "
              f"persistent alerts all {s['persistent']['all']} -> candidate "
              f"{s['persistent']['candidate']}")
        for scenario in verdict.SCENARIOS:
            r = s[scenario]
            print(f"  {scenario:<17} AUROC {r['auroc']['all']:.3f} -> {r['auroc']['candidate']:.3f}"
                  f" | detection at 5% {r['detection']['all']:.3f} -> "
                  f"{r['detection']['candidate']:.3f}")
    steady = frame[frame["group"].eq("steady") & frame["scenario"].eq("benign")]
    bulk = frame[frame["group"].eq("bulk") & frame["scenario"].eq("benign")]
    print("\nheld-out benign windows flagged (not part of the verdict)")
    for method in verdict.METHODS:
        for group, part in (("steady", steady), ("bulk", bulk)):
            x = part[part["method"].eq(method)]
            print(f"  {method:<5}{group:<7}" + "  ".join(
                f"{s}: {x[x['set'].eq(s)]['flagged'].sum() / x[x['set'].eq(s)]['windows'].sum():.3f}"
                for s in ("all", "candidate")))
    decision, reasons = verdict.decide(summary)
    print(f"\nfeature-set verdict: {decision}")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
