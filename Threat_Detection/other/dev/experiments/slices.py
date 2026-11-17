"""Sliced flows against whole flows, on the adopted detector, on every stratum.

Each tap is run twice through experiments/novelty.py's rows: once with today's flow rule
(`segment_flows`, a flow crossing a second is dropped) and once with `slice_flows` (it is cut
at the seconds it crosses, and each slice says new or continuing). Everything else is the
same: the machine is learned from the first 70% of the benign recording's flows, both
cutoffs come from the held-out windows, and an event is an attack recording with a
persistent alert in its warm windows.

Run it with:  .venv/bin/python other/dev/experiments/slices.py
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1]),
                 str(Path(__file__).resolve().parents[3] / "subsystem")]

import argparse
from functools import partial

import pandas as pd

from verdicts import slices as slices_verdict
from core.data_io import MANIFEST_NAME, load_manifest, resolve_output
from experiments import novelty
from experiments.windowed_scores import sweep
from methods.pdfa import slice_flows

SLICES_CSV = "slices.csv"
RULES = {"whole": novelty.whole_flows, "sliced": slice_flows}


def main():
    parser = argparse.ArgumentParser(description="Measure sliced flows against whole flows and "
                                                 "print the pre-registered verdict.")
    parser.add_argument("--methods", nargs="+", default=["tcp", "ptcp"], choices=("tcp", "ptcp"))
    parser.add_argument("--out", default=SLICES_CSV)
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args()

    import local_paths
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    frames = []
    for rule, flows_of in RULES.items():
        frame, excluded = sweep(manifest, args.methods, rows_for=partial(novelty.label_rows, flows_of=flows_of))
        frames.append(frame.assign(rule=rule))
        for item in excluded:
            print(f"  excluded under {rule}: {item}")
    frame = pd.concat(frames, ignore_index=True)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows")
    for rule in RULES:
        print(f"-- {rule}")
        print("\n".join(novelty.summarize(frame[frame["rule"].eq(rule)])))
    verdict, reasons = slices_verdict.decide(frame.to_dict("records"))
    print(f"\nSlices verdict: {verdict}")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
