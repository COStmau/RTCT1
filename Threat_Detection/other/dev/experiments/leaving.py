"""A role contract that can say a conversation left it, on one labelled session.

Three detectors per tapped instance of a role, each learned from that instance's own first
minutes and cut off at the held-out end of them:

  flow            today's flow symbols, frequency score (the detector the live monitor runs)
  role            the role's symbols, frequency score
  role+leaving    the same machine; a window is flagged by the frequency score or by the
                  count of conversations that left the contract (methods.roles.role_leaving)

Judged as experiments/roles.py judges: attacks by alerts newly raised, benign windows later
in the session, and the benign windows of a second session. The rule is verdicts/leaving.py.

Run it with:
  .venv/bin/python other/dev/experiments/leaving.py <session> --second <benign session>
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1]),
                 str(Path(__file__).resolve().parents[3] / "subsystem")]

import argparse
import json

import numpy as np
import pandas as pd

from verdicts import leaving as leaving_verdict
from core.data_io import resolve_output
from core.detectors import persistent_mask
from experiments.roles import TRAIN_FRACTION, fit, load_instance, scores
from experiments.session_score import judge
from methods import roles
from methods.scores import FORGET_SECONDS, frequency_cutoff

LEAVING_CSV = "leaving.csv"


def detectors(role, inst, train_seconds):
    """{variant: flags(instance)} for one instance: its machines and cutoffs, ready to apply."""
    learn, held = int(train_seconds * TRAIN_FRACTION), slice(int(train_seconds * TRAIN_FRACTION) + 1, int(train_seconds))
    before = lambda symbols: inst[symbols][inst[symbols]["start_ts"] - inst["t0"] < learn]
    over = lambda values, cutoff: np.nan_to_num(values, nan=-np.inf) > cutoff
    models = {symbols: fit(role, symbols, [before(symbols)]) for symbols in ("flow", "role")}
    left = lambda other: roles.role_leaving(models["role"], other["role"], other["t0"], other["n"])[0]
    cut = {symbols: frequency_cutoff(scores(model, symbols, inst)[held]) for symbols, model in models.items()}
    cut["leaving"] = frequency_cutoff(left(inst)[held])
    frequency = lambda symbols: lambda other: over(scores(models[symbols], symbols, other), cut[symbols])
    return {"flow": frequency("flow"), "role": frequency("role"),
            "role+leaving": lambda other: frequency("role")(other) | over(left(other), cut["leaving"])}


def session_rows(session, train_seconds, second=None):
    """Rows per (label, variant): a benign row, attack rows, and second-session benign."""
    attacks = json.loads((Path(session) / "attacks.json").read_text())
    captures = lambda root: {p.name[:-len("-tcp.pcap")]: p for p in sorted(Path(root).glob("*/pcapng files/*-tcp.pcap"))}
    here, there = captures(session), captures(second) if second else {}
    rows = []
    for label, capture in here.items():
        role = roles.role_of(label)
        if role is None:
            continue
        inst = load_instance(capture)
        other = load_instance(there[label], inst["own"]) if label in there else None
        scored = lambda i, skip: np.isin(np.arange(i["n"]), i["role"]["window"]) & (np.arange(i["n"]) >= skip)
        for variant, flags in detectors(role, inst, train_seconds).items():
            common = {"role": role.name, "label": label, "variant": variant}
            rows += [dict(common, **row) for row in judge(flags(inst), scored(inst, train_seconds), inst["t0"], attacks)]
            if other:
                flagged, benign = flags(other), scored(other, FORGET_SECONDS)       # a cold clock
                rows.append(dict(common, scenario="second benign", windows=int(benign.sum()),
                                 flagged=int(flagged[benign].sum()),
                                 alert_windows=int(persistent_mask(flagged).to_numpy()[benign].sum())))
    return rows, attacks


def totals(frame, attacks):
    """Per variant, pooled over roles and taps: the rows verdicts/leaving.py reads."""
    kinds = len({a["scenario"] for a in attacks})
    out = []
    for variant, rows in frame.groupby("variant"):
        hit = rows[rows["scenario"].ne("benign") & rows["scenario"].ne("second benign") & rows["scored"].eq(True)]
        benign, second = rows[rows["scenario"].eq("benign")], rows[rows["scenario"].eq("second benign")]
        out.append({"variant": variant,
                    "rounds": [(len(g), int(g["detected"].sum())) for _, g in hit.groupby(hit["attack"] // kinds)],
                    "benign_windows": int(benign["windows"].sum()),
                    "benign_alert_windows": int(benign["alert_windows"].sum()),
                    "second_benign_windows": int(second["windows"].sum()),
                    "second_benign_alert_windows": int(second["alert_windows"].sum())})
    return out


def main():
    parser = argparse.ArgumentParser(description="A role contract with a count of the conversations that leave it.")
    parser.add_argument("session")
    parser.add_argument("--second", help="another session of the same taps, benign, never learned from")
    parser.add_argument("--train", type=float, default=600.0)
    parser.add_argument("--out", default=LEAVING_CSV)
    args = parser.parse_args()
    rows, attacks = session_rows(args.session, args.train, args.second)
    frame = pd.DataFrame(rows)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows, {len(attacks)} attacks, taps {sorted(frame['label'].unique())}")
    hit = frame[frame["scored"].eq(True)]
    print(hit.groupby(["variant", "label", "scenario"])["detected"].sum().unstack("scenario").to_string())
    verdict, reasons = leaving_verdict.decide(totals(frame, attacks))
    print(f"\nLeaving verdict: {verdict}")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
