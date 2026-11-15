"""Role machines against a tap's own machine, on one labelled session.

For every role with a tapped instance in the session, four detectors, the cross of two
choices: the machine is learned from the instance's `own` first minutes or `pooled` over the
role's instances, and its symbols are today's `flow` symbols or the `role`'s (methods/roles.py).
All four use the frequency score and take their cutoff from the held-out end of the learning
stretch: an own machine from its own tap, a pooled machine from the role's taps together, one
cutoff for the role. own / flow is the detector the live monitor runs.

Each is judged as experiments/session_score.py judges: attacks by alerts newly raised, benign
windows later in the session, and, with --second, the benign windows of another session the
machine never saw. The rule is verdicts/roles.py, which is meant for a held-out session.

Run it with:
  .venv/bin/python dev/experiments/roles.py <session> --second <benign session>
"""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

import argparse
import json

import numpy as np
import pandas as pd

from verdicts import roles as roles_verdict
from core.data_io import resolve_output
from core.detectors import persistent_mask
from core.features import WINDOW_SIZE
from experiments.novelty import whole_flows
from experiments.session_score import judge
from methods import roles
from methods.pdfa import fit_segments
from methods.scores import FORGET_SECONDS, frequency_cutoff, frequency_scores_by_window

ROLES_CSV = "roles.csv"
TRAIN_FRACTION = 0.7       # of the learning stretch; the rest sets the cutoff
VARIANTS = [(source, symbols) for source in ("own", "pooled") for symbols in ("flow", "role")]


def load_instance(capture):
    """One tapped instance: its packets as both kinds of record, on its own clock."""
    packets = roles.load_packets(capture)
    t0 = float(packets["ts"].min())
    return {"t0": t0, "n": int((float(packets["ts"].max()) - t0) // WINDOW_SIZE) + 1,
            "flow": whole_flows(packets, t0),
            "role": roles.exchanges(packets, roles.own_address(packets), t0)}


def fit(role, symbols, learned):
    """A machine of the given symbols from one or more instances' learning records."""
    return fit_segments(learned) if symbols == "flow" else roles.fit_role(learned, role)


def scores(model, symbols, instance):
    if symbols == "flow":
        return frequency_scores_by_window(model, instance["flow"], instance["t0"], instance["n"], FORGET_SECONDS)
    return roles.role_scores(model, instance["role"], instance["t0"], instance["n"])[0]


def role_models(role, instances, train_seconds):
    """{(source, symbols): {label: (model, cutoff)}} for one role's instances."""
    learn, held = int(train_seconds * TRAIN_FRACTION), slice(int(train_seconds * TRAIN_FRACTION) + 1, int(train_seconds))
    before = lambda inst, symbols: inst[symbols][inst[symbols]["start_ts"] - inst["t0"] < learn]
    out = {}
    for symbols in ("flow", "role"):
        own = {label: fit(role, symbols, [before(inst, symbols)]) for label, inst in instances.items()}
        out[("own", symbols)] = {label: (model, frequency_cutoff(scores(model, symbols, instances[label])[held]))
                                 for label, model in own.items()}
        pooled = fit(role, symbols, [before(inst, symbols) for inst in instances.values()])
        cutoff = frequency_cutoff(np.concatenate([scores(pooled, symbols, inst)[held] for inst in instances.values()]))
        out[("pooled", symbols)] = {label: (pooled, cutoff) for label in instances}
    return out


def session_rows(session, train_seconds, second=None):
    """Rows per (role, label, source, symbols): a benign row, attack rows, and second-session benign."""
    attacks = json.loads((Path(session) / "attacks.json").read_text())
    captures = lambda root: {p.name[:-len("-tcp.pcap")]: p for p in sorted(Path(root).glob("*/pcapng files/*-tcp.pcap"))}
    here, there = captures(session), captures(second) if second else {}
    rows = []
    for role in roles.ROLES:
        labels = [label for label in here if roles.role_of(label) == role]
        if not labels:
            continue
        instances = {label: load_instance(here[label]) for label in labels}
        others = {label: load_instance(there[label]) for label in labels if label in there}
        for (source, symbols), fitted in role_models(role, instances, train_seconds).items():
            for label, (model, cutoff) in fitted.items():
                common = {"role": role.name, "label": label, "source": source, "symbols": symbols,
                          "states": model["pdfa"].n_states, "cutoff": cutoff}
                inst = instances[label]
                values = scores(model, symbols, inst)
                later = np.isfinite(values)
                later[:int(train_seconds)] = False
                flagged = np.nan_to_num(values, nan=-np.inf) > cutoff
                rows += [dict(common, **row) for row in judge(flagged, later, inst["t0"], attacks)]
                if label in others:
                    values = scores(model, symbols, others[label])
                    scored = np.isfinite(values)
                    scored[:int(FORGET_SECONDS)] = False        # a cold clock
                    flagged = np.nan_to_num(values, nan=-np.inf) > cutoff
                    rows.append(dict(common, scenario="second benign", windows=int(scored.sum()),
                                     flagged=int(flagged[scored].sum()),
                                     alert_windows=int(persistent_mask(flagged).to_numpy()[scored].sum())))
    return rows, attacks


def totals(frame, attacks):
    """Per variant, pooled over roles and taps: the rows verdicts/roles.py reads."""
    kinds = len({a["scenario"] for a in attacks})
    out = []
    for (source, symbols), rows in frame.groupby(["source", "symbols"]):
        hit = rows[rows["scenario"].ne("benign") & rows["scenario"].ne("second benign") & rows["scored"].eq(True)]
        rounds = [(len(g), int(g["detected"].sum())) for _, g in hit.groupby(hit["attack"] // kinds)]
        benign, second = rows[rows["scenario"].eq("benign")], rows[rows["scenario"].eq("second benign")]
        out.append({"source": source, "symbols": symbols, "rounds": rounds,
                    "benign_windows": int(benign["windows"].sum()),
                    "benign_alert_windows": int(benign["alert_windows"].sum()),
                    "second_benign_windows": int(second["windows"].sum()),
                    "second_benign_alert_windows": int(second["alert_windows"].sum())})
    return out


def main():
    parser = argparse.ArgumentParser(description="Role machines against own machines on a labelled session.")
    parser.add_argument("session")
    parser.add_argument("--second", help="another session of the same taps, benign, never learned from")
    parser.add_argument("--train", type=float, default=600.0)
    parser.add_argument("--out", default=ROLES_CSV)
    args = parser.parse_args()
    rows, attacks = session_rows(args.session, args.train, args.second)
    frame = pd.DataFrame(rows)
    out = resolve_output(args.out)
    frame.to_csv(out, index=False)
    print(f"Wrote {out} | {len(frame)} rows, {len(attacks)} attacks, taps {sorted(frame['label'].unique())}")
    hit = frame[frame["scored"].eq(True)]
    print(hit.groupby(["source", "symbols", "scenario"])["detected"].agg(["sum", "count"]).unstack("scenario").to_string())
    verdict, reasons = roles_verdict.decide(totals(frame, attacks))
    print(f"\nRoles verdict: {verdict}")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
