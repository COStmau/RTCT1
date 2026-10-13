"""Show the state machine responding to an attack, in words and one chart.

Reads the real benign/attack pair, learns the PDFA from benign flows, then
scores both recordings trace by trace. Prints what it learned, what flagged,
and the exact moment the attack recording first looks nothing like normal.
Writes outputs/statemachine_demo.png: per-trace likelihood over time for the
unseen benign tail and the attack, with the cutoff line and flagged traces.

Run it with:
    cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
    .venv/bin/python statemachine_demo.py
"""
import matplotlib.pyplot as plt
import numpy as np

import local_paths
from collections import Counter
from data_io import resolve_output
from features import WINDOW_SIZE
from statemachine import (encode, fit_model, flags_for_windows,
                          load_flow_packets, make_flows, n_windows_for,
                          plot_pdfa, score_cutoff, score_flows, split_flows)

PNG_FILE = "statemachine_demo.png"


def heading(text):
    print("\n" + text)
    print("=" * len(text))


def main():
    heading("WHAT THIS PROGRAM DOES")
    print("1. Read two recordings: normal traffic and the web-flood attack.")
    print("2. Group packets into flows and learn the machine from normal flows only.")
    print("3. Score both recordings trace by trace: low likelihood means")
    print("   'nothing like normal'. Flag the traces below the line.")

    heading("STEP 1  Read the two recordings")
    benign = load_flow_packets(local_paths.BENIGN_CSV)
    attack = load_flow_packets(local_paths.ATTACK_CSV)
    benign_flows, attack_flows = make_flows(benign), make_flows(attack)
    print(f"   normal traffic: {len(benign):,} packets in {len(benign_flows)} flows")
    print(f"   attack traffic: {len(attack):,} packets in {len(attack_flows)} flows")

    heading("STEP 2  Learn the machine from normal flows")
    train, holdout = split_flows(benign_flows)
    model = fit_model(train)
    pdfa = model["pdfa"]
    alphabet = {s for _, out in pdfa.probs.values() for s in out}
    print(f"   learned from {len(train)} flows, kept {len(holdout)} flows aside")
    common, count = Counter(encode(train, model["enc"])).most_common(1)[0]
    print(f"   the machine has {pdfa.n_states} states and {len(alphabet)} symbols")
    print("   one symbol is one flow: protocol plus its size and duration bins;")
    print(f"   the most common normal flow is {common} ({count} of {len(train)} flows)")

    heading("STEP 3  Score both recordings, flag below the line")
    cutoff = score_cutoff(score_flows(model, holdout))
    benign_scored = score_flows(model, holdout)
    attack_scored = score_flows(model, attack_flows)
    benign_flags = flags_for_windows(benign_scored, benign["ts"].min(),
                                     n_windows_for(benign), cutoff)
    attack_flags = flags_for_windows(attack_scored, attack["ts"].min(),
                                     n_windows_for(attack), cutoff)
    print(f"   cutoff (worst 5% of unseen normal): {cutoff:.2f}")
    print(f"   unseen normal: {int(benign_flags.sum()):>3} of {len(benign_flags)} seconds flagged")
    print(f"   attack:        {int(attack_flags.sum()):>3} of {len(attack_flags)} seconds flagged")
    first = attack_flags[attack_flags].index
    if len(first):
        second = int(first[0])
        print(f"   the attack recording first looks nothing like normal at second {second}:")
        worst = min(attack_scored, key=lambda pair: pair[1])
        print(f"   its strangest trace scores {worst[1]:.1f}, against a cutoff of {cutoff:.2f}")
    else:
        print("   nothing flagged: these measurements do not separate this pair.")

    heading("STEP 4  Draw it")
    t0_benign, t0_attack = benign["ts"].min(), attack["ts"].min()
    fig, axes = plt.subplots(2, 1, figsize=(13, 8))
    for ax, scored, t0, title, flags in [
            (axes[0], benign_scored, t0_benign,
             f"unseen normal ({int(benign_flags.sum())}/{len(benign_flags)} seconds flagged)",
             benign_flags),
            (axes[1], attack_scored, t0_attack,
             f"attack ({int(attack_flags.sum())}/{len(attack_flags)} seconds flagged)",
             attack_flags)]:
        times = np.array([(t - t0) for t, _ in scored])
        scores = np.array([s for _, s in scored])
        shown = np.clip(scores, cutoff - 15, None)
        ax.plot(times, shown, color="#1f77b4", linewidth=1.2)
        bad = scores < cutoff
        ax.scatter(times[bad], shown[bad], color="#d62728", s=15, zorder=3,
                   label="flagged trace")
        ax.axhline(cutoff, color="gray", linestyle="--", linewidth=1,
                   label=f"cutoff = {cutoff:.2f}")
        ax.set_title(title, fontsize=10, fontweight="bold")
        ax.set_xlabel("seconds since capture start", fontsize=9, fontweight="bold")
        ax.set_ylabel("trace likelihood (mean log prob)", fontsize=9,
                      fontweight="bold")
        ax.legend(fontsize=8, prop={"weight": "bold"})
    for ax in fig.axes:
        for label in ax.get_xticklabels() + ax.get_yticklabels():
            label.set_fontweight("bold")
    fig.suptitle("State machine trace scores: low means nothing like normal"
                 " | 5-flow traces | symbols learned from benign only", fontsize=11)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    path = resolve_output(PNG_FILE)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\nWrote {path}")

    heading("STEP 5  Draw the machine itself")
    print("Each circle is a state, sized by how many traces passed through.")
    print("Each arrow is a learned transition, wider when more likely; only the")
    print("likely ones carry a symbol label. An attack trace that takes an arrow")
    print("that is not there scores the floor, which is what STEP 3 measured.")
    plot_pdfa(pdfa)


if __name__ == "__main__":
    main()
