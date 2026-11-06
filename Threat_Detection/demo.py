"""The one script that shows what this subsystem does.

    .venv/bin/python demo.py        # menu: pick what to see
    .venv/bin/python demo.py 3      # run item 3 and stop
    .venv/bin/python demo.py all    # everything, in dependency order

Every item presents results that the four layers already compute, so nothing here
re-implements detection. The three shows that used to be separate files (detector.py,
walkthrough.py, statemachine_demo.py) are items 1-3. The experiments (sweep, compare,
feature_value) stay in their own scripts, and this menu runs them as documented.
"""
import subprocess
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

# reporting pins matplotlib to Agg before it imports pyplot, so importing it first gives
# this module the same headless backend instead of opening a window.
from core.reporting import plot_detection, summarize_flags, to_events, write_events, write_report
import matplotlib.pyplot as plt

from core.evaluation import BULK_LABELS

from core.data_io import load_capture, resolve_output
from core.detectors import PERSISTENCE_WINDOW, THRESHOLD, build
from core.features import FEATURE_LABELS, WINDOW_SIZE, make_windows, split_reference
from statemachine import (encode, fit_model, flags_for_windows, load_flow_packets,
                          make_flows, n_windows_for, plot_pdfa, score_cutoff,
                          score_flows, segment_flows, split_flows, write_pair)

HERE = Path(__file__).resolve().parent
DETECTOR = "z_score"


def heading(text):
    print("\n" + text)
    print("=" * len(text))


# --- 1. Pair demo ----------------------------------------------------------------

def resolve_reference(benign_windows):
    """Pick the reference windows and the held-out windows from one benign capture.

    Two options. With a second benign capture set as BENIGN_EVAL_CSV, the whole
    first capture fits the reference and the separate capture is the evaluation -- no
    window ever does both jobs. Without one, the capture is split by time and the later
    windows are held out. Either way the reference never sees evaluation traffic.
    """
    import local_paths

    evaluation_path = getattr(local_paths, "BENIGN_EVAL_CSV", "")
    if evaluation_path:
        if Path(evaluation_path).resolve() == Path(local_paths.BENIGN_CSV).resolve():
            raise ValueError("BENIGN_EVAL_CSV must differ from the baseline capture.")
        reference = benign_windows
        held_out = make_windows(load_capture(evaluation_path))
        note = "Benign evaluation uses a separate capture, excluded from fitting."
    else:
        reference, held_out = split_reference(benign_windows)
        note = (f"First {len(reference)} windows fit the reference; "
                f"the next {len(held_out)} are held out.")
    return reference, held_out, note


def _label_of(path):
    """The capture label a packet CSV belongs to, e.g. pod-nginx from pod-nginx-tcp.csv."""
    from core.data_io import parse_capture
    from pathlib import Path
    return parse_capture(Path(path).name)[0]


def pair_demo():
    """Two captures in, one report and one chart out."""
    import local_paths

    if not local_paths.BENIGN_CSV or not local_paths.ATTACK_CSV:
        raise ValueError("Set BENIGN_CSV and ATTACK_CSV in local_paths.py.")

    reference, held_out, note = resolve_reference(
        make_windows(load_capture(local_paths.BENIGN_CSV)))
    detector = build(DETECTOR).pipeline(reference, held_out)

    benign_results = detector.annotate(held_out)
    results = detector.annotate(make_windows(load_capture(local_paths.ATTACK_CSV)))

    results.to_csv(resolve_output("results.csv"))
    benign_results.to_csv(resolve_output("benign_results.csv"))

    # The detection -> response handoff (EVENT_LOG.md). Only flagged attack windows are
    # emitted, each carrying its second inside the capture so the response side can order
    # and expire them.
    events = to_events(results, detector=DETECTOR, pods=[_label_of(local_paths.ATTACK_CSV)])
    write_events(events)

    summarize_flags(results, benign_results, len(reference), note)
    print(f"   {len(events)} events written to outputs/events.jsonl ({events[0]['version'] if events else 'no flags'})")
    plot_detection(results, benign_results, detector.mean, detector.std, len(reference))


# --- 2. Walkthrough --------------------------------------------------------------

def walkthrough():
    """The pair demo again, narrated for someone who does not program.

    Ends by writing outputs/SHOWCASE.md: every measured result as one handover file.
    """
    import local_paths

    heading("WHAT THIS PROGRAM DOES")
    print("1. Read two recordings of traffic: one normal, one during an attack.")
    print("2. Cut each recording into 1-second slices and count things per slice.")
    print("3. Learn what a normal second looks like from the normal recording.")
    print("4. Measure how far each second of each recording is from that normal.")
    print("5. Flag the far-away seconds, and only alert if several come in a row.")

    # STEP 1 -----------------------------------------------------------------
    heading("STEP 1  Read the two recordings")
    print("One row in these files is one packet. The counts below are what is on disk.")
    benign_packets = load_capture(local_paths.BENIGN_CSV)
    attack_packets = load_capture(local_paths.ATTACK_CSV)
    for name, packets in (("normal traffic ", benign_packets),
                          ("attack traffic ", attack_packets)):
        span = packets["ts"].max() - packets["ts"].min()
        print(f"   {name}: {len(packets):,} packets covering {span:.1f} seconds")

    # STEP 2 -----------------------------------------------------------------
    heading("STEP 2  Cut each recording into 1-second slices")
    print(f"Every slice is {WINDOW_SIZE:g} second long. Counting per second is what turns")
    print("'a lot of traffic' into something a computer can compare to normal.")
    benign_seconds = make_windows(benign_packets)
    attack_seconds = make_windows(attack_packets)
    print(f"   normal traffic: {len(benign_seconds)} slices")
    print(f"   attack traffic: {len(attack_seconds)} slices")

    # STEP 3 -----------------------------------------------------------------
    heading("STEP 3  Learn what a normal second looks like")
    print("From the normal recording only. We keep the last 30% of it out of sight")
    print("and use that part later as an honest check, so the detector is never")
    print("graded on the same seconds it learned from.")
    learned, unseen_normal = split_reference(benign_seconds)
    # calibrate() sets the z-score cutoff, which is the fixed design threshold; for
    # z_score it fits nothing on unseen_normal, so this is not grading on its own data.
    detector = build(DETECTOR).pipeline(learned, unseen_normal)
    mean, spread = detector.mean, detector.std
    print(f"   learned from {len(learned)} seconds, kept {len(unseen_normal)} seconds aside")
    print("\n   What each slice counts, and what 'normal' looked like:")
    for name in learned.columns:
        label, unit = FEATURE_LABELS[name]
        print(f"      {label:<26} normal is about {mean[name]:>8.2f} {unit}")

    # STEP 4 -----------------------------------------------------------------
    heading("STEP 4  Measure how far each second is from normal")
    print("For every second we look at the biggest difference from normal, measured in")
    print(f"'typical spreads'. A difference of {THRESHOLD:g} spreads or more is treated as")
    print("far away.")
    normal_results = detector.annotate(unseen_normal)
    attack_results = detector.annotate(attack_seconds)

    # STEP 5 -----------------------------------------------------------------
    heading("STEP 5  Flag the far-away seconds, and require several in a row")
    print(f"   normal traffic we had never seen:  {int(normal_results['anomaly'].sum()):>3}"
          f" of {len(normal_results)} seconds flagged")
    print(f"   attack traffic:                   {int(attack_results['anomaly'].sum()):>3}"
          f" of {len(attack_results)} seconds flagged")
    print(f"\n   Requiring {PERSISTENCE_WINDOW} seconds in a row before an alert:")
    print(f"   normal traffic: {int(normal_results['persistent_flag'].sum())} alerts"
          f"   |   attack traffic: {int(attack_results['persistent_flag'].sum())} alerts")

    # STEP 6 -----------------------------------------------------------------
    heading("STEP 6  Show the strongest piece of evidence")
    flagged = attack_results.loc[attack_results["anomaly"].fillna(False)]
    if flagged.empty:
        print("   Nothing stood out in this recording. That is a result, not a failure:")
        print("   it means these measurements do not separate this recording from normal.")
    else:
        strongest = flagged["anomaly_score"].idxmax()
        row = flagged.loc[strongest]
        label, unit = FEATURE_LABELS[row["top_feature"]]
        print(f"   The clearest second is second {strongest} of the attack recording.")
        print(f"   What stood out: {label}. That second saw {row['observed_value']:,.2f} {unit}")
        print(f"   where normal traffic sits near {row['expected_mean']:,.2f} {unit}.")
        print(f"   That is {abs(row['feature_z_score']):.0f} typical spreads away from normal.")
        print("\n   How often each measurement was the one that stood out:")
        for feature, count in flagged["top_feature"].value_counts().items():
            print(f"      {FEATURE_LABELS[feature][0]:<26} in {count} flagged seconds")

    # STEP 7 -----------------------------------------------------------------
    heading("STEP 7  The same measurement across all 88 recordings")
    print("One command repeats the whole exercise above once per recording in the")
    print("dataset: 4 scenarios, 11 capture points, 2 capture methods.")
    try:
        sweep = pd.read_csv(resolve_output("sweep_results.csv"))
    except FileNotFoundError:
        print("   outputs/sweep_results.csv is missing. Run item 4 (sweep) first.")
        return
    attacks = sweep[(sweep["method"] == "tcp") & (sweep["scenario"] != "benign")
                    & (sweep["windows"] > 10)].copy()
    reference = (sweep[(sweep["method"] == "tcp") & (sweep["scenario"] == "benign")]
                 [["label", "flagged_fraction"]]
                 .rename(columns={"flagged_fraction": "normal_flag_rate"}))
    attacks = attacks.merge(reference, on="label", how="left")
    attacks["above_normal"] = attacks["flagged_fraction"] - attacks["normal_flag_rate"]
    attacks = attacks.sort_values("above_normal", ascending=False)
    print("\n   Where an attack stands out beyond that place's own normal noise.")
    print("   Second number is how often the same recording point flags on normal")
    print("   traffic with these settings, so a big first number alone proves nothing:")
    for _, row in attacks.head(6).iterrows():
        print(f"      {row['label']:<22} {row['scenario']:<17} {row['flagged_fraction']:.2f}"
              f" flagged, normal {row['normal_flag_rate']:.2f}")
    benign = sweep[(sweep["method"] == "tcp") & (sweep["scenario"] == "benign")]
    # The split is measured, not assumed: these three captures carry a bulk-transfer regime
    # change, so flagging there is the detector noticing a step in normal traffic.
    drifting = benign[benign["label"].isin(BULK_LABELS)]
    steady = benign[~benign["label"].isin(BULK_LABELS)]
    print(f"\n   Split by regime: {steady['flagged_fraction'].mean():.2f} on the "
          f"{len(steady)} steady captures, {drifting['flagged_fraction'].mean():.2f} on the "
          f"{len(drifting)} that change regime mid-recording.")
    print("   Those are a real step change in normal traffic, not a miscalibration, and")
    print("   flagging them is the detector working. A per-vantage cutoff would hide it.")
    print("\n   Nothing above is simulated, and every number can be regenerated by the")
    print("   items in this menu or the commands in README.md.")

    # STEP 8 -----------------------------------------------------------------
    heading("STEP 8  Write the showcase report")
    # Keyed by output filename, so a missing file names itself in the message.
    frames = {}
    for filename, key in (("sweep_results.csv", "sweep"),
                          ("ablation_results.csv", "ablation"),
                          ("capture_manifest.csv", "capture_manifest"),
                          ("detector_comparison.csv", "detector_comparison")):
        try:
            frames[key] = pd.read_csv(resolve_output(filename))
        except FileNotFoundError:
            print(f"   {filename} is missing. Run item 8 (everything), or the sweep,")
            print("   ablation and compare items in that order.")
            return
    written = write_report(sweep=frames["sweep"], ablation=frames["ablation"],
                           manifest=frames["capture_manifest"],
                           comparison=frames["detector_comparison"])
    print(f"   wrote {written}")
    print("   Same numbers, same charts, one file to hand over. The correction comes")
    print("   first in it, then the measurements behind it.")


# --- 3. State machine ------------------------------------------------------------

def state_machine():
    """PDFA anomaly detection on the same pair: what it learned, what flagged, two charts."""
    import local_paths

    heading("WHAT THIS PROGRAM DOES")
    print("1. Read two recordings: normal traffic and the web-flood attack.")
    print("2. Group packets into flows and learn the machine from normal flows only.")
    print("3. Score both recordings trace by trace: low likelihood means")
    print("   'nothing like normal'. Flag the traces below the line.")

    heading("STEP 1  Read the two recordings")
    benign = load_flow_packets(local_paths.BENIGN_CSV)
    attack = load_flow_packets(local_paths.ATTACK_CSV)
    benign_flows, benign_dropped = segment_flows(make_flows(benign), benign["ts"].min())
    attack_flows, attack_dropped = segment_flows(make_flows(attack), attack["ts"].min())
    print(f"   normal traffic: {len(benign):,} packets in {len(benign_flows)} flows"
          f" ({benign_dropped} crossing a window boundary, dropped)")
    print(f"   attack traffic: {len(attack):,} packets in {len(attack_flows)} flows"
          f" ({attack_dropped} crossing a window boundary, dropped)")

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
    holdout_scores = score_flows(model, holdout)
    cutoff = score_cutoff(holdout_scores)
    attack_scored = score_flows(model, attack_flows)
    benign_flags = flags_for_windows(holdout_scores, benign["ts"].min(),
                                     n_windows_for(benign), cutoff)
    attack_flags = flags_for_windows(attack_scored, attack["ts"].min(),
                                     n_windows_for(attack), cutoff)
    print(f"   cutoff (worst 5% of unseen normal): {cutoff:.2f}")
    print(f"   unseen normal: {int(benign_flags.sum()):>3} of {len(benign_flags)} seconds flagged")
    print(f"   attack:        {int(attack_flags.sum()):>3} of {len(attack_flags)} seconds flagged")
    pair_csv = write_pair(benign_flags, attack_flags)
    print(f"   wrote {pair_csv}")
    flagged_seconds = attack_flags[attack_flags].index
    if len(flagged_seconds):
        print(f"   the attack recording first looks nothing like normal at second "
              f"{int(flagged_seconds[0])}:")
        worst = min(attack_scored, key=lambda pair: pair[1])
        print(f"   its strangest trace scores {worst[1]:.1f}, against a cutoff of {cutoff:.2f}")
    else:
        print("   nothing flagged: these measurements do not separate this pair.")

    heading("STEP 4  Draw it")
    t0_benign, t0_attack = benign["ts"].min(), attack["ts"].min()
    fig, axes = plt.subplots(2, 1, figsize=(13, 8))
    for ax, scored, t0, title, flags in [
            (axes[0], holdout_scores, t0_benign,
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
    path = resolve_output("statemachine_demo.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\nWrote {path}")

    heading("STEP 5  Draw the machine itself")
    print("Each circle is a state, sized by how many traces passed through.")
    print("Each arrow is a learned transition, wider when more likely; only the")
    print("likely ones carry a symbol label. An attack trace that takes an arrow")
    print("that is not there scores the floor, which is what STEP 3 measured.")
    plot_pdfa(pdfa)


# --- 4-7. The experiments, run exactly as their own scripts document -------------

def _run(*args):
    """Run a command with the interpreter that started this menu, from this folder."""
    # Flush first: our own prints are buffered when output is piped, and the child writes
    # straight to the file descriptor, so without this the transcript interleaves wrongly.
    sys.stdout.flush()
    sys.stderr.flush()
    subprocess.run([sys.executable, *args], cwd=HERE, check=True)


def sweep_captures():
    _run("experiments/sweep.py")


def ablation():
    _run("experiments/sweep.py", "--groups", "volume,size_timing,diversity,flags,protocol",
         "--out", "ablation_results.csv")


def comparison():
    _run("experiments/compare.py")


def feature_value():
    _run("experiments/feature_value.py")


def run_tests():
    _run("-m", "unittest", "tests")


# --- 10. The story page -----------------------------------------------------------

def story_page():
    """The state machine learned and replayed, as one self-contained interactive page."""
    from story import page as story
    story.main([])


# --- 11. The pcap diff ------------------------------------------------------------

def pcap_diff():
    """The last pcap_diff.py run, summarized. The run itself reads every capture file, so
    it is started by hand: .venv/bin/python pcap_diff.py"""
    _run("convert/diff.py", "--report")


# --- 8. Everything ---------------------------------------------------------------

def everything():
    """Regenerate every artifact, in dependency order: the report needs all of them."""
    for step in (pair_demo, sweep_captures, ablation, comparison, feature_value,
                 walkthrough):
        step()


# --- The menu --------------------------------------------------------------------

# (name, function, what it shows) in the order a reviewer would walk through them.
ITEMS = [
    ("Pair demo", pair_demo, "one normal and one attack recording: report and chart"),
    ("Walkthrough", walkthrough, "the same pair narrated plainly, then SHOWCASE.md"),
    ("State machine", state_machine, "trace scores from a learned automaton, two charts"),
    ("Sweep", sweep_captures, "every capture against its own matched benign reference"),
    ("Ablation", ablation, "the sweep repeated once per feature group"),
    ("Compare", comparison, "z-score against isolation forest and one-class SVM"),
    ("Feature value", feature_value, "what each measurement is worth on its own"),
    ("Everything", everything, "all of the above, in the order the report needs it"),
    ("Tests", run_tests, "the unit suite"),
    ("Story", story_page, "the state machine learned and replayed, as an interactive page"),
    ("Pcap diff", pcap_diff, "regenerated packet rows against the sponsor CSVs"),
]


def _attempt(label, function):
    """Run one item; report a failure plainly instead of ending the session."""
    print(f"\n===== {label} =====")
    try:
        function()
    except (ValueError, OSError, ImportError, subprocess.CalledProcessError) as error:
        print(f"\nstopped: {error}")
        return False
    return True


def run(number):
    name, function, _ = ITEMS[number - 1]
    return _attempt(f"{number}. {name}", function)


def menu():
    while True:
        print("\nWhat do you want to see?")
        for number, (name, _, blurb) in enumerate(ITEMS, start=1):
            print(f"  {number}  {name:<14} {blurb}")
        print("  0  Quit")
        try:
            choice = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("", "0", "q", "quit"):
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(ITEMS):
            print(f"Pick 1-{len(ITEMS)}, or 0 to quit.")
            continue
        run(int(choice))


def main(argv):
    if not argv:
        menu()
        return
    failed = False
    for arg in argv:
        if arg == "all":
            failed = not _attempt("everything", everything) or failed
        elif arg.isdigit() and 1 <= int(arg) <= len(ITEMS):
            failed = not run(int(arg)) or failed
        else:
            raise SystemExit(f"Pick 1-{len(ITEMS)} or all, not {arg!r}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
