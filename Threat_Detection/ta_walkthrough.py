"""A guided, plain-language run through the detector.

Read this file top to bottom and it explains itself. The comments are written for
someone who does not program, so you can walk through the code on screen and read
the notes out loud.

Five sentences to open with:

  1. "Each row of the sponsor's data files is one network packet, and each file is a
     recording from one place in the cluster."
  2. "I cut every recording into one-second slices and count things per slice, like
     how many packets went by and how many different destinations were contacted."
  3. "I learn what a normal second looks like from a recording of normal traffic, then
     ask how far each second of the other recordings is from that normal."
  4. "A second that is far enough away gets flagged, and I only raise an alert when
     several flagged seconds happen in a row, so one odd moment is not an alert."
  5. "All of this runs on the real captures. Nothing on the screen is simulated."

Run it with:
    cd /Users/cos/Documents/school/ECEN403/RTCT1/Threat_Detection
    .venv/bin/python ta_walkthrough.py
"""
import pandas as pd

import local_paths
import manifest
from test import (BENIGN_TRAIN_FRACTION, FEATURE_LABELS, PERSISTENCE_WINDOW, THRESHOLD,
                  WINDOW_SIZE, build_baseline, detect_anomalies, flag_persistent,
                  make_features, split_benign)


def heading(text):
    print("\n" + text)
    print("=" * len(text))


def describe(name, packets):
    span = packets["ts"].max() - packets["ts"].min()
    print(f"   {name}: {len(packets):,} packets covering {span:.1f} seconds")


def main():
    heading("WHAT THIS PROGRAM DOES")
    print("1. Read two recordings of traffic: one normal, one during an attack.")
    print("2. Cut each recording into 1-second slices and count things per slice.")
    print("3. Learn what a normal second looks like from the normal recording.")
    print("4. Measure how far each second of each recording is from that normal.")
    print("5. Flag the far-away seconds, and only alert if several come in a row.")

    # STEP 1 -----------------------------------------------------------------
    heading("STEP 1  Read the two recordings")
    print("One row in these files is one packet. The counts below are what is on disk.")
    benign_packets = manifest.load_capture(local_paths.BENIGN_CSV)
    attack_packets = manifest.load_capture(local_paths.ATTACK_CSV)
    describe("normal traffic ", benign_packets)
    describe("attack traffic ", attack_packets)

    # STEP 2 -----------------------------------------------------------------
    heading("STEP 2  Cut each recording into 1-second slices")
    print(f"Every slice is {WINDOW_SIZE:g} second long. Counting per second is what turns")
    print("'a lot of traffic' into something a computer can compare to normal.")
    benign_seconds = make_features(benign_packets)
    attack_seconds = make_features(attack_packets)
    print(f"   normal traffic: {len(benign_seconds)} slices")
    print(f"   attack traffic: {len(attack_seconds)} slices")

    # STEP 3 -----------------------------------------------------------------
    heading("STEP 3  Learn what a normal second looks like")
    print("From the normal recording only. We keep the last 30% of it out of sight")
    print("and use that part later as an honest check, so the detector is never")
    print("graded on the same seconds it learned from.")
    learned, unseen_normal = split_benign(benign_seconds)
    mean, spread = build_baseline(learned)
    print(f"   learned from {len(learned)} seconds, kept {len(unseen_normal)} seconds aside")
    print("\n   What each slice counts, and what 'normal' looked like:")
    for name in learned.columns:
        label, unit = FEATURE_LABELS[name]
        print(f"      {label:<26} normal is about {mean[name]:>8.2f} {unit}")

    # STEP 4 -----------------------------------------------------------------
    heading("STEP 4  Measure how far each second is from normal")
    print("For every second we look at the biggest difference from normal, measured in")
    print("'typical spreads'. A difference of 3 spreads or more is treated as far away.")
    normal_results = flag_persistent(detect_anomalies(unseen_normal, mean, spread))
    attack_results = flag_persistent(detect_anomalies(attack_seconds, mean, spread))

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
    print("This is the part that is new this week. One command repeats the whole")
    print("exercise above once per recording in the dataset: 4 scenarios, 11 capture")
    print("points, 2 capture methods.")
    try:
        sweep = pd.read_csv("sweep_results.csv")
    except FileNotFoundError:
        print("   sweep_results.csv is missing. Run: .venv/bin/python sweep.py")
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
        print(f"      {row['label']:<22} {row['scenario']:<17} {row['flagged_fraction']:.2f} flagged,"
              f" normal {row['normal_flag_rate']:.2f}")
    benign = sweep[(sweep["method"] == "tcp") & (sweep["scenario"] == "benign")]
    print(f"\n   But the same settings also flag {benign['flagged_fraction'].mean():.0%} of unseen")
    print("   NORMAL seconds on average, so the alarm level still needs calibrating per")
    print("   recording location before any detection rate is taken at face value.")
    print("\n   Nothing above is simulated, and every number can be regenerated with")
    print("   the four commands listed in PROGRESS.md.")


if __name__ == "__main__":
    main()
