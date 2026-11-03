"""Regenerate every sponsor packet CSV from its capture file and diff the two, row for row.

This is the evidence that pcap_rows produces the dataset's own rows, so a capture taken today
can be windowed and scored with no sponsor conversion in between.

Two tiers. Tier A is frame_number plus every column the pipeline reads (data_io.PACKET_COLUMNS):
those cells must be identical and the window tables equal. Tier B is the other 22 columns:
every difference is counted and named, but nothing downstream reads them.

Both files are streamed in lockstep, so memory stays flat even on the 19.7 GB captures.
Captures run smallest first; --max-gb, --only, --labels and --limit narrow a run.
"""
import argparse
import csv
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

from data_io import (MANIFEST_NAME, PACKET_COLUMNS, load_capture, load_manifest, resolve_output,
                     timebase_issues)
from features import make_windows
from pcap_rows import COLUMNS, capture_rows, format_cell

TIER_A = {"frame_number", *PACKET_COLUMNS}
MIN_FREE_BYTES = 20e9              # --regen-out stops before the disk drops below this


def locate_pcap(root, scenario, label, method):
    """The one capture file for a manifest row, in either the flat or the nested layout."""
    matches = sorted((Path(root) / scenario / "pcapng files").rglob(f"{label}-{method}.pcapng"))
    if len(matches) != 1:
        raise ValueError(f"{scenario}/{label}/{method}: {len(matches)} capture files")
    return matches[0]


def _window_verdict(regenerated, sponsor):
    """'equal', 'differ', 'both unusable', or the error that stopped the check."""
    try:
        ours, theirs = load_capture(str(regenerated)), load_capture(str(sponsor))
        usable = (timebase_issues(ours)["usable"], timebase_issues(theirs)["usable"])
        if usable == (False, False):
            return "both unusable"
        if False in usable:
            return "differ"
        pd.testing.assert_frame_equal(make_windows(ours), make_windows(theirs))
    except AssertionError:
        return "differ"
    except ValueError as error:
        return f"error: {error}"
    return "equal"


def compare_capture(pcap_path, csv_path, regen_path=None):
    """One result row: row counts, cell mismatches per column, and the window verdict.

    The regenerated CSV is written while it is compared, to regen_path or to a temp file
    that is removed afterwards, so the window check reads both sides through load_capture.
    """
    started = time.time()
    temp_dir = None
    if regen_path is None:
        temp_dir = tempfile.mkdtemp()
        regen_path = Path(temp_dir) / Path(csv_path).name
    warnings, counts, first = [], {}, ""
    rows_regen = rows_sponsor = 0
    try:
        with open(csv_path, newline="") as theirs_file, open(regen_path, "w", newline="") as ours_file:
            theirs, writer = csv.reader(theirs_file), csv.writer(ours_file)
            next(theirs, None)
            writer.writerow(COLUMNS)
            for row in capture_rows(pcap_path, warnings):
                cells = [format_cell(value) for value in row]
                writer.writerow(cells)
                rows_regen += 1
                sponsor = next(theirs, None)
                if sponsor is None:
                    continue
                rows_sponsor += 1
                for column, mine, other in zip(COLUMNS, cells, sponsor):
                    if mine != other:
                        counts[column] = counts.get(column, 0) + 1
                        first = first or f"frame {cells[0]} {column} {mine}|{other}"
            rows_sponsor += sum(1 for _ in theirs)
        windows = _window_verdict(regen_path, csv_path)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
    tier_a_clean = not any(column in TIER_A for column in counts)
    return {"rows_sponsor": rows_sponsor, "rows_regen": rows_regen,
            "tier_a_exact": tier_a_clean and rows_sponsor == rows_regen and not warnings,
            "mismatch_cells": sum(counts.values()),
            "differing_columns": ";".join(f"{c}:{n}" for c, n in counts.items()),
            "first_mismatch": first, "windows": windows, "warnings": "; ".join(warnings),
            "seconds": round(time.time() - started, 1)}


def summarize(results):
    """The one-line verdict, then the Tier-B column totals."""
    scored = results[results["note"].fillna("") == ""]
    exact = int(scored["tier_a_exact"].astype(bool).sum())
    equal = int((scored["windows"] == "equal").sum())
    totals = {}
    for entry in scored["differing_columns"].fillna(""):
        for part in filter(None, str(entry).split(";")):
            column, count = part.rsplit(":", 1)
            totals[column] = totals.get(column, 0) + int(count)
    columns = ", ".join(f"{c}:{n}" for c, n in sorted(totals.items())) or "none"
    notes = results["note"].fillna("")
    failed = int(notes.str.startswith("error").sum())
    skipped = len(results) - len(scored) - failed
    # A capture file cut off mid-record is never called exact, but when the sponsor's CSV was
    # made from the same cut file every row can still agree. Say so rather than hide it.
    cut_short = int((~scored["tier_a_exact"].astype(bool) & (scored["mismatch_cells"] == 0)
                     & (scored["rows_sponsor"] == scored["rows_regen"])
                     & scored["warnings"].fillna("").str.startswith("truncated")).sum())
    return (f"{exact} of {len(scored)} Tier-A exact"
            + (f"; {cut_short} more identical but cut short at the source" if cut_short else "")
            + f"; windows equal on {equal}"
            + (f"; {skipped} skipped" if skipped else "")
            + (f"; {failed} failed (see note)" if failed else "")
            + f"\nColumns that differ anywhere: {columns}")


def _check_free_space(directory, pcap_size):
    free = shutil.disk_usage(directory).free
    if free - pcap_size * 0.1 < MIN_FREE_BYTES:
        raise OSError(f"less than {MIN_FREE_BYTES / 1e9:.0f} GB would remain free in {directory}")


def run(manifest, root, only=None, labels=None, limit=None, max_gb=None, regen_out=None,
        out_file=None):
    """Compare every selected capture, smallest first.

    A capture that cannot be read is recorded with its error and the run moves on, and the
    results so far are rewritten to out_file after every capture: a full run takes hours,
    and one bad file must not cost the rest.
    """
    captures = manifest.copy()
    if only:
        captures = captures[captures["method"] == only]
    if labels:
        captures = captures[captures["label"].isin(labels)]
    captures["pcap"] = [locate_pcap(root, c["scenario"], c["label"], c["method"])
                        for _, c in captures.iterrows()]
    captures["pcap_gb"] = [round(p.stat().st_size / 1e9, 3) for p in captures["pcap"]]
    captures = captures.sort_values("pcap_gb").head(limit)
    rows = []
    for number, (_, capture) in enumerate(captures.iterrows(), start=1):
        row = {key: capture[key] for key in ("scenario", "label", "method", "pcap_gb")}
        row["pcap"], row["note"] = str(capture["pcap"]), ""
        if max_gb is not None and capture["pcap_gb"] > max_gb:
            row["note"] = "skipped: size"
        else:
            regen_path = None
            if regen_out:
                Path(regen_out).mkdir(parents=True, exist_ok=True)
                _check_free_space(regen_out, capture["pcap"].stat().st_size)
                regen_path = Path(regen_out) / f"{capture['scenario']}--{Path(capture['path']).name}"
            try:
                row.update(compare_capture(capture["pcap"], capture["path"], regen_path))
            except ValueError as error:
                row["note"] = f"error: {error}"
        rows.append(row)
        if out_file is not None:
            pd.DataFrame(rows).to_csv(out_file, index=False)
        print(f"[{number}/{len(captures)}] {row['scenario']} {row['label']} {row['method']}"
              f" rows={row.get('rows_regen', '-')} tierA={row.get('tier_a_exact', '-')}"
              f" windows={row.get('windows', '-')} {row.get('seconds', '-')}s {row['note']}",
              flush=True)
    return pd.DataFrame(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Regenerate sponsor CSVs from captures and diff them.")
    parser.add_argument("--only", choices=["tcp", "ptcp"])
    parser.add_argument("--labels", help="comma-separated capture labels, e.g. pod-nginx,node-child1")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-gb", type=float, help="skip captures larger than this")
    parser.add_argument("--regen-out", help="keep the regenerated CSVs in this folder")
    parser.add_argument("--out", default="pcap_diff.csv")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    parser.add_argument("--report", action="store_true", help="summarize the last run and exit")
    args = parser.parse_args(argv)

    out_file = resolve_output(args.out)
    if args.report:
        print(summarize(pd.read_csv(out_file)))
        return
    import local_paths                 # only a real run needs the dataset on this machine
    manifest = load_manifest(local_paths.KUBEDATA_ROOT, name=args.manifest)
    results = run(manifest, local_paths.KUBEDATA_ROOT, args.only,
                  args.labels.split(",") if args.labels else None, args.limit, args.max_gb,
                  args.regen_out, out_file)
    print(f"\nWrote {out_file}")
    print(summarize(results))


if __name__ == "__main__":
    main(sys.argv[1:])
