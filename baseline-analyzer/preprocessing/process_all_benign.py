#!/usr/bin/env python3
"""Batch-process benign TCP captures using the project's existing aggregator.

Run from the repository root:
    python preprocessing/process_all_benign.py --pattern "*-tcp.csv" --strip-capture-suffix

Input default:  data/raw/**/*.csv
Output default: data/processed/*-5s.csv
Manifest:       data/baseline/batch_manifest.csv
"""

import argparse
import csv
from pathlib import Path
import subprocess
import sys


def get_args():
    parser = argparse.ArgumentParser(description="Aggregate all benign TCP CSV captures into fixed windows")
    parser.add_argument("--input-dir", type=Path, default=Path("data/raw"), help="Directory of raw benign captures")
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed"), help="Directory for aggregated CSVs")
    parser.add_argument("--manifest", type=Path, default=Path("data/baseline/batch_manifest.csv"), help="Output CSV manifest for exporter")
    parser.add_argument("--aggregator", type=Path, default=Path("preprocessing/aggregate_benign_1s.py"), help="Existing per-file aggregation script")
    parser.add_argument("--pattern", default="*-tcp.csv", help="Filename glob; recursive under input-dir")
    parser.add_argument("--window", type=int, default=5, help="Aggregation window size in seconds")
    parser.add_argument("--strip-capture-suffix", action="store_true", help="Derive source name by stripping trailing -tcp (or -ptcp)")
    args = parser.parse_args()
    if args.window <= 0:
        parser.error("--window must be positive")
    return args


def main():
    args = get_args()
    root = Path.cwd()
    input_dir = (root / args.input_dir).resolve()
    output_dir = (root / args.output_dir).resolve()
    manifest = (root / args.manifest).resolve()
    aggregator = (root / args.aggregator).resolve()

    if not input_dir.is_dir():
        sys.exit(f"Input folder not found: {input_dir}")
    if not aggregator.is_file():
        sys.exit(f"Existing aggregation script not found: {aggregator}")

    captures = sorted(p for p in input_dir.rglob(args.pattern) if p.is_file())
    if not captures:
        sys.exit(f"No files matching {args.pattern!r} in {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    planned = []
    seen_sources = set()
    seen_outputs = set()

    for capture in captures:
        stem = capture.stem
        source = stem
        if args.strip_capture_suffix:
            for suffix in ("-tcp", "-ptcp"):
                if source.endswith(suffix):
                    source = source[:-len(suffix)]
                    break
        if not source:
            sys.exit(f"Empty source name derived from {capture.name}")
        output = output_dir / f"{stem}-{args.window}s.csv"
        if source in seen_sources:
            sys.exit(f"Duplicate source {source!r}. Rename captures or adjust pattern before running.")
        if output in seen_outputs:
            sys.exit(f"Output collision for {output.name}")
        seen_sources.add(source)
        seen_outputs.add(output)
        planned.append((capture, output, source))

    print(f"Found {len(planned)} benign capture(s). Processing {args.window}-second windows...")
    rows = []
    for ix, (capture, output, source) in enumerate(planned, start=1):
        print(f"[{ix}/{len(planned)}] {capture.name} -> {output.name} (source={source})", flush=True)
        cmd = [sys.executable, str(aggregator), str(capture), str(output), "--window", str(args.window)]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            sys.exit(f"Aggregation failed for {capture.name} (exit={exc.returncode}); manifest was not updated")
        if not output.is_file() or output.stat().st_size == 0:
            sys.exit(f"Aggregator did not create a nonempty CSV: {output}")
        try:
            rel_output = output.relative_to(root).as_posix()
        except ValueError:
            rel_output = str(output)
        rows.append({"source": source, "path": rel_output, "window_seconds": args.window})

    tmp_manifest = manifest.with_name(manifest.name + ".tmp")
    with tmp_manifest.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["source", "path", "window_seconds"])
        writer.writeheader()
        writer.writerows(rows)
    tmp_manifest.replace(manifest)
    print(f"\nSuccess: {len(rows)} captures processed; manifest written to {manifest}")


if __name__ == "__main__":
    main()
