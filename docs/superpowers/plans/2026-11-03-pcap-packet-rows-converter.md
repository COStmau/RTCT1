# Pcap → Packet-Rows Converter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn any capture file in the KUBEDATA corpus into the 34-column packet CSV that `data_io.load_capture` reads, and prove it by regenerating all 88 sponsor CSVs and diffing them row for row.

**Architecture:** Two stdlib-only modules. `pcap_read.py` handles the containers (pcap, pcapng) and yields raw frames. `pcap_rows.py` dissects each frame into one row and writes the CSV in the sponsor's format. One experiment script, `pcap_diff.py`, streams each regenerated capture against its sponsor CSV and writes `outputs/pcap_diff.csv`. The converter feeds `data_io`; it does not replace it.

**Tech Stack:** Python 3.11, stdlib (`struct`, `csv`, `ipaddress`), pandas only in `pcap_diff.py` and the window check. No new dependencies.

**Spec:** this document. The "Measured facts" section below is the spec. It replaces the original pasted plan, whose grounding section was wrong in places. Every fact below was read from the Drive on 2026-11-03.

## Measured facts (the spec)

**Containers**
- **88 captures**, 44 `tcp` and 44 `ptcp`. All are named `*.pcapng`, but the extension doesn't say which container a file actually is.
- **Layout.** `benign/` and `injection attack/` are flat: `<scenario>/pcapng files/<label>-<method>.pcapng`. `nginx attack/` and `lidar attack/` are nested: `<scenario>/pcapng files/{tcp,ptcp}/<level> level/<label>-<method>.pcapng`.
- **tcp files are classic pcap.** Magic `d4 c3 b2 a1` (little-endian, microsecond timestamps), version 2.4, snaplen **262144**, linktype **276 (LINUX_SLL2)**. The SLL2 header is 20 bytes; its first 2 bytes are the protocol type (for example `86dd`).
- **ptcp files are pcapng from ptcpdump v0.37.0.** The SHB is at offset 0 and is 128 bytes long. An IDB follows at `0x80`: linktype **1 (Ethernet)**, snaplen 65535, name `dummy-0`, and **`if_tsresol` = 9 (nanoseconds)**.
- **Truncation.** The three largest files have sizes that are exact multiples of 4096, which suggests cut-off copies. Their last record may be incomplete.

**Sponsor CSV format**
- **Header.** 34 columns in the order of `COLUMNS` (Task 2).
- **Line endings.** **CRLF** (the default of `csv.writer`).
- **Blank cells.** An empty field means "no value".
- **Numbers.** Python `str()`/`repr()` form, so `0`, `17`, `1771545910.9068313`, `8.58306884765625e-06`.

**Column rules, read from the CSVs**
- **`ts`** is float64 seconds. Every `iat` is an exact multiple of 2⁻²², so `iat` is float64 `ts[i] − ts[i−1]`. The first row's `iat` is the int `0`. `iat` is negative when a frame's timestamp is earlier than the one before it.
- **`frame_len`** is the original wire length (orig_len). It includes the link header: 14 bytes for Ethernet, 20 for SLL2.
- **`eth_*` columns.**
  - tcp/SLL2: all three blank.
  - ptcp/Ethernet: lowercase MACs, and `eth_type` as `0x%04x`.
  - Loopback frames: `00:00:00:00:00:00`, taken from the header itself.
  - `0x8899` is real RRCP traffic.
  - `0xc0a8` is a raw IPv4 packet stored under the Ethernet IDB. The sponsor parsed it as Ethernet, so its IP columns are **blank**. The converter copies this behaviour.
- **`proto`.** `tcp`/`udp`/`icmp` for protocol 6/17/1. Otherwise the number as a string: `58` for ICMPv6, `2` for IGMP.
- **`is_dns`, `is_http`, `is_https`.** `1` when **either** port is 53, 8080 or 443 respectively, else `0`. This holds regardless of transport.
- **ICMP rows.**
  - `icmp_type` and `icmp_code` are **blank when the value is 0**. Example: echo request prints type `8` and a blank code; echo reply prints both blank.
  - ICMP *error* messages (here ICMPv6 type 1 code 4) take `src_port`, `dst_port`, `udp_length` and `is_*` **from the quoted inner header**. `tcp_payload_len` stays blank on those rows.
- **`tcp_payload_len`.** IP payload length minus the TCP header length, read from the headers rather than the captured bytes. Example: 65226-byte frame → 65160. Printed as `0` on TCP rows with no payload, blank on non-TCP rows.
- **`udp_length`.** The UDP header's length field, which includes the 8-byte header. Blank on non-UDP rows.
- **TCP flags.** `0`/`1` on every row, including non-TCP rows (where they are `0`).
- **ARP.** IP columns blank; ARP columns filled; `eth_*` filled.
- **Row counts** match frame counts. No frames are dropped or reordered.

## Global Constraints

- **No new pip dependency.** `requirements.txt` stays unchanged.
- **Read-only.** Nothing under `~/Library/CloudStorage` is written, moved or deleted. The corpus stays downloaded as it is now. Freeing it later is a manual Finder step: set the folders to **Online only**, never delete them.
- **Imports.** `pcap_read.py` and `pcap_rows.py` must import without `local_paths`, the same rule `data_io` follows.
- **`data_io` is untouched.** The converter's output must pass `load_capture` unchanged.
- **Interpreter.** Run commands from `Threat_Detection/` in the worktree with `PY=../../../../Threat_Detection/.venv/bin/python`.
- **Speed.** The default unit suite stays fast. Tests that use the corpus skip cleanly when `local_paths.KUBEDATA_ROOT` is unset or missing.
- **Pass criterion, Tier A (gates the work).** `frame_number` and every `data_io.PACKET_COLUMNS` cell must be string-identical, and the `make_windows` table must be equal.
- **Pass criterion, Tier B (reported, not gating).** The other 22 columns: every mismatch is counted per column and named in the report.
- **Outside the code.** Ask the sponsor for the script that generated their CSVs. If it arrives, it decides any rule the diff leaves open.

## Review Focus

1. **Truncated last record** (the page-aligned large files). The reader yields every complete frame, records a warning, and the diff never marks that capture exact. → Task 1 test `test_truncated_tail_warns_and_keeps_complete_frames`.
2. **Raw IP under an Ethernet IDB.** `eth_type 0xc0a8`, IP columns blank, no exception. → Task 2 test `test_raw_ip_under_ethernet_blanks_ip_columns`.
3. **Second IDB mid-file.** An EPB for interface 1 uses that IDB's `if_tsresol` and linktype. → Task 1 test `test_second_idb_mid_file_sets_resolution`.
4. **Frame clipped by snaplen.** `frame_len` is orig_len, and `tcp_payload_len` comes from the IP header. → Task 2 test `test_clipped_frame_uses_header_lengths`.
5. **Unsupported linktype or block.** A `ValueError` naming the file and the reason, never a CSV with silent blanks. → Task 1 test `test_unsupported_linktype_raises_with_path`.

---

## File Structure

| File | Responsibility |
|---|---|
| `Threat_Detection/pcap_read.py` (create) | Container formats only: magic detection, pcap and pcapng walking, `Frame` records, warnings |
| `Threat_Detection/pcap_rows.py` (create) | Frame → 34-column row (Ethernet, SLL2, IPv4, IPv6, ARP, TCP, UDP, ICMP), timestamp arithmetic, CSV writer |
| `Threat_Detection/pcap_diff.py` (create) | Manifest → find each pcap → stream-compare against the sponsor CSV → window check → `outputs/pcap_diff.csv` |
| `Threat_Detection/tests.py` (modify) | Classes `PcapReadChecks`, `PcapRowChecks`, `PcapDiffChecks`, `PcapCorpusChecks` |
| `Threat_Detection/demo.py` (modify) | Menu item "Pcap diff" |
| `Threat_Detection/README.md`, `PROGRESS.md` (modify) | Documentation and the measured result |

---

### Task 0: Worktree setup

- [ ] **Step 1:** Copy `../../../../Threat_Detection/local_paths.py` into the worktree's `Threat_Detection/`. It's gitignored, which you can confirm with `git check-ignore local_paths.py`.
- [ ] **Step 2:** Run `$PY -m unittest tests`. Expected: OK. This is the baseline before any change.

### Task 1: Container reader (`pcap_read.py`)

**Files:** Create `Threat_Detection/pcap_read.py`; Test: `tests.py` class `PcapReadChecks`

**Interfaces:**
- Produces:
  - `Frame = namedtuple("Frame", "number ts_sec ts_frac ts_digits orig_len data linktype")`
    - `number` is 1-based.
    - `data` is the captured bytes, cut to at most `HEAD_BYTES = 256`.
    - `ts_digits` is 6 or 9.
  - `detect_format(path) -> str`: returns `"pcap"` or `"pcapng"`. Raises `ValueError(f"{path}: unknown capture magic {hex}")`.
  - `class CaptureReader(path)`: `.frames()` generator of `Frame`, `.warnings: list[str]`, `.format`.
  - `LINKTYPES = {1: "ethernet", 276: "sll2"}`

**Behaviour to implement**
- **pcap.**
  - Byte order comes from the magic. `a1b2c3d4` means microseconds (6 digits); `a1b23c4d` means nanoseconds (9 digits).
  - Each record has a 16-byte header: `sec`, `frac`, `incl_len`, `orig_len`.
- **pcapng.**
  - The SHB byte-order magic is `0x1A2B3C4D`. Each SHB starts a new interface list.
  - IDB options: `if_tsresol` (code 9) defaults to 6. A tsresol with the high bit set (base-2 resolution) raises. `if_tsoffset` (code 14) raises if present.
  - EPB (type 6): the 64-bit timestamp is `(hi << 32) | lo`, then `sec, frac = divmod(ts, 10**digits)`.
  - Skip: ISB (5), NRB (4), DSB (10), custom blocks.
  - Raise on: SPB (3) and the obsolete PB (2).
- **Reading.** Read at most `HEAD_BYTES` of each frame, then `seek` past the rest of the record.
- **Truncation.** If the file ends mid-record, append `f"truncated after frame {n}"` to `.warnings` and stop.
- **Unsupported link.** A linktype not in `LINKTYPES` raises `ValueError(f"{path}: unsupported linktype {lt}")`.

**Steps**
- [ ] **Step 1: Write the test helpers and failing tests.** The helpers, `_pcap_bytes(frames, linktype=276, nano=False, big_endian=False)` and `_pcapng_bytes(interfaces, packets)`, build files in a temp dir. Tests:
  - `test_detect_format_by_magic_not_extension`: a pcap file named `.pcapng` returns `"pcap"`; garbage raises `ValueError` matching `unknown capture magic`.
  - `test_pcap_little_endian_micro`: `(sec=1771545908, frac=877129, orig_len=77, len(data)=77, linktype=276, ts_digits=6)`.
  - `test_pcap_nano_and_big_endian` round-trip the same frame.
  - `test_pcapng_nanosecond_resolution`: IDB tsresol 9, EPB timestamp 1771545910906831300 → `ts_sec == 1771545910`, `ts_frac == 906831300`, `ts_digits == 9`.
  - `test_second_idb_mid_file_sets_resolution`: IDB0 has tsresol 6, IDB1 (added after a packet) has tsresol 9. The EPB on interface 1 gives `ts_digits == 9` and `linktype == 1`.
  - `test_long_frame_is_cut_to_head_bytes`: orig 65549, incl 65535 → `len(data) == 256`, `orig_len == 65549`, and the next frame still parses.
  - `test_truncated_tail_warns_and_keeps_complete_frames`: cut the last record in half. 2 of 3 frames are yielded, and `warnings == ["truncated after frame 2"]`.
  - `test_unsupported_linktype_raises_with_path`: linktype 101 raises `ValueError` whose message contains the path and `101`.
  - `test_reader_imports_without_local_paths`: the subprocess pattern from `DataIoChecks`.
- [ ] **Step 2:** Run `$PY -m unittest tests.PcapReadChecks -v`. Expected: FAIL / ImportError.
- [ ] **Step 3:** Implement `pcap_read.py` to the interface above.
- [ ] **Step 4:** Run `$PY -m unittest tests.PcapReadChecks -v`. Expected: all pass.
- [ ] **Step 5:** Commit with the message `feat: pcap/pcapng reader for the capture corpus`.

### Task 2: Row dissection and CSV writer (`pcap_rows.py`)

**Files:** Create `Threat_Detection/pcap_rows.py`; Test: `tests.py` class `PcapRowChecks`

**Interfaces:**
- Consumes: `pcap_read.CaptureReader`, `Frame`.
- Produces:
  - `COLUMNS`: the 34 names, in this order: `frame_number, ts, iat, frame_len, eth_src, eth_dst, eth_type, ip_version, src_ip, dst_ip, proto, ttl_or_hlim, src_port, dst_port, arp_opcode, arp_sender_ip, arp_target_ip, arp_sender_mac, arp_target_mac, is_dns, is_http, is_https, icmp_type, icmp_code, tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, tcp_ece, tcp_cwr, tcp_payload_len, udp_length`
  - `ts_seconds(sec, frac, digits, rule=TS_RULE) -> float`. `TS_RULE` is one of:
    - `"add"`: `sec + frac / 10**digits`
    - `"div"`: `(sec * 10**digits + frac) / 10**digits`

    Start with `"div"`. Task 3 fixes the final choice by measurement.
  - `frame_row(frame) -> dict`: every key in `COLUMNS` except `frame_number`, `ts` and `iat`. `None` means a blank cell.
  - `capture_rows(path) -> Iterator[list]`: one list per frame in `COLUMNS` order, with `frame_number`, `ts` and `iat` filled in. The first `iat` is the int `0`.
  - `format_cell(value) -> str`: `None → ""`, otherwise `str(value)`.
  - `write_capture_rows(pcap_path, csv_path) -> dict`: writes the header plus rows with `csv.writer` (CRLF) and returns `{"rows": int, "warnings": list[str]}`.

**Behaviour to implement**
- Implement every rule under "Column rules" in the spec.
- **Dispatch.** Ethernet uses the ethertype at byte 12; SLL2 uses the protocol type at byte 0. Both dispatch on `0x0800`, `0x86dd` and `0x0806`. Any other ethertype leaves the IP and ARP columns blank.
- **IPv6.** `proto` comes from the fixed header's next-header field. Extension headers aren't walked; the corpus diff will show whether that's enough.
- **ICMP error types.** v4 types `{3, 4, 5, 11, 12}` and v6 types `{1, 2, 3, 4}` dissect the quoted header. They take the ports, `udp_length` and TCP flags from it, and leave `tcp_payload_len` blank.
- **Short frames.** If the captured bytes end before a header is complete, the fields that are missing stay blank. Count these in the `warnings` that `capture_rows` collects, as `"N frames too short to dissect"`.

**Steps**
- [ ] **Step 1: Write the failing tests.** Each test builds one frame with the Task 1 helpers and asserts the full row dict.
  - `test_sll2_ipv6_udp_matches_sponsor_row1`: reproduces row 1 of benign `pod-nginx-tcp.csv` → `eth_* None`, `ip_version 6`, `::1 → ::1`, `proto "udp"`, `ttl 64`, ports `53570 → 8080`, `is_http 1`, `udp_length 17`, `tcp_payload_len None`, `frame_len 77`.
  - `test_ethernet_loopback_zero_macs`: `eth_src == "00:00:00:00:00:00"`, `eth_type == "0x86dd"`.
  - `test_ipv4_tcp_payload_and_flags`: a SYN+ACK with 100 payload bytes → `tcp_syn 1`, `tcp_ack 1`, `tcp_payload_len 100`.
  - `test_tcp_without_payload_prints_zero`.
  - `test_clipped_frame_uses_header_lengths`: IPv4 total length 65212, data cut at 256 → `tcp_payload_len == 65160`, `frame_len == 65226`.
  - `test_ports_either_side_set_flags`: src 53 → `is_dns 1`; src 443 → `is_https 1`; dst 8080 → `is_http 1`.
  - `test_icmp_zero_type_and_code_are_blank`: echo request → `(8, None)`; echo reply → `(None, None)`.
  - `test_icmpv6_error_takes_quoted_udp_ports`: type 1 code 4 quoting UDP 53570 → 8080 length 17 → `proto "58"`, ports filled, `is_http 1`, `udp_length 17`, `tcp_payload_len None`.
  - `test_igmp_proto_is_numeric_string`: `proto == "2"`.
  - `test_arp_fills_arp_columns_only`: `arp_opcode 1`, sender and target IP/MAC filled, `ip_version None`, `eth_type "0x0806"`.
  - `test_raw_ip_under_ethernet_blanks_ip_columns`: frame bytes start `45 00 01 88 …` → `eth_type == "0xc0a8"`, `src_ip None`, no exception.
  - `test_iat_first_row_int_zero_then_signed_float`: three frames, the third earlier than the second → `iat` values `[0, positive float, negative float]`, and the first formats as `"0"`.
  - `test_ts_seconds_rules_differ_only_in_last_ulp`: the `"add"` and `"div"` results for `(1771545910, 906831300, 9)` are within 2.4e-7 of each other.
  - `test_written_csv_loads_through_data_io`: `write_capture_rows` → `data_io.load_capture` returns `PACKET_COLUMNS`, the file uses CRLF line endings, and the header equals `COLUMNS`.
- [ ] **Step 2:** Run `$PY -m unittest tests.PcapRowChecks -v`. Expected: FAIL.
- [ ] **Step 3:** Implement `pcap_rows.py`. Write one small function per layer, each returning a partial dict, and merge them in `frame_row`.
- [ ] **Step 4:** Run `$PY -m unittest tests.PcapRowChecks tests.PcapReadChecks -v`. Expected: all pass.
- [ ] **Step 5:** Commit with the message `feat: dissect frames into the sponsor's 34-column packet rows`.

### Task 3: Calibrate against the four smallest real captures

**Files:** Modify `pcap_rows.py` (`TS_RULE` and any rule the diff corrects); Test: `tests.py` class `PcapCorpusChecks`

**Interfaces:**
- Consumes: `capture_rows`, `local_paths.KUBEDATA_ROOT`.
- Produces: the final `TS_RULE`, plus a `SPONSOR_QUIRKS` module docstring section listing every rule copied from the sponsor's output (blank zero ICMP fields, quoted-header ports, raw-IP blanking, SLL2 blank `eth_*`).

**Steps**
- [ ] **Step 1: Write the corpus tests**, decorated with `@unittest.skipUnless(_kubedata(), "KUBEDATA_ROOT not set")`. `_kubedata()` imports `local_paths` inside a try block and returns the root `Path` if it exists, else `None`. The captures are:
  - `injection attack/pcapng files/pod-nginx-tcp.pcapng` (5 KB)
  - `injection attack/pcapng files/pod-nginx-ptcp.pcapng` (48 rows)
  - `benign/pcapng files/pod-nginx-tcp.pcapng` (346 rows)
  - `benign/pcapng files/pod-nginx-ptcp.pcapng`

  For each one, `test_small_capture_matches_sponsor_csv` compares `capture_rows` → `format_cell` against `csv.reader` of the matching sponsor CSV, cell for cell. It asserts **zero** mismatches and reports the first divergent `(frame_number, column, ours, theirs)`.
- [ ] **Step 2:** Run `$PY -m unittest tests.PcapCorpusChecks -v`. Record which columns diverge.
- [ ] **Step 3: Fix divergences one rule at a time.**
  - If `ts` differs, switch `TS_RULE` to the other candidate and re-run. Keep whichever gives zero `ts` mismatches on both methods. If neither does, stop and report: the sponsor's arithmetic is something else, and their script is needed.
  - Any other column: correct the rule, add a unit test to `PcapRowChecks` that pins the corrected behaviour, and list it in `SPONSOR_QUIRKS`.
- [ ] **Step 4: Add `test_small_capture_windows_match`.** For each capture, `make_windows(load_capture(tmp))`, where `tmp` is the capture written with `write_capture_rows` into a `tempfile` directory, must equal `make_windows(load_capture(sponsor_csv))` under `pd.testing.assert_frame_equal`.
- [ ] **Step 5:** Run `$PY -m unittest tests -v`. Expected: all pass. The corpus classes run here because `local_paths` is present.
- [ ] **Step 6:** Commit with the message `feat: calibrate converter rules against sponsor captures`.

### Task 4: Corpus diff script (`pcap_diff.py`)

**Files:** Create `Threat_Detection/pcap_diff.py`; Test: `tests.py` class `PcapDiffChecks`

**Interfaces:**
- Consumes: `capture_rows`, `COLUMNS`, `data_io.load_manifest`, `data_io.load_capture`, `data_io.PACKET_COLUMNS`, `features.make_windows`, `local_paths.KUBEDATA_ROOT`.
- Produces:
  - `locate_pcap(root, scenario, label, method) -> Path`: searches `root/scenario/"pcapng files"` with `rglob(f"{label}-{method}.pcapng")`. Raises `ValueError` if the count isn't exactly 1, naming the scenario, label and method.
  - `compare_capture(pcap_path, csv_path) -> dict`: streams both files in lockstep and never holds either one in full. Returns one row with these keys:
    - `rows_sponsor`, `rows_regen`
    - `tier_a_exact` (bool)
    - `mismatch_cells`
    - `differing_columns` (`"col:count;..."`)
    - `first_mismatch` (`"frame N col ours|theirs"`)
    - `windows_equal` (bool)
    - `warnings`
    - `seconds`

    `tier_a_exact` is True only when there are no `frame_number` or `PACKET_COLUMNS` mismatches, the row counts are equal, and there are no warnings. The window check runs `make_windows(load_capture(...))` on the regenerated CSV and on the sponsor CSV, and compares the two with `assert_frame_equal`. The regenerated CSV is the `--regen-out` file if one was written; otherwise it's a temp file in `tempfile.gettempdir()` (at most ~100 MB), deleted afterwards. When `timebase_issues` makes both sides unusable, it reports `"both unusable"`.
- **CLI.** `--only tcp|ptcp`, `--labels a,b`, `--limit N`, `--max-gb X` (skips larger pcaps and records `"skipped: size"`), `--regen-out DIR`, `--out pcap_diff.csv`, and `--report` (prints the summary of the existing output file and exits, without reading the Drive).
- **Order.** Captures run smallest file first. One progress line per capture: `[i/88] scenario label method rows tierA windows seconds`.
- **Disk guard.** Before writing each regenerated CSV under `--regen-out`, check `shutil.disk_usage(DIR).free - pcap_size*0.1 >= 20e9`. If not, raise `OSError("less than 20 GB would remain free")`.
- **Summary.** The final line reads `N of M Tier-A exact; windows equal on K; Tier-B differences: col:count, ...`.

**Steps**
- [ ] **Step 1: Write the failing tests.**
  - `test_locate_pcap_flat_and_nested`: a temp tree with both layouts finds both.
  - `test_locate_pcap_missing_or_duplicate_raises`.
  - `test_compare_capture_counts_and_names_mismatch`: write a hand-built pcap with Task 1 helpers, write its CSV with `write_capture_rows`, then change one `dst_port` cell. Expected: `tier_a_exact False`, `mismatch_cells 1`, `differing_columns "dst_port:1"`, and `first_mismatch` names the frame.
  - `test_compare_capture_tier_b_only_is_still_tier_a_exact`: change one `eth_src` cell. Expected: `tier_a_exact True`, `differing_columns "eth_src:1"`.
  - `test_truncation_warning_blocks_exact`.
  - `test_report_flag_reads_cached_output_without_drive`: run the script in a subprocess with a temp `--out`.
- [ ] **Step 2:** Run `$PY -m unittest tests.PcapDiffChecks -v`. Expected: FAIL.
- [ ] **Step 3:** Implement `pcap_diff.py`. Its module docstring and `argparse` follow `sweep.py`'s style.
- [ ] **Step 4:** Run `$PY -m unittest tests -v`. Expected: all pass.
- [ ] **Step 5:** Run `$PY pcap_diff.py --max-gb 0.2`. Expected: a summary line, and `outputs/pcap_diff.csv` with one row per capture (larger ones marked `skipped: size`).
- [ ] **Step 6:** Commit with the message `feat: pcap_diff regenerates sponsor CSVs and diffs them row for row`.

### Task 5: Full corpus run

- [ ] **Step 1:** Run `$PY pcap_diff.py` in the background. It's about 178 GB of local reads, so expect tens of minutes. Note the start and end time.
- [ ] **Step 2:** For every capture that isn't Tier-A exact, read `first_mismatch` and either:
  - fix the rule (unit test + `SPONSOR_QUIRKS` entry, then re-run that capture with `--labels`), or
  - name the cause in the report: truncation, the quarantined `nginx attack/pod-robot-controller/tcp`, and so on.

  Don't accept an unexplained mismatch.
- [ ] **Step 3:** Commit `outputs/pcap_diff.csv` and any rule fixes with the message `data: full pcap_diff run over the 88 captures`.

### Task 6: Docs and menu

**Files:** Modify `demo.py`, `README.md`, `PROGRESS.md`

- [ ] **Step 1: `demo.py`.** Add `def pcap_diff(): _run("pcap_diff.py", "--report")` and add `("Pcap diff", pcap_diff, "regenerated packet rows against the sponsor CSVs")` to `ITEMS` before "Everything". Don't add it to `everything()`, because the full run is too long for the menu.
- [ ] **Step 2: README.** Add a section "Capture to packet rows" covering:
  - the two containers and linktypes;
  - that the extension doesn't identify the container;
  - the `SPONSOR_QUIRKS` list;
  - how to run `pcap_diff.py` (and `--report`);
  - the measured result line.

  Add both new modules to "What each file is".
- [ ] **Step 3: PROGRESS.md.** Add a section "Pcap converter verdict (2026-11-xx)" with the Tier-A and window results and the Tier-B counts per column, each with its named cause.
- [ ] **Step 4:** Run `$PY -m unittest tests` (expected: OK), then `$PY demo.py 8` (the new item's number; expected: the summary prints).
- [ ] **Step 5:** Commit with the message `docs: pcap converter section, demo item, progress verdict`.

### After verification (manual, not part of the code)

Once Task 5 is committed and reviewed, free the space in Finder: right-click each `KUBEDATA/*/pcapng files` → Google Drive → **Online only**. Keep the four Task 3 captures offline if the corpus tests should keep running locally. Don't delete anything; the folder is shared.

## Out of scope

- Live capture or calling `tcpdump`/`ptcpdump`.
- A "correct" mode that recovers the raw-IP rows the sponsor blanked.
- Rotated captures (`name0.pcapng`, `name1.pcapng`).
- VLAN tags and IPv6 extension-header walking, unless the diff shows they're needed.
- Changes to `data_io`, `evaluation.py`, or the misnamed `at_snaplen` metric (it counts 64 KB GSO frames, not truncation). Note that last one in PROGRESS.md only.
