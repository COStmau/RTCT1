# Subsystem 2: detection and diagnosis

Offline analysis of the KUBEDATA packet captures. Run everything from this folder with
the project virtualenv: `.venv/bin/python`.

## Try it on your machine

The provided dataset is not in this repository. What is here is the page built from
them (`baked_demo/`), and the harness that opens on it and loads your own captures. Pick one:

**1. Look only (no install).** Open `baked_demo/state_machine.html` in a browser. The file is
self-contained and works offline. It shows the cluster map, the state machine learning, and
every attack replayed through the detector.

**2. Run the harness (Python 3.11 or newer).** One command builds a virtualenv in `.venv` on
the first run. The setup takes a few minutes. The command then opens the page in your browser:

```bash
git clone https://github.com/COStmau/RTCT1.git
cd RTCT1/Threat_Detection
python3 run.py          # Windows: py -3.11 run.py
```

The harness opens on the baked page. Its **Data** tab loads your own packet CSVs or
pcap/pcapng files, and rebuilds every tab from them (see "The harness" below).
`python3 run.py --data <folder>` scans a folder on start. `--port` and `--no-open` also work.
Press Ctrl-C to stop the harness.
If you do not have Python 3.11, get it from [python.org](https://www.python.org/downloads/). On
Windows, tick "Add python.exe to PATH" and use the `py` launcher.

**3. Docker (only Docker needed).**

I haven't been able to test this yet.

```bash
cd RTCT1/Threat_Detection
docker build -t rtct-detect .
docker run --rm -p 127.0.0.1:8765:8765 rtct-detect
# then open http://127.0.0.1:8765/
```

To load your captures, mount the folder and scan it on start:
`docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/captures:/data" rtct-detect python viz/serve.py --host 0.0.0.0 --data /data`
(PowerShell: `-v "${PWD}/captures:/data"`).

If you have no captures of your own, Docker and [k3d](https://k3d.io) can record some from a
local cluster. See "Collecting new captures" below (macOS and Linux).

The repository is private. Ask Charles to add your GitHub account as a collaborator. Without
access, the clone asks for a login and then reports that the repository is not found.
`demo.py` items 1-8 need the dataset itself (`local_paths.py`). Without the dataset, they
print a message and skip.

Rebuild the page into `baked_demo/` with `.venv/bin/python viz/bake.py`, on a machine that has
the captures. The script refuses to write a page that still holds a local path.

## How it fits together

Data flows one way through four layers, and each layer only knows the one below it:

```
packet CSVs ──► data_io ──► features ──► detectors ──► reporting ──► tables, charts, stdout
                load a      1-second    fit / calibrate   print and
                capture     windows     / score / flag    plot
```

`core/data_io.py` → `core/features.py` → `core/detectors.py` → `core/reporting.py`. Nothing
downstream reaches back upstream, and none of the four import `local_paths.py`, so they are
portable and testable on their own. `core/` may not import `methods/`, `viz/`, `convert/`, `demo` or `local_paths`,
nor anything in `dev/` (`experiments`, `verdicts`, `metrics`, `statemachine`).

```
core/          the subsystem. This is what goes into the project.
methods/       the second detection method, a learned automaton.
viz/           the interactive visualization page.
convert/       capture files -> the sponsor's packet CSVs.
dev/           how it was built and judged: experiments, verdicts, tests, design notes.
```

Everything under `dev/` (the measurements, the keep-or-drop
rules, the unit suite, the progress log and the rearchitecting notes) is mapped in
[`dev/README.md`](dev/README.md). Nothing outside `dev/` imports from it.

## What each file is

**`core/` and `methods/` are the subsystem.** They are what goes into the project; everything
below them is how it is presented and how captures are fed to it. `core` imports nothing
outside itself.

### The subsystem

| File | What it does |
|---|---|
| `core/__init__.py` | The whole subsystem in six calls: `load_capture` → `make_windows` → `split_reference` → `build_detector` → `pipeline` → `annotate`. Its docstring is the shortest correct description of this folder. |
| `core/data_io.py` | The input format and where output goes. Names every capture, reads the packet columns, checks the timebase and snaplen saturation, builds and caches the manifest, resolves `outputs/`. |
| `core/features.py` | Packets → one row per second. The 13 features, the 9 the detectors read by default (`DETECTION_FEATURES`), the ablation groups, and the temporal train/held-out split. Stateless: no baseline, no thresholds, no detection. |
| `core/detectors.py` | Every detection method behind one interface (each reads `DETECTION_FEATURES` unless built with `features=None`): `fit` → `calibrate` → `score` → `flag`, with optional `explain`. The z-score baseline is median + MAD. Add one by writing a class and adding it to `REGISTRY`. |
| `core/evaluation.py` | How a result is judged, in one place: the 70/30 split, the six bulk-transfer files that never calibrate, and the warm-up window. |
| `core/reporting.py` | Console reports, charts, the `SHOWCASE.md` handover file, and the event log the response side reads. Takes results, renders them; computes no detection logic. Pins matplotlib to `Agg`, so nothing here opens a window. |
| `methods/pdfa.py` | PDFA anomaly detection after Cao et al. (ARES 2022), learning half: packet flows to symbols, the prefix tree, ALERGIA state merging, the automaton. |
| `methods/scores.py` | The scoring half of the same method: trace likelihood, and SEQUENT's cumulative and windowed frequency scores with their cutoffs. |

### The presentation

| File | What it does |
|---|---|
| `viz/page.py` | The state machine as one interactive page, `outputs/state_machine.html`: the inferred cluster, ALERGIA learning step by step, and a replay of held-out benign and every attack through the windowed SEQUENT scorer (the 8 s anomaly clock, forgetting, release). One page carries every steady capture tap (`--vantages` to choose; `--vantage` picks the one it opens on): click a tap on the map or use the header picker to switch the learning and detection acts, and the Detection tab's *Across taps* view lines one scenario up at every tap on a shared capture-time axis. Self-contained (about 3 MB for the 8 steady taps; past 15 MB the other taps' per-trace breakdown is dropped); opens offline. `demo.py` item 10. The renderer is `viz/template/`. Bulk-transfer vantages (`core/evaluation.BULK_LABELS`) never set a cutoff, so they are left out unless `--allow-bulk`, and the page then marks their verdicts as inspection only. Each cutoff shows how many held-out windows it rests on and how often it actually flags them; capture text is HTML-escaped in the bundle. |
| `viz/cluster.py` | The k3s cluster's shape inferred from benign traffic: nodes, pods (including host-network ones), services, conversations and where each capture listened. |
| `viz/bake.py` | Builds the harness's default bundle from KUBEDATA and writes it, with every local path rewritten to `KUBEDATA/...`, into `baked_demo/`. |
| `viz/layout.py` | Computed positions for the page: the prefix tree as an icicle, the learned machine in columns. |
| `viz/serve.py` | The harness: the same page served from a local, standard-library server, so its **Data** tab can load other captures and rebuild. Binds 127.0.0.1 only. Opens already built on today's page when `local_paths.KUBEDATA_ROOT` is set. `demo.py` item 12. See "The harness" below. |
| `viz/sources.py` | What the harness reads: scans folders (CSV, pcap, pcapng, told by magic number), loads a file as flow packets (converting captures through `convert/`), turns role/tap assignments into a bundle with its provenance, and replays a capture as a stream of 1-second windows (`ReplaySource`, counts only). |
| `localcluster/collect.py` | A local k3s cluster (k3d on Docker) that records new captures in the KUBEDATA layout: `up`, `run <scenario>`, `all`, `status`, `down`. Two profiles in `localcluster/profiles/`: `lab` (the lab look-alike) and `general` (a generic app on the kubeadm address plan). See "Collecting new captures" below. |
| `localcluster/traffic.py` | Every workload and attack in those clusters as one stdlib script with modes, mounted into the pods from a ConfigMap. |

### Capture conversion

Capture files to the packet CSVs `core/data_io.py` reads. Upstream of the subsystem and
independent of it; see "Capture to packet rows" below.

| File | What it does |
|---|---|
| `convert/read.py` | The two capture containers (pcap, pcapng) to raw frames. Format from the magic number, never the extension. Reads at most 256 bytes of each frame. |
| `convert/rows.py` | Frames to the sponsor's 34-column packet rows, written as their CSV. Copies the sponsor's own quirks on purpose; `SPONSOR_QUIRKS` in its docstring lists them. |

### The entry surface

| File | What it does |
|---|---|
| `demo.py` | A menu over the whole subsystem. Items 1-3 are presentations (pair demo, plain-language walkthrough, state machine); 4-7 run experiments from `dev/`; 8 regenerates every artifact; 9 runs the tests (`dev/tests.py`); 10 builds the interactive state-machine visualization page; 11 summarizes the last capture-conversion diff; 12 starts the harness (`viz/serve.py`). |
| `local_paths.py` | Your local dataset paths. Not committed; copy `local_paths.example.py` and fill it in. Only the entry points and experiments read it, never `core/`. |
| `dev/` | Development material, not shipped: experiments, verdicts, tests and design notes. Mapped in `dev/README.md`. |
| `run.py` | The one-command start for any machine: makes `.venv`, installs `requirements.txt` once, opens the harness. Standard library only. See "Try it on your machine". |
| `baked_demo/` | The KUBEDATA page, prebuilt and with no capture data: `state_machine.html` (opens offline) and `bundle.json.gz` (what the harness opens on when there is no `KUBEDATA_ROOT`). Written by `viz/bake.py`. |
| `Dockerfile` | The harness in a container, for a machine with only Docker. |
| `requirements.txt` | The pinned runtime: Python 3.11 with numpy, pandas, matplotlib and scikit-learn at the versions the numbers were measured under. |
| `EVENT_LOG.md` | The detection → response event contract (`LogV1`, carries the capture-relative second). |
| `outputs/` | Everything generated. Safe to delete; `demo.py` item 8 rebuilds it. `outputs/SHOWCASE.md` is every measured result as one file. |


## Run it

Build the virtualenv once from the pinned runtime:
`python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt`.

```bash
cd Threat_Detection
.venv/bin/python demo.py            # menu
.venv/bin/python demo.py 2          # one item, no menu
.venv/bin/python demo.py all        # sweep, ablation, compare, features, then the report
```

The menu, in order:

```
 1  Pair demo       one normal and one attack recording: report and chart
 2  Walkthrough     the same pair narrated plainly, then writes outputs/SHOWCASE.md
 3  State machine   trace scores from a learned automaton, two charts
 4  Sweep           every capture against its own matched benign reference
 5  Ablation        the sweep repeated once per feature group
 6  Compare         z-score against isolation forest and one-class SVM
 7  Feature value   what each measurement is worth on its own
 8  Everything      all of the above, in the order the report needs it
 9  Tests           the unit suite
10  Visualization   the state machine learned and replayed, as an interactive page
11  Pcap diff       regenerated packet rows against the sponsor CSVs (last run's summary)
12  Harness         the visualization served live: load any captures on its Data tab
```

Items 4-7, 9 and 11 run scripts in `dev/`. In a copy without `dev/`, they print a message and
skip. You can also build the page directly:

```bash
.venv/bin/python viz/page.py        # interactive page, every steady tap; --vantage pod-nginx opens on it
```

The experiments, the tests and the capture diff live in `dev/`. Their commands are in
`dev/README.md`.

Generated files always go to `Threat_Detection/outputs/`, whatever directory you start from.
After you change the dataset, delete `outputs/capture_manifest.csv`. Otherwise the sweep
scores the previous inventory.

## The harness

`viz/page.py` bakes one dataset into a static page. The harness serves the same page live. A
person with other captures (another cluster, another attack) can then use the page without
editing code:

```bash
cd Threat_Detection
python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt   # once
.venv/bin/python viz/serve.py --open                                    # or: demo.py 12
```

The harness adds no dependencies. The options are `--port`, `--data <folder>` (a folder that
the harness scans when the page opens), and `--no-preload` (start empty instead of building
today's KUBEDATA page). The page gains a first tab, **Data**. Do these steps:

1. **Source.** Load the KUBEDATA manifest (tcp or ptcp). Or scan folders, which the harness
   searches recursively. Or drop files onto the page. Uploads go to `outputs/uploads/`.
2. **Captures.** The table has one row per file. Set the role, level, tap name and scenario of
   each file.
   - **benign** trains a tap. The harness learns the first 70% and holds out the last 30% to
     set that tap's cutoffs. Each benign capture also draws the cluster map. A tap needs
     exactly one benign capture.
   - **attack** is replayed against the tap with the same name.
   - **ignore** leaves the file out.
   - A tap name is `level-name` (`pod-nginx`, `node-child1`, `router-any`). The level tells
     the map where the capture listened.
   The harness guesses these values from file names and folders. Check each guess.
3. **Cluster profile.** The address plan that the map assumes, held in
   `viz/cluster.ClusterProfile`: pod and service CIDRs, the per-node pod subnet size,
   the control-plane, kubelet and NFS ports, and flannel's `.0`/`.1` rule. `k3s` is the
   testbed's plan. `kubeadm` uses 10.244/16 for pods and 10.96/12 for services. You can edit
   any field.
4. **Parameters and build.** Set the anomaly clock, the tap to open on, and whether to draw
   bulk-transfer taps. **Build page** runs the same pipeline as the static page. The other
   tabs then redraw. **Export static page** writes the result to one offline file,
   `outputs/harness_export.html`. It never overwrites `state_machine.html`. The Data tab of
   the exported page lists what it was built from.
5. **Replay as a stream.** A capture replayed at 1-200x as a stream of 1-second windows
   (packets, bytes, flows, new endpoints). The harness does not score this stream. Scoring
   live traffic is a separate program, the live monitor (see "Live monitor").

A capture is a packet CSV with `ts, frame_len, src_ip, dst_ip, src_port, dst_port, proto`
(headers like `Src IP` are accepted), or a pcap/pcapng file. `convert/` changes captures into
the sponsor's 34-column rows and caches them in `outputs/converted/`. With the manifest loaded
and the default settings, the harness builds exactly the bundle that `viz/page.py` writes.
`HarnessParityChecks` holds it to that.

## Collecting new captures

`localcluster/` runs a k3s cluster on this machine with k3d (k3s inside Docker containers) and
records captures from it. The files are named and arranged like KUBEDATA, so the harness loads
them like the sponsor's data.

```bash
brew install k3d                                       # once; Docker Desktop must be running
.venv/bin/python localcluster/collect.py up            # the lab look-alike cluster
.venv/bin/python localcluster/collect.py all --csv     # benign + every attack, 60 s each
.venv/bin/python viz/serve.py --no-preload --open      # Data tab: Load manifest, root ~/rtct-data/lab
.venv/bin/python localcluster/collect.py down
```

**Profiles.** Choose one with `--profile`. Each is a folder holding `k3d.yaml` (the cluster)
and `profile.json` (workloads, taps and attacks, as data). Adding a workload is one line.
- `lab` (the default) copies the lab's names:
  - nodes child1, child2, child4 (control plane) and gchild9;
  - pods nginx, lidar, camera, a host-network robot-controller and robot-hardware;
  - the k3s address plan.
- `general` is deliberately unlike the lab:
  - a small shop app: frontend, api, redis, store, worker and a load generator;
  - nodes named server, agent1 and agent2;
  - the kubeadm plan (pods 10.244/16, services 10.96/12). Choose the **kubeadm** preset on
    the harness's Data tab for this one; `<out>/profile.json` says which preset to use.

**Scenarios.** `benign`, plus four attacks that start at `--attack-at` (default second 10)
and run to the end:
- `http-flood`: concurrent requests to the web service.
- `scan`: a TCP connect scan of the cluster's own service and pod ranges.
- `lateral`: a compromised workload connecting to peers and ports it never uses.
- `sensor-flood`: the lidar stream at about 20x its rate, or a TCP flood on redis in `general`.

Attack traffic only targets the local cluster's addresses.

**Taps.** Each recording runs tcpdump at the same three levels as KUBEDATA:
- **pod:** inside the pod, from a `capture` sidecar;
- **node:** inside the k3d node container's network namespace;
- **router:** `router-any` is the Docker bridge between the nodes, and `router-flannel` is that
  bridge filtered to VXLAN, the pod overlay.

Output goes to `<out>/<scenario>/pcapng files/<label>-tcp.pcap`. With `--csv` the sponsor's
packet CSVs are also written to `csv files/`. `<out>` defaults to `~/rtct-data/<profile>`,
outside the repo.

**How it differs from the lab.**
- The nodes are containers on one Docker VM, so "router" is a Linux bridge and node NICs are
  veths.
- There is no NFS server, so no NFS traffic.
- The router captures are Ethernet frames, not Linux cooked frames.
- `core/evaluation.BULK_LABELS` drops router-any, node-child4 and pod-robot-controller because
  the *lab* recordings carry bulk transfers. Local recordings don't, so tick "draw bulk-transfer
  taps" in the harness to see those taps.

## Live monitor

The demo above (`viz/`) explains recordings and is kept as it is. Watching a cluster as it runs
is a separate program, `live/`, with its own server and its own dashboard. The two share the
detector (`methods/calibration.py`: one calibration, one set of alert and release rules) and
nothing else, so a live tap and a replayed recording of it can be checked against each other.

```bash
.venv/bin/python localcluster/collect.py up --profile general
.venv/bin/python live/serve.py --open                         # http://127.0.0.1:8766
```

No cluster is needed to try it: recordings can be played back as if they were taps.

```bash
.venv/bin/python live/serve.py --open --replay ~/rtct-data/general/"http-flood attack"/"pcapng files"/pod-api-tcp.pcap --speed 10
```

One screen:

- **Cluster:** nodes, pods and services from Kubernetes itself (nothing inferred), with who talked
  to whom in the last 30 s at the watched taps. Each tap's dot is its latest verdict; click one to
  follow it.
- **Taps:** one strip per tap: the windowed score against its cutoff over the last three minutes,
  the status band under it, attacks shaded. Watch or stop taps one at a time or all at once; pods
  and nodes are the default (router taps carry every packet between nodes).
- **The selected tap:** its verdict in words, the trace behind the latest flagged window and who
  its flows were between (also drawn in red on the map), and what its detector rests on.
- **Attacks** (local cluster only): the profile's own scenarios for 5-300 s, shaded on every strip.
  The event log gives each tap's alert latency from the attack's start and its release after the end.
- **Events:** alerts, releases, attacks, and taps that stopped or stalled.

Where a tap's machine comes from, first that applies: one saved by an earlier run
(`live/models/<label>.pkl`); the tap's benign recording from `collect.py run benign`, when that is
newer; otherwise the tap's own stream, whose first 60 s are taken as benign. So a cluster with no
recording at all can be watched straight away. **Re-learn** does the last of these on demand, for
one tap or all: the next N seconds are learned from while the old machine keeps scoring, then the
new one is swapped in. Nothing restarts, and open alerts carry over. Use it whenever benign traffic
has drifted (a running app's data grows, and response sizes move between bins). It is refused
while an attack is running, and attacks are refused while a tap is learning.

A tap is two processes, the capture piped into a scoring worker (`live/worker.py watch`), so taps
score on separate cores. The monitor supervises them: a capture that dies (a pod restarted, a
dropped `kubectl exec`) is restarted with a growing delay on the pod's new name, a tap that stops
closing windows is called stalled and then restarted, and one tap failing leaves the rest alone.
A window scored more than 5 s late is marked `behind`.

Everything a session produced is kept under `~/rtct-data/<profile>/live/`:
`session-<time>/events.jsonl` (every verdict, alert and attack), `attacks.json`, and, with
**Record packets** on, each tap's packets in `live attack/pcapng files/<label>-tcp.pcap`, laid out
so the demo's Data tab or `--replay` can read them back.

| File | What it does |
|---|---|
| `methods/calibration.py` | The detector both programs use: `calibrate` (the machine and its cutoffs from benign packets) and `WindowRules` (alert, release and status, one window at a time). |
| `live/stream.py` | A pcap byte stream (`tcpdump -w -`) read without seeking, closed one second at a time into flows, and scored. Also `replay`, a recording through the same path. |
| `live/worker.py` | One tap's scoring process: learns or loads its machine, re-learns on command, writes one JSON line per closed second. `pace` plays a recording back as a stream. |
| `live/taps.py` | Where packets come from, as a small provider interface: the local k3d clusters (`LocalClusterProvider`) or recordings (`ReplayProvider`). A deployed cluster is a third provider. |
| `live/monitor.py` | The monitor: supervises each tap's processes, keeps the snapshot and the event stream a page needs, launches attacks, writes the session log. |
| `live/serve.py` | Its server (standard library, 127.0.0.1): the dashboard in `live/web/`, `/api/state`, and `/api/stream`, which resumes from where a page left off. |

One rule has to change for a stream: offline, a 5-tuple whose packets span more than one second
anywhere in the capture is dropped; live, a flow is kept in its second only if its 5-tuple appeared
in no earlier second (within 120 s) and in none of the next two. So each window is scored about
three seconds after it ends, and a tap is always trained on flows cut the live way
(`live.stream.calibrate_live`). The two rules disagree only on reused 5-tuples, such as DNS lookups
that reuse a source port half a minute later.

## Capture to packet rows

`convert/read.py` and `convert/rows.py` turn a capture file into the same 34-column packet
CSV the sponsor supplied, so a capture taken today can be windowed and scored with no dataset in
between. `dev/experiments/pcap_diff.py` is the proof: it regenerates every sponsor CSV from its
capture and diffs the two.

What the corpus actually is, read from the files rather than their names:

- Every capture is named `.pcapng`, but only the 44 ptcp ones are pcapng (ptcpdump v0.37.0,
  Ethernet link layer, nanosecond timestamps). The 44 tcp ones are classic pcap (Linux cooked
  capture v2, microsecond timestamps). The reader goes by the magic number.
- `benign/` and `injection attack/` keep their captures flat under `pcapng files/`; the
  other two nest them under `{tcp,ptcp}/<level> level/`.
- 14 capture files end mid-record, their tails filled with zeros. In
  `injection attack/node-child4-ptcp` the real data stops at 4.58 GB of a 10.8 GB file. The
  sponsor's CSVs were made from these same cut files.

The converter copies the sponsor's conversion where it is surprising rather than correcting
it, so the rows match; `SPONSOR_QUIRKS` in `convert/rows.py` lists each rule with its evidence.
The one deliberate exception is a zero-filled tail, which the reader stops at instead of
reading zeros as packets.
The ones that change a counted feature: `is_http` matches port 80 or 8080 on either side, and
an ICMP error message takes its ports from the packet it quotes.

Measured 2026-11-03 over all 88 captures, 461 seconds: every regenerated row identical, cell
for cell, to the sponsor's row at the same position, and the window tables equal on 87.
`dev/experiments/pcap_diff.py` counts 74 captures Tier-A exact and 13 "identical but cut short at the source",
because a file cut mid-record is never called complete.

The 88th is the quarantined `nginx attack / pod-robot-controller / tcp`, and the converter
explains it. Its recording ends at frame 155,603, 3.56 GB into a 3.75 GB file; the rest is
zeros. The sponsor's conversion read 64,853 of those zero records as packets with timestamp
0, which is what made the capture unusable. The converter stops at the first zero record, so
its version of this capture is 155,603 real frames and can be windowed.

## Adding a detector

Write one class and add one line to `REGISTRY`:

```python
class MyDetector(Detector):
    name = "my_detector"

    def fit(self, reference): ...          # learn from benign training windows
    def calibrate(self, held_out_benign): ...   # set self.cutoff
    def score(self, windows): ...          # higher = more anomalous; NaN if unscorable
```

Then `build("my_detector")`. `dev/experiments/compare.py` picks it up with no changes, because it iterates
the registry. Two rules the protocol guarantees, so a new detector cannot break a
comparison:

- **Higher score means more anomalous.** scikit-learn's `decision_function` runs the other
  way, so learned detectors negate it once in `LearnedDetector.score`.
- **Attribution is optional.** `explain` stays `None` unless your detector can genuinely
  name the feature that moved. The z-score can; a learned model that guessed would make the
  comparison lopsided.

## Rules the code follows

- One second per window. A window with no packets keeps zero counts and leaves the
  averages empty, not zero.
- The reference is learned from benign traffic only, and the last 30% of that capture is
  never used for fitting. That part is the honest check.
- The baseline is a median and a MAD, not a mean and a standard deviation. Six of the 22
  benign captures contain a bulk-transfer regime change, and a mean/std summary is set by
  those windows rather than by normal traffic. `dev/PROGRESS.md` has the reasoning.
- A window is flagged when its score passes the cutoff, and an alert needs
  `PERSISTENCE_WINDOW` flagged windows in a row.
- Missing or mismatched data is reported as insufficient, never as normal.
- Learned models take their cutoff from held-out benign windows, so every detector is
  compared at the same false-alarm budget.
- A capture truncated by the recorder's snaplen is still scored, but `at_snaplen` in the
  manifest records the fraction of packets clipped, and those captures' length-based
  features are not comparable to the unclipped ones.
