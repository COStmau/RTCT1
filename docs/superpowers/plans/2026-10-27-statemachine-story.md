# State-Machine Story Visualization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One self-contained, generated HTML page that tells the state-machine story in three acts: the k8s cluster and where we listened, how the PDFA is learned from benign flows, and a playback of held-out benign and attack traffic through the learned machine. The playback makes the anomaly clock (8 s forgetting), the SEQUENT frequency score, and the release after a burst visible.

**Architecture:** Python builds a JSON "story bundle" from the real pipeline (`statemachine.py`, unchanged in behavior) plus two small instrumentation hooks. A static HTML/JS/CSS template renders the bundle with D3. `story.py` inlines template + bundle into `outputs/statemachine_story.html`. Nothing about the cluster, the states, their positions, or the timeline is written by hand: topology is inferred from the captures' IPs and ports, layouts are computed, every number comes from the bundle.

**Tech Stack:** Python 3.11, numpy, pandas (already pinned). D3 v7.9.0, inlined from a vendored copy so the page works offline on a projector. No new Python dependencies.

**Spec:** This document; the design is in "Design" below (there is no separate spec). The user's request: visualize state-machine creation, then detection on playback of held-out data; a visual of the k8s cluster structure; detection must show off the timer / forgetting / SEQUENT scoring; programmatically generated, not hardcoded; prioritize a good, understandable, pretty visual.

## Global Constraints

- Run everything from `Threat_Detection/` with `.venv/bin/python`. Tests are `unittest` in `tests.py` (`.venv/bin/python -m unittest tests`).
- `statemachine.py` scores must not change: existing `WindowedScorerChecks` and `StateMachineChecks` stay green, and the bit-identical windowed-vs-cumulative test still holds.
- Layering from `README.md`: `story.py` and `cluster.py` are library modules and must not import `local_paths`; only `demo.py` (and `story.py`'s `main()`, imported lazily like `statemachine.main`) reads it.
- All generated files land in `outputs/` via `data_io.resolve_output`.
- No hardcoded topology, IPs, state ids, coordinates, colors-per-state or timestamps in the template or the bundle builder. Constants allowed: `FORGET_SECONDS`, `TRACE_LEN`, `WINDOW_SIZE`, `BENIGN_QUANTILE`, `PERSISTENCE_WINDOW` imported from where they live; well-known port names (6443 apiserver, 2379 etcd, 53 DNS, 8472 flannel VXLAN, 2049 NFS) in one `WELL_KNOWN_PORTS` dict in `cluster.py`; the k3s CIDR conventions (`10.42.0.0/16` pods, `10.43.0.0/16` services) as named constants in `cluster.py`.
- The HTML must open from `file://` with no network access, render at 1280×720 (projector) and 1920×1080, and stay under 15 MB.
- Palette: one sequential scale for state heat, one accent for "flagged", one for "released/normal", neutral grays for structure. Colors defined once as CSS custom properties.

## Design

The page is a single scroll-free "stage" with a top act switcher (`1 Cluster · 2 Learning · 3 Detection`), a large canvas on the left, and a narrative side panel on the right that explains, in plain language, what the current frame shows (text generated from bundle numbers, e.g. "Merged state 7 into 3: every next-symbol frequency within the Hoeffding bound ±0.21").

**Act 1 — Cluster.** Hosts (k3s nodes) are rounded boxes; pods discovered in each node's `10.42.N.0/24` sit inside them as circles labeled from the pod-level capture names (`pod-nginx`, `pod-lidar`, …). The flannel overlay is a band between nodes; the router vantage is drawn on the uplink; the control plane is the host that serves 6443/2379. Each of the 11 capture vantages (pod / node / router) is a small "tap" icon on the element it records. Edges are the observed conversations, width ∝ log(packets), labeled by well-known port. The vantage selected for the story is highlighted, and the panel says what that tap can and cannot see.

**Act 2 — Learning.** Left: the symbol stream (flows → `tcp_p2_p1`-style chips, colored by protocol, size/duration bins as two small bars) feeding fixed 5-flow traces. Center: the prefix-tree acceptor drawn as an **icicle** (depth = position in trace, width = visits), which stays readable at thousands of PTA nodes. Then ALERGIA red-blue merging is played step by step: the blue candidate is outlined, the red state it is tested against is outlined, and a small bar chart shows `|p1 − p2|` per symbol against the Hoeffding bound (green under, red over). A merge animates the blue subtree folding into the red state; a promotion turns blue to red. A scrubber covers all merge steps; "skip to result" jumps to the final PDFA. The final PDFA is drawn as a layered graph (BFS depth columns, barycenter ordering), node area ∝ visits, edge width ∝ probability, self-loops drawn as arcs, same encoding as `plot_pdfa` so the PNG and the page agree.

**Act 3 — Detection playback.** A capture selector (held-out benign, nginx attack, lidar attack, injection attack, for the chosen vantage) and play/pause/speed/scrub controls on a time axis in capture seconds.

- *Machine view:* the final PDFA. The current trace is a token walking its states; a symbol with no transition shows the token falling off with a red ✕ ("unseen behavior → floor probability").
- *Anomaly clock:* every state carries a ring of tick marks, one per visit currently inside the trailing `FORGET_SECONDS` window; each tick drains clockwise as it ages and vanishes on expiry. State fill = windowed test count vs training count (the SEQUENT ratio), on the sequential heat scale. A global clock at the top shows the window `[t − 8 s, t]` sliding over the timeline, with expiring visits dropping out of its left edge.
- *Score strip (bottom):* three aligned lines over capture time: trace likelihood with its cutoff (the existing detector), windowed SEQUENT score with its cutoff, and cumulative SEQUENT as a dashed ghost line. Flagged windows are shaded; an alert badge appears after `PERSISTENCE_WINDOW` consecutive flagged windows; a "released" marker appears where the windowed score drops back under its cutoff. The ghost line staying up while the windowed line releases is the visual argument for forgetting.
- *Score breakdown:* hovering the current trace shows its four SEQUENT terms per visited state (`log(test+1)`, `−log(train+1)`, `log(total_train+1)`, `log(states_seen+1)`) as a stacked bar, so the score is explainable, not just a number.
- *Cluster inset:* a mini Act-1 map; the flows in the current trace pulse along their edges, and the tapped element glows with the current flag state.

Default story: `pod-lidar` with `lidar attack` (the 5 s replay loop that `FORGET_SECONDS` was sized for, so a release is visible inside the capture), overridable by CLI.

## File Structure

| File | Responsibility |
|---|---|
| `Threat_Detection/statemachine.py` (modify) | Add an optional `trace=` recorder to `learn_pdfa` and a `score_terms` method on `WindowedFrequencyScorer`; behavior unchanged. Add `frequency_cutoff`. |
| `Threat_Detection/cluster.py` (create) | Infer the cluster topology from packet frames: hosts, pods, services, vantages, conversations. Pure functions. |
| `Threat_Detection/layout.py` (create) | Deterministic layered layout for the PDFA and the icicle layout for the PTA. Pure functions. |
| `Threat_Detection/story.py` (create) | Build the story bundle (dict) from captures, write the HTML. `main()` CLI. |
| `Threat_Detection/story_template/index.html`, `story.css`, `story.js` (create) | The renderer. Reads `window.STORY`; no data of its own. |
| `Threat_Detection/story_template/vendor/d3.v7.9.0.min.js` (create) | Vendored D3 for offline use. |
| `Threat_Detection/demo.py` (modify) | Menu item 10 "Story". |
| `Threat_Detection/tests.py` (modify) | `ClusterChecks`, `LayoutChecks`, `StoryBundleChecks`, plus instrumentation checks in the existing state-machine classes. |
| `Threat_Detection/README.md` (modify) | One row in the file table, one line in "Run it". |

## Story bundle schema (the contract between Python and JS)

```text
{
  "meta":    {"vantage": str, "level": str, "forget_seconds": float, "trace_len": int,
              "window_size": float, "persistence": int, "generated": iso8601},
  "cluster": {"hosts":   [{"id", "ip", "pod_cidr"|null, "roles": [str]}],
              "pods":    [{"id", "ip", "host"|null, "name"|null}],
              "services":[{"id", "ip", "port_names": [str]}],
              "external":[{"id", "ip"}],
              "edges":   [{"src", "dst", "packets": int, "ports": [str]}],
              "vantages":[{"label", "level", "element": id}]},
  "learning":{"symbols":   [{"symbol", "proto", "bytes_bin", "duration_bin", "count"}],
              "pta":       [{"id", "parent"|null, "symbol"|null, "visits", "x0", "x1", "depth"}],
              "steps":     [{"kind": "merge"|"promote", "red": pta_id, "blue": pta_id,
                             "tests": [{"symbol", "p_red", "p_blue"}], "bound": float}],
              "pdfa":      {"states": [{"id", "visits", "x", "y", "pta_ids": [pta_id]}],
                            "edges":  [{"src", "dst", "symbol", "prob"}]}},
  "playback":{"captures": [{"scenario", "duration_s",
               "cutoffs": {"likelihood": float, "windowed": float},
               "traces":  [{"t", "symbols": [str], "states": [state_id],
                            "fell_off_at": int|null, "likelihood": float,
                            "windowed": float, "cumulative": float,
                            "terms": [[a, b, c, d]], "flows": [[src_id, dst_id]],
                            "expired": [[t_visit, state_id]]}],
               "windows": [{"index", "flagged": bool, "alert": bool, "released": bool}]}]}
}
```

State ids are `pdfa_states_in_order` indices; PTA ids are BFS indices of the prefix tree. `expired` lists the visits the scorer dropped before scoring this trace, so the renderer animates exactly what the scorer forgot rather than recomputing it.

## Review Focus

1. A vantage with no pod-level capture (e.g. `router-any`) chosen as the story vantage → cluster still draws, pods without capture names get their IP as label, no crash.
2. An attack capture whose every trace falls off the machine at symbol 1 (all-unseen alphabet) → token animation shows the ✕ immediately, scores are finite in JSON (no `-Infinity`/`NaN`, which `json` would emit and `JSON.parse` rejects).
3. A PTA with thousands of nodes → icicle stays readable and bundle stays under 15 MB (cap `steps` detail to the first `MAX_STEP_DETAIL = 400` merges plus a summary count).
4. A long attack capture (thousands of traces) → playback holds 60 fps; renderer must update via data joins, not rebuild the SVG per frame.
5. Opening the HTML from `file://` with no network → D3 is inlined and nothing is fetched.

---

### Task 1: Instrument the learner and the windowed scorer without changing scores

**Files:**
- Modify: `Threat_Detection/statemachine.py` (`learn_pdfa`, `WindowedFrequencyScorer`, new `frequency_cutoff`)
- Test: `Threat_Detection/tests.py` (`StateMachineChecks`, `WindowedScorerChecks`)

**Interfaces:**
- Produces:
  - `learn_pdfa(traces, alpha=ALERGIA_ALPHA, trace=None) -> PDFA`. When `trace` is a list, it receives, in order: one `("pta", root)` before merging (root of the unmerged prefix tree, deep-copied so later merges do not mutate it), then one dict per red-blue step: `{"kind": "merge"|"promote", "red": node|None, "blue": node, "red_visits": int, "blue_visits": int, "tests": [(symbol, p_red, p_blue)], "bound": float}`, with visits and probabilities captured *before* the fold. `tests` includes `"#"` for termination; a promote carries the test against the last red state it was compared with (the one shown failing). Nodes are identified to the PTA copy by their path of symbols from the root (`"path": tuple[str]`, also in the dict), since merging rewires the live nodes.
  - `WindowedFrequencyScorer.score_terms(trace, when) -> tuple[list[tuple[float, float, float, float]], list[tuple[float, int]]]`: per-visited-state terms and the `(when, key)` visits expired before scoring. `score()` becomes `sum(map(sum, terms))` over `score_terms`, so the arithmetic exists once.
  - `frequency_cutoff(holdout_scores: np.ndarray, quantile=BENIGN_QUANTILE) -> float`: `np.nanquantile(scores, 1 - quantile)` (high scores flag here, unlike `score_cutoff`).

- [ ] **Step 1: Write failing tests** in `StateMachineChecks`:
  - `test_learn_trace_does_not_change_the_machine`: same traces learned with and without `trace=[]` give equal `n_states` and equal sorted `(state_index, symbol, prob)` triples.
  - `test_learn_trace_records_pta_then_steps`: first event kind is `"pta"`; every later kind is in `{"merge", "promote"}`; `1 + promotes == pdfa.n_states`.
  - `test_learn_trace_bound_matches_hoeffding`: every merge step's `bound == statemachine._hoeffding(step["red_visits"], step["blue_visits"])`, and every merge step has all `abs(p_red - p_blue) < bound`.
  
  And in `WindowedScorerChecks`:
  - `test_score_terms_sum_to_score`: for every trace in a stream, `sum(map(sum, terms))` from one scorer equals `score()` from a twin scorer exactly (`assertEqual`, not almost).
  - `test_score_terms_report_expiry`: with `forget_seconds=2.0`, scoring at t=0 then t=5 reports the t=0 visits as expired at t=5 and none at t=0.
  - `test_frequency_cutoff_flags_top_budget`: `frequency_cutoff(np.arange(100.0))` is `np.quantile(np.arange(100.0), 0.95)`; NaNs are ignored.
- [ ] **Step 2:** Run `.venv/bin/python -m unittest tests.StateMachineChecks tests.WindowedScorerChecks`. Expected: the six new tests fail (unexpected keyword / no attribute).
- [ ] **Step 3:** Implement. In `learn_pdfa`, compute `tests` with the same loop `_compatible` uses (factor that loop into `_frequency_tests(node1, node2) -> list[(symbol, p1, p2)]` and have `_compatible` call it, so the test the page shows is the test that ran). Deep-copy the PTA with an iterative copier (recursion depth is only `TRACE_LEN`, so `copy.deepcopy` on `_Node` is acceptable).
- [ ] **Step 4:** Run the full suite: `.venv/bin/python -m unittest tests`. Expected: all pass, including the existing bit-identical windowed test.
- [ ] **Step 5: Commit** `feat(statemachine): record ALERGIA steps and SEQUENT terms for visualization`.

### Task 2: Infer the cluster topology from the captures

**Files:**
- Create: `Threat_Detection/cluster.py`
- Test: `Threat_Detection/tests.py` (`ClusterChecks`)

**Interfaces:**
- Consumes: `data_io.level_from_label`; packet frames with `src_ip, dst_ip, src_port, dst_port, proto`.
- Produces: `infer_cluster(captures: dict[str, pd.DataFrame]) -> dict` matching the bundle's `cluster` schema. `captures` maps capture label (`"pod-nginx"`, `"node-child1"`, `"router-any"`, …) to that label's benign packet frame.

Rules (each is one test):
- Pod IP = address in `POD_CIDR` (`10.42.0.0/16`); host pod CIDR = its `/24`. Service = address in `SERVICE_CIDR` (`10.43.0.0/16`). Host = RFC1918 address outside those two that appears as an endpoint of traffic on ports in `WELL_KNOWN_PORTS` or exchanges traffic with another host. Everything else (loopback excluded) is `external`.
- A pod-level capture names the pod whose IP is the most frequent pod-CIDR address in it.
- A node-level capture's host is the most frequent host IP in it; the pod `/24` most frequent in that capture is assigned to that host. A `/24` no capture claims stays `host: null` and is drawn in an "unattributed" lane.
- Host roles: `control-plane` if it serves 6443 or 2379; `nfs` if it serves 2049; `worker` otherwise.
- Router vantages attach to the overlay (`router-flannel`) or the uplink (`router-any`) by label suffix.
- Edges aggregate packets by unordered endpoint pair over all captures; `ports` lists the well-known names of the lower port seen.

- [ ] **Step 1: Write failing tests** with small synthetic frames (no dataset needed): `test_pod_named_from_pod_capture`, `test_node_capture_claims_pod_subnet`, `test_control_plane_from_apiserver_port`, `test_unclaimed_subnet_is_unattributed`, `test_loopback_is_ignored`, `test_router_vantages_attach_by_suffix`, `test_vantage_without_pods_still_builds` (only `router-any` given → pods list may be empty, `vantages` has one entry, no exception).
- [ ] **Step 2:** Run `.venv/bin/python -m unittest tests.ClusterChecks`. Expected: fail, `No module named 'cluster'`.
- [ ] **Step 3:** Implement with `ipaddress`; ids are stable strings (`host:192.168.50.32`, `pod:10.42.0.56`).
- [ ] **Step 4:** Run the class, then smoke-test on the real dataset: load every benign `tcp` capture from the manifest with `statemachine.load_flow_packets`, call `infer_cluster`, and print host/pod/vantage counts. Expected: more than one host, `10.42.0.0/24` and `10.42.3.0/24` among pod CIDRs, one control-plane host.
- [ ] **Step 5: Commit** `feat(cluster): infer k3s topology from capture traffic`.

### Task 3: Deterministic layouts for the PTA icicle and the PDFA graph

**Files:**
- Create: `Threat_Detection/layout.py`
- Test: `Threat_Detection/tests.py` (`LayoutChecks`)

**Interfaces:**
- Consumes: `statemachine._Node`, `statemachine.PDFA`, `statemachine.pdfa_states_in_order`.
- Produces:
  - `icicle(root: _Node) -> list[dict]`: BFS order, each `{"id", "parent", "symbol", "visits", "depth", "x0", "x1"}`, `x0/x1` in `[0, 1]`, children laid out left-to-right by sorted symbol, widths proportional to child visits within the parent's span.
  - `layered(pdfa: PDFA, node_ids: dict[int, int] | None = None) -> dict`: `{"states": [{"id", "visits", "x", "y"}], "edges": [{"src", "dst", "symbol", "prob"}]}`; `x` = BFS depth normalized to `[0, 1]`; `y` within each column from 4 sweeps of barycenter ordering, normalized to `[0, 1]`; ties broken by state id.
  - `pta_to_pdfa_map(steps, pta_ids) -> dict[pdfa_state_id, list[pta_id]]` so a final state can highlight the PTA nodes merged into it.

- [ ] **Step 1: Write failing tests:** `test_icicle_children_tile_parent` (children's spans sum to the parent's span within 1e-12 when parent.visits equals the sum of children's visits plus finals — use `final` share as an empty tail), `test_icicle_is_deterministic`, `test_layered_root_is_leftmost`, `test_layered_is_deterministic` (two calls, equal output), `test_layered_coordinates_in_unit_square`, `test_layered_has_every_transition` (edge count equals `sum(len(out) for _, out in pdfa.probs.values())`).
- [ ] **Step 2:** Run `.venv/bin/python -m unittest tests.LayoutChecks`. Expected: fail, no module.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/python -m unittest tests`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(layout): icicle and layered layouts for the state machine`.

### Task 4: Build the story bundle

**Files:**
- Create: `Threat_Detection/story.py`
- Test: `Threat_Detection/tests.py` (`StoryBundleChecks`)

**Interfaces:**
- Consumes: Task 1 (`learn_pdfa(..., trace=)`, `score_terms`, `frequency_cutoff`), Task 2 (`infer_cluster`), Task 3 (`icicle`, `layered`, `pta_to_pdfa_map`); existing `make_flows`, `segment_flows`, `split_flows`, `fit_percentile`, `encode`, `make_traces`, `score_flows`, `score_cutoff`, `trace_states`, `FrequencyScorer`, `detectors.persistent_mask`.
- Produces:
  - `build_story(benign: pd.DataFrame, targets: dict[str, pd.DataFrame], cluster_captures: dict[str, pd.DataFrame], vantage: str, forget_seconds=FORGET_SECONDS) -> dict` (the schema above). `targets` maps scenario name → attack packet frame for the same vantage; held-out benign is always added first as `"benign (held out)"`.
  - `to_json(story: dict) -> str`: replaces non-finite floats with `None` and rounds floats to 4 decimals.
  - `MAX_STEP_DETAIL = 400`.

Notes the implementer cannot infer:
- Fit exactly as `statemachine_rows` does (segment, split, `fit_model`) but learn through `learn_pdfa(traces, trace=events)` so the recorded PDFA is the scored PDFA; assert `n_states` equality in a test.
- Windowed cutoff = `frequency_cutoff` over the held-out benign windowed per-window maxima (as `frequency_scores_by_window` computes them), so both detectors run at the same 5 % benign budget.
- `alert` uses `detectors.persistent_mask` with `PERSISTENCE_WINDOW`; `released` is the first unflagged window after an alert run.
- `flows` per trace maps each flow's `(src_ip, dst_ip)` to cluster ids via the cluster's IP index; unknown IPs map to `external:<ip>`.
- One windowed scorer and one cumulative scorer per capture, fed in time order — not one per chunk.

- [ ] **Step 1: Write failing tests** on synthetic packet frames (a benign stream of repeating flows and an attack stream with a 3 s burst of a new flow type, then quiet):
  - `test_bundle_scores_match_pipeline`: per-window max of the bundle's `windowed` equals `frequency_scores_by_window(model, flows, t0, n, FORGET_SECONDS)` (NaN-aware equal).
  - `test_bundle_likelihood_matches_score_flows`.
  - `test_replaying_expiry_reconstructs_counts`: replaying visits (+1 per state in `states`) and expiries (−1 per `expired`) gives, at the last trace, the same counts a fresh `WindowedFrequencyScorer` holds after the stream.
  - `test_burst_alerts_then_releases`: the attack capture has at least one `alert` window and a later `released` window; the cumulative score at the last trace is above the windowed cutoff (forgetting matters).
  - `test_json_has_no_nonfinite`: `json.loads(to_json(story))` succeeds with `parse_constant` raising on `NaN`/`Infinity`.
  - `test_all_unseen_attack_falls_off_first_symbol`: an attack with only new symbols yields `fell_off_at == 0` on every trace and finite likelihoods.
  - `test_step_detail_is_capped`: with `MAX_STEP_DETAIL` patched to 2, `len(steps) == 2` and `learning["steps_total"]` holds the real count.
- [ ] **Step 2:** Run `.venv/bin/python -m unittest tests.StoryBundleChecks`. Expected: fail, no module.
- [ ] **Step 3:** Implement `build_story`, `to_json`.
- [ ] **Step 4:** Run `.venv/bin/python -m unittest tests`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(story): build the state-machine story bundle from the pipeline`.

### Task 5: The renderer — Acts 1 and 2

**Files:**
- Create: `Threat_Detection/story_template/index.html`, `story.css`, `story.js`, `vendor/d3.v7.9.0.min.js`
- Modify: `Threat_Detection/story.py` (add `write_html`)
- Test: `Threat_Detection/tests.py` (`StoryBundleChecks.test_html_is_self_contained`)

**Interfaces:**
- Consumes: the bundle schema; `window.STORY` set by an inline `<script>` that `write_html` injects in place of the `/*__STORY__*/` marker; D3 injected in place of `/*__D3__*/`.
- Produces: `write_html(story: dict, path=None) -> Path` writing `outputs/statemachine_story.html`; JS modules `renderCluster(svg, cluster, {focus})`, `renderLearning(svg, learning)`, `renderDetection(svg, story)` (Task 6), and a shared `narrate(text)` side-panel helper.

- [ ] **Step 1: Write the failing test** `test_html_is_self_contained`: the written file contains no `src="http`, no `href="http`, contains `window.STORY =`, and is under 15 MB for the synthetic story.
- [ ] **Step 2:** Run it. Expected: fail, no `write_html`.
- [ ] **Step 3:** Vendor D3: download `https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js` once into `vendor/` (commit it; note its sha256 in a comment at the top of `story.js`). Implement `write_html`.
- [ ] **Step 4:** Implement Act 1 per the Design: hosts as rounded rects sized by pod count, pods packed with `d3.pack` inside each host, an unattributed lane, services and external as a side column, the overlay band, tap icons per vantage, edges as curved links. Layout from data only: hosts arranged in a row ordered control-plane first then by IP.
- [ ] **Step 5:** Implement Act 2 per the Design: symbol-stream chips, icicle from `pta` (`x0/x1` × width, depth × row height), step scrubber with the Hoeffding bar chart, merge fold animation (blue rect scales into the red rect's column, 400 ms), promote color change, then cross-fade to the layered PDFA (`states.x/y` × canvas). Narration text is generated from step fields.
- [ ] **Step 6:** Generate a real page: `.venv/bin/python story.py` (CLI lands in Task 7; for now a `__main__` guard calling `main()` with defaults is fine). Open `outputs/statemachine_story.html` in the browser pane at 1280×720 and 1920×1080; screenshot Act 1 and three points in Act 2. Expected: no console errors, no overlapping labels on hosts/pods, icicle and PDFA readable. Fix what the screenshots show before committing.
- [ ] **Step 7: Commit** `feat(story): cluster and learning acts`.

### Task 6: The renderer — Act 3 detection playback

**Files:**
- Modify: `Threat_Detection/story_template/story.js`, `story.css`

**Interfaces:**
- Consumes: `playback.captures[*]`, `learning.pdfa`, `cluster`, `meta.forget_seconds`, `meta.persistence`.
- Produces: `renderDetection(svg, story)`; a single `Player` object with `play()`, `pause()`, `seek(t)`, `setSpeed(x)`, `setCapture(i)`; every view subscribes to `player.on("tick", t => …)`.

- [ ] **Step 1:** Implement the player clock from `requestAnimationFrame`, mapping wall time × speed to capture seconds; `seek` rebuilds window state by replaying `states`/`expired` from 0 (same replay `test_replaying_expiry_reconstructs_counts` proves), cached every 5 s of capture time so scrubbing is instant.
- [ ] **Step 2:** Machine view: token walk along `states`, ✕ at `fell_off_at`; visit-tick rings with age-driven arc length `1 − (t − t_visit) / forget_seconds`; state fill from the windowed count / training-visits ratio on `d3.interpolateYlOrRd` (log scale, domain from the bundle's max).
- [ ] **Step 3:** Global anomaly clock: a bracket `[t − forget_seconds, t]` on the time axis; visits leaving the bracket fall out with a short fade, synchronized with the ring ticks vanishing.
- [ ] **Step 4:** Score strip: three lines (likelihood with its cutoff; windowed with its cutoff; cumulative dashed), flagged windows shaded, alert badge and "released" marker from `windows`. Score breakdown stacked bar on hover from `terms`.
- [ ] **Step 5:** Cluster inset: reuse `renderCluster` at small scale; pulse `flows` edges for the current trace; tap glow colored by flag state.
- [ ] **Step 6:** Verify in the browser pane on the real `pod-lidar` story at 1280×720: play the lidar attack at 4×, screenshot (a) mid-burst with an alert badge, (b) after release with the cumulative ghost still high, (c) a fall-off ✕. Check the console is clean and the frame rate holds (`performance.now()` deltas logged under `?debug`). Fix what the screenshots show.
- [ ] **Step 7: Commit** `feat(story): detection playback with anomaly clock and forgetting`.

### Task 7: CLI, demo menu, README

**Files:**
- Modify: `Threat_Detection/story.py` (`main`), `Threat_Detection/demo.py` (`ITEMS`), `Threat_Detection/README.md`
- Test: `Threat_Detection/tests.py` (`DemoMenuChecks` or the existing menu test, whichever covers `ITEMS`)

**Interfaces:**
- Consumes: `data_io.load_manifest`, `data_io.load_capture`-style readers (`statemachine.load_flow_packets` for flow columns), `local_paths.KUBEDATA_ROOT`.
- Produces: `story.main()` with `--vantage` (default `pod-lidar`), `--method` (default `tcp`), `--scenarios` (default all non-benign in the manifest), `--forget` (default `FORGET_SECONDS`), `--out` (default `statemachine_story.html`). `demo.py` item 10 `("Story", story_page, "the state machine learned and replayed, as an interactive page")` appended after Tests so existing item numbers (`demo.py 3` etc.) keep their meaning.

- [ ] **Step 1: Write the failing test** `test_story_is_menu_item_10`: `demo.ITEMS[9][0] == "Story"` and items 1–9 are unchanged by name.
- [ ] **Step 2:** Run it. Expected: fail (IndexError).
- [ ] **Step 3:** Implement `main()` and `demo.story_page()` (lazy `import story; story.main_with(local_paths.KUBEDATA_ROOT)`); cluster captures are every benign capture of the chosen method from the manifest, skipping `usable == False`.
- [ ] **Step 4:** Run `.venv/bin/python demo.py 10`, then `.venv/bin/python story.py --vantage pod-nginx`. Expected: both write the page and print its path and size; both pages open cleanly in the browser pane.
- [ ] **Step 5:** README: one row in "The experiments" table for `story.py`, one row for `cluster.py`/`layout.py` under Layers, item 10 in the menu listing, and the run line.
- [ ] **Step 6:** Run `.venv/bin/python -m unittest tests`. Expected: all pass (the README's test count line updated to the new number).
- [ ] **Step 7: Commit** `feat(demo): state-machine story as menu item 10`.
