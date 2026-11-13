// The live monitor's dashboard. It owns no state of its own: /api/state is the snapshot
// (what is running, every tap's state and machine, attacks) and /api/stream brings what
// happens after it (windows, alerts, tap changes), resumed by sequence number on reconnect.
// Vendored D3: d3js.org v7.9.0
(() => {
"use strict";
const SPAN = 180;            // seconds of history the charts show
const KEEP = 330;            // seconds of windows kept in the page
const MAP_SPAN = 30;         // seconds of conversations the map draws
const TEXT_KEY = "rtct.mapText";   // the reader's choice of map label size, kept between visits
const textScale = value => Math.min(1.6, Math.max(0.8, Math.round(value * 10) / 10));
let TEXT_SCALE = textScale(storedText());
let mapHover = false;         // the pointer is over the map, so its layout holds still

function storedText() {
  try { return Number(localStorage.getItem(TEXT_KEY)) || 1; } catch (e) { return 1; }
}
const tip = d3.select("#tooltip");
const fmt = d3.format(",");
const f1 = d3.format(".1f");
const pct = d3.format(".0%");
const hhmmss = d3.timeFormat("%H:%M:%S");
const esc = value => String(value ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clock = seconds => {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

// a window's verdict, and a tap's own condition when it has none to give
const CODE = { alert: "var(--critical)", flagged: "var(--warning)", unseen: "var(--serious)", released: "var(--good)",
  normal: "var(--good)", warmup: "var(--grid)", learning: "var(--grid)", nodata: "none" };
const VERDICT = {
  alert: { cls: "critical", text: "Alert" }, flagged: { cls: "warning", text: "Flagged" },
  unseen: { cls: "serious", text: "Unseen behaviour" }, nodata: { cls: "", text: "No trace" },
  warmup: { cls: "", text: "Warming up" }, released: { cls: "good", text: "Released" },
  normal: { cls: "good", text: "Normal" }, learning: { cls: "", text: "Learning" } };
const CONDITION = {
  starting: { cls: "", text: "Starting" }, stalled: { cls: "warning", text: "Stalled" },
  failed: { cls: "critical", text: "Not running" }, ended: { cls: "", text: "Ended" } };

const st = { info: null, infoSeq: 0, skew: 0, boot: null, seq: 0, taps: new Map(), windows: new Map(), attacks: [], events: [],
  names: new Map(), selected: null, error: null, busy: null, record: false, attackSeconds: 30, learnSeconds: 60,
  refreshAt: 0, refreshTimer: null, frame: null, mapSig: null, mapAt: 0, map: null };

// ---------------------------------------------------------------- server

async function api(path, body) {
  const init = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, init);
  let out = null;
  try { out = await res.json(); } catch (e) { throw new Error(`${res.status} ${res.statusText}`); }
  if (!res.ok || (out && out.error)) throw new Error((out && out.error) || res.statusText);
  return out;
}

function take(info) {
  st.info = info;
  st.infoSeq = info.seq;                       // the snapshot already holds every event up to here
  st.skew = info.now - Date.now() / 1000;      // server clock minus ours
  st.learnSeconds = st.learnSeconds || info.learn_default;
  const taps = new Map();
  for (const tap of info.taps) taps.set(tap.label, tap);
  st.taps = taps;
  st.attacks = info.attacks.map(a => ({ scenario: a.scenario, start: a.started, planned: a.started + a.seconds, end: a.ended ?? null }));
  st.names = new Map();
  const inv = info.inventory;
  if (inv) {
    for (const n of inv.nodes) if (n.ip) st.names.set(n.ip, `node ${n.name}`);
    for (const x of inv.services) st.names.set(x.ip, `service ${x.name}`);
    for (const p of inv.pods) if (p.ip && !p.host_network) st.names.set(p.ip, p.app);
  }
  if (!st.selected || !taps.has(st.selected)) {
    const first = info.taps.find(t => t.watching) || info.taps[0];
    st.selected = first ? first.label : null;
  }
}

async function refresh(fresh = false) {
  st.refreshAt = Date.now();
  try {
    take(await api(`/api/state${fresh ? "?fresh=1" : ""}`));
    st.error = null;
  } catch (e) { st.error = e.message; }
  renderAll();
}

function refreshSoon() {
  if (st.refreshTimer) return;
  st.refreshTimer = setTimeout(() => { st.refreshTimer = null; refresh(); }, Math.max(0, 400 - (Date.now() - st.refreshAt)));
}

async function act(label, path, body) {
  st.busy = label; st.error = null; banner();
  try { take(await api(path, body || {})); } catch (e) { st.error = e.message; }
  st.busy = null;
  renderAll();
}

function connect() {
  const es = new EventSource("/api/stream");
  es.onmessage = e => onEvent(JSON.parse(e.data));
  // EventSource reconnects by itself and says where it was (Last-Event-ID); the server resumes from there
}

function onEvent(ev) {
  if (ev.kind === "hello") {
    if (!ev.resumed) {            // a first connection, or a restarted server: what follows is everything
      st.windows = new Map(); st.events = []; st.seq = 0;
      if (st.boot && st.boot !== ev.boot) refreshSoon();
    }
    st.boot = ev.boot;
    return;
  }
  if (ev.seq <= st.seq) return;
  st.seq = ev.seq;
  const recent = Date.now() / 1000 + st.skew - ev.at < 5;
  if (ev.kind === "window") {
    const rows = st.windows.get(ev.label) || [];
    rows.push(ev);
    while (rows.length && rows[0].wall < ev.wall - KEEP) rows.shift();
    st.windows.set(ev.label, rows);
  } else {
    st.events.push(ev);
    if (st.events.length > 300) st.events.shift();
    if (ev.seq <= st.infoSeq) { /* history: for the log only, the snapshot is newer */ }
    else if (ev.kind === "tap") {
      const tap = st.taps.get(ev.label);
      if (!tap) { if (recent) refreshSoon(); }
      else if (ev.state === null) Object.assign(tap, { watching: false, state: null, error: null, learning: null });
      else Object.assign(tap, { watching: true, state: ev.state, error: ev.error, ready: ev.ready, learning: ev.learning,
                                learn_error: ev.learn_error, restarts: ev.restarts, alert_since: ev.alert_since });
      if (recent) structure();
    } else if (ev.kind === "attack") {
      if (ev.phase === "start") st.attacks.push({ scenario: ev.scenario, start: ev.wall, planned: ev.wall + ev.seconds, end: null });
      else { const a = [...st.attacks].reverse().find(x => x.scenario === ev.scenario && x.end === null); if (a) a.end = ev.wall; }
      if (recent) refreshSoon();
    } else if ((ev.kind === "started" || ev.kind === "stopped") && recent) refreshSoon();
  }
  if (!st.frame) st.frame = requestAnimationFrame(() => { st.frame = null; live(); log(); });
}

// ---------------------------------------------------------------- reading the state

const serverNow = () => Date.now() / 1000 + st.skew;
// a replayed recording runs on its own clock (faster than ours, and it ends): charts follow the stream
function now() {
  if (st.info && st.info.finite) {
    let latest = 0;
    for (const rows of st.windows.values()) if (rows.length) latest = Math.max(latest, rows[rows.length - 1].wall + 1);
    if (latest) return latest;
  }
  return serverNow();
}
const watched = () => [...st.taps.values()].filter(t => t.watching);
const lastWindow = label => { const rows = st.windows.get(label); return rows && rows.length ? rows[rows.length - 1] : null; };

// what to say about a tap right now: its own condition first, then its latest verdict
function verdict(label) {
  const tap = st.taps.get(label);
  if (!tap || !tap.watching) return null;
  if (CONDITION[tap.state] && tap.state !== "ended") return { ...CONDITION[tap.state], key: tap.state };
  const last = lastWindow(label);
  if (tap.state === "ended") return { ...CONDITION.ended, key: last ? last.status : "ended" };
  if (!last) return { ...(tap.ready ? CONDITION.starting : VERDICT.learning), key: tap.ready ? "starting" : "learning" };
  return { ...VERDICT[last.status], key: last.status };
}
const dotColor = label => {
  const v = verdict(label);
  return !v ? null : v.key === "failed" ? "var(--critical)" : v.key === "stalled" ? "var(--warning)" : CODE[v.key] || null;
};
const nameOf = ip => st.names.get(ip) || ip;

function why(label) {
  const tap = st.taps.get(label), last = lastWindow(label), r = tap && tap.ready;
  if (!tap || !tap.watching) return "Not watched. Watch it to learn its normal traffic and score it every second.";
  if (tap.state === "failed") return tap.error || "Its capture stopped; it will be restarted.";
  if (tap.state === "stalled") return `${tap.error || "No window lately"}: a live tap closes a window every second, traffic or not, so its capture has stopped answering. It is restarted if this goes on.`;
  if (tap.state === "starting") return "Its capture and its scoring process are starting.";
  if (!r) return tap.learn_error ? `No machine yet: ${tap.learn_error}`
    : "No machine yet: its traffic is being taken as benign and learned from. Windows are counted, not judged, until that is done.";
  if (!last) return "No window scored yet: its first seconds are still inside the lateness wait.";
  const ended = tap.state === "ended" ? "The recording has ended. Its last window: " : "";
  const text = last.status === "alert" ? `${r.persistence} or more windows in a row above the cutoff: a sustained alert. This window's score ${f1(last.peak)} is over ${f1(last.cutoff)}.`
    : last.status === "flagged" ? `Score ${f1(last.peak)} is over the cutoff ${f1(last.cutoff)}; it becomes an alert if ${r.persistence} windows in a row stay over it.`
    : last.status === "unseen" ? `Score ${f1(last.peak)} is under the cutoff, but a trace fell below the likelihood cutoff: something benign never did.`
    : last.status === "warmup" ? `The ${r.forget_seconds} s clock is not full yet, so scores are low by construction: quiet here is not evidence of normal.`
    : last.status === "nodata" ? "No trace ended in this second: no verdict either way."
    : last.status === "released" ? `An alert just ended: ${r.clear_windows} clean windows in a row since the last flag.`
    : last.status === "learning" ? "Counted, not judged: the machine is still being learned."
    : `Score ${f1(last.peak)} is under the cutoff ${f1(last.cutoff)}.`;
  return ended + text;
}

// ---------------------------------------------------------------- the frame around everything

function header() {
  const info = st.info, n = watched().length;
  d3.select("#subtitle").text(!info ? "looking for a cluster …"
    : !info.profile ? "no cluster running"
    : `${info.provider === "replay" ? "replaying recordings" : `${info.profile} cluster`} · `
      + (n ? `watching ${n} tap${n === 1 ? "" : "s"} · ${clock(serverNow() - info.monitor_started)}${info.recording ? " · recording packets" : ""}` : "not watching"));
}

function banner() {
  const info = st.info, parts = [];
  if (st.error) parts.push(`<div class="note error">${esc(st.error)}</div>`);
  if (st.busy) parts.push(`<div class="note busy">${esc(st.busy)} …</div>`);
  if (info && !info.profile) {
    const unready = info.clusters.map(c => `${esc(c.cluster)} exists but is not ready`).join("; ");
    parts.push(`<div class="note">No local cluster is running. Start one from <span class="mono">Threat_Detection</span>, or replay a recording:
      <pre class="mono">.venv/bin/python localcluster/collect.py up --profile general
.venv/bin/python live/serve.py --replay &lt;capture.pcap&gt; --speed 10</pre>${unready ? `<div>${unready}</div>` : ""}</div>`);
  }
  d3.select("#banner").html(parts.join(""));
}

function actions() {
  const info = st.info, box = d3.select("#actions");
  if (!info || !info.profile) return box.html(`<button id="a-refresh">Look again</button>`).select("#a-refresh").on("click", () => refresh(true));
  const n = watched().length, defaults = info.taps.filter(t => t.default && !t.watching).map(t => t.label);
  box.html(n ? `<button id="a-stop" ${st.busy ? "disabled" : ""}>Stop all</button>`
    : `<label class="check" title="Also write each tap's packets to the session folder as a pcap"><input type="checkbox" id="a-record" ${st.record ? "checked" : ""}> Record packets</label>
       <button class="primary" id="a-start" ${st.busy || !defaults.length ? "disabled" : ""}>Watch ${defaults.length} tap${defaults.length === 1 ? "" : "s"}</button>`);
  box.select("#a-record").on("change", function () { st.record = this.checked; });
  box.select("#a-start").on("click", () => act("Starting the taps", "/api/taps/start", { taps: defaults, record: st.record }));
  box.select("#a-stop").on("click", () => act("Stopping", "/api/taps/stop", {}));
}

// ---------------------------------------------------------------- charts

// One tap's score against its cutoff over the last SPAN seconds, with the status band under
// it and attacks shaded. The elements are made once and moved, so a tick costs attributes only.
function drawChart(sel, label, { h = 46, big = false } = {}) {
  const node = sel.node();
  if (!node) return;
  const width = Math.max(220, node.parentNode.clientWidth);
  const band = big ? 12 : 7, left = big ? 36 : 2, right = 62, top = big ? 10 : 4, axis = big ? 20 : 0;
  sel.attr("width", width).attr("height", top + h + band + 4 + axis);
  if (sel.select("path.score").empty()) {
    for (const cls of ["spans", "axis y", "axis x", "band"]) sel.append("g").attr("class", cls);
    sel.append("line").attr("class", "cut");
    sel.append("path").attr("class", "score");
    sel.append("circle").attr("class", "now-dot").attr("r", big ? 4 : 2.5);
    sel.append("text").attr("class", "lbl peak-label");
    sel.append("text").attr("class", "lbl cut-label");
  }
  const t1 = now(), t0 = t1 - SPAN;
  const x = d3.scaleLinear().domain([t0, t1]).range([left, width - right]);
  const data = (st.windows.get(label) || []).filter(w => w.wall >= t0);
  const tap = st.taps.get(label), last = data[data.length - 1];
  const cutoff = tap && tap.ready ? tap.ready.cutoff : null;
  const peaks = data.filter(w => w.peak != null).map(w => w.peak);
  const hi = Math.max(cutoff || 1, d3.max(peaks) || 1) * 1.08, lo = Math.min(cutoff || 0, d3.min(peaks) ?? 0) * 0.9;
  const y = d3.scaleLinear().domain([lo, hi]).range([top + h - 3, top + 2]);
  const spans = st.attacks.map(a => ({ ...a, x0: x(Math.max(a.start, t0)), x1: x(Math.min(a.end ?? Math.min(serverNow(), a.planned), t1)) }))
    .filter(a => a.x1 > left);
  sel.select(".spans").selectAll("rect").data(spans).join("rect").attr("class", "attack-span")
    .attr("x", a => a.x0).attr("y", top).attr("width", a => Math.max(a.x1 - a.x0, 1)).attr("height", h + band + 2);
  sel.select(".spans").selectAll("text").data(big ? spans : []).join("text").attr("class", "attack-label")
    .attr("x", a => a.x0 + 4).attr("y", top + 11).text(a => a.scenario);
  sel.select(".cut").style("display", cutoff == null ? "none" : null)
    .attr("x1", left).attr("x2", width - right).attr("y1", y(cutoff || 0)).attr("y2", y(cutoff || 0));
  sel.select(".score").attr("d", d3.line().defined(w => w.peak != null).x(w => x(w.wall + 0.5)).y(w => y(w.peak))(data));
  sel.select(".band").selectAll("rect").data(data, w => w.seq).join("rect")
    .attr("x", w => x(w.wall)).attr("width", w => Math.max(x(w.wall + 1) - x(w.wall) - 0.5, 0.5))
    .attr("y", top + h + 2).attr("height", band).attr("fill", w => CODE[w.status] || "none");
  const scored = last && last.peak != null;
  sel.select(".now-dot").style("display", scored ? null : "none")
    .attr("cx", scored ? x(last.wall + 0.5) : 0).attr("cy", scored ? y(last.peak) : 0);
  // the score and the cutoff read out at the right edge, pushed apart when they would collide
  const yPeak = scored ? y(last.peak) + 4 : null;
  let yCut = cutoff != null ? y(cutoff) + 4 : null;
  if (yPeak != null && yCut != null && Math.abs(yPeak - yCut) < 12) yCut = yPeak + (yCut >= yPeak ? 12 : -12);
  sel.select(".peak-label").style("display", yPeak == null ? "none" : null).attr("x", width - right + 6).attr("y", yPeak || 0).text(scored ? f1(last.peak) : "");
  sel.select(".cut-label").style("display", yCut == null ? "none" : null).attr("x", width - right + 6)
    .attr("y", yCut == null ? 0 : Math.min(Math.max(yCut, 10), top + h + 8)).text(cutoff != null ? `cut ${f1(cutoff)}` : "");
  if (big) {
    sel.select(".axis.y").attr("transform", `translate(${left},0)`).call(d3.axisLeft(y).ticks(4));
    sel.select(".axis.x").attr("transform", `translate(0,${top + h + band + 4})`)
      .call(d3.axisBottom(x).ticks(6).tickFormat(t => `-${Math.round(t1 - t)} s`));
  }
}

// ---------------------------------------------------------------- taps

const machineNote = tap => tap.machine === "saved" ? "has a learned machine"
  : tap.machine === "recording" ? "will learn from its benign recording"
  : `will learn from its first ${st.info.learn_default} s`;

function strips() {
  const info = st.info, host = d3.select("#strips");
  const taps = info && info.profile ? [...st.taps.values()] : [];
  d3.select("#taps-sub").text(taps.length ? `last ${SPAN / 60} minutes · score against cutoff` : "");
  d3.select(host.node().parentNode).style("display", info && info.profile ? null : "none");
  if (!taps.length) return host.html(info && info.profile ? `<p class="muted">This cluster has no capture taps.</p>` : "");
  host.selectAll("p").remove();
  // a row is rebuilt when a tap starts or stops being watched; otherwise only its contents move
  const rows = host.selectAll("div.strip").data(taps, t => `${t.label}:${t.watching ? "on" : "off"}`);
  rows.exit().remove();
  const made = rows.enter().append("div").attr("class", t => `strip ${t.watching ? "" : "idle"}`).attr("data-tap", t => t.label);
  made.each(function (t) {
    const row = d3.select(this);
    row.append("div").attr("class", "strip-info").html(t.watching
      ? `<b></b><span><span class="pill"><i></i><span class="pill-text"></span></span></span><span class="meta"></span>`
      : `<b></b><span class="meta">${esc(t.level)} tap</span>`);
    row.select("b").text(t.label);
    if (t.watching) {
      const chart = row.append("div").attr("class", "strip-chart");
      chart.append("svg").attr("class", "chart");
      chart.append("button").attr("class", "small x").text("Stop").on("click", event => {
        event.stopPropagation();
        act(`Stopping ${t.label}`, "/api/taps/stop", { taps: [t.label] });
      });
      row.on("click", () => select(t.label));
    } else {
      row.append("span").attr("class", "meta t2").text(machineNote(t));
      row.append("button").attr("class", "small").text("Watch")
        .on("click", () => act(`Starting ${t.label}`, "/api/taps/start", { taps: [t.label], record: st.record }));
    }
  });
  host.selectAll("div.strip").sort((a, b) => taps.indexOf(a) - taps.indexOf(b));
  const any = watched().length;
  d3.select("#taps-actions").html(any ? `<button class="small" id="t-learn" title="Take the next ${st.learnSeconds} s of every watched tap's traffic as benign and learn from it. Nothing restarts.">Re-learn all</button>` : "")
    .select("#t-learn").on("click", () => act("Asking every tap to re-learn", "/api/learn", { seconds: st.learnSeconds }));
  stripsLive();
}

function stripsLive() {
  d3.selectAll("#strips .strip").each(function (t) {
    const tap = st.taps.get(t.label) || t, row = d3.select(this);
    row.classed("selected", t.label === st.selected);
    if (!tap.watching) return;
    const v = verdict(t.label) || VERDICT.learning, last = lastWindow(t.label);
    row.select(".pill").attr("class", `pill ${v.cls}`);
    row.select(".pill-text").text(v.text);
    const bad = tap.state === "failed" || tap.state === "stalled";
    row.select(".strip-info .meta").classed("bad", bad).text(bad ? (tap.error || "")
      : tap.learning ? learningText(tap)
      : last ? `${fmt(last.packets)} pkt/s · lag ${f1(Math.max(last.lag, 0))} s${last.behind ? " · behind" : ""}` : "");
    drawChart(row.select("svg.chart"), t.label);
  });
}

function learningText(tap) {
  const job = tap.learning;
  if (job.phase === "fitting") return "learning the machine …";
  const done = job.started ? Math.min(serverNow() - job.started, job.seconds) : 0;
  return `listening ${clock(done)} / ${clock(job.seconds)}`;
}

function select(label) {
  if (label === st.selected) return;
  st.selected = label;
  st.mapSig = null;
  detail(); stripsLive(); drawMap();
}

// ---------------------------------------------------------------- the selected tap

function detail() {
  const box = d3.select("#detail"), tap = st.taps.get(st.selected);
  if (!st.info || !st.info.profile || !tap) return box.html("");
  const r = tap.ready, range = st.info.learn_seconds;
  const choices = [30, 60, 120, 300].filter(n => n >= range[0] && n <= range[1]);
  const source = !r ? "" : r.source === "stream" ? "its own stream" : `<span class="mono" title="${esc(r.source)}">${esc(r.source.split("/").slice(-3).join("/"))}</span>`;
  box.html(`<div class="head"><b>${esc(tap.label)}</b><span class="pill" id="d-pill"><i></i><span id="d-pill-text"></span></span></div>
    <p class="why" id="d-why"></p>
    ${tap.watching ? `<svg class="chart" id="d-chart"></svg><div class="facts" id="d-facts"></div><div id="d-top"></div>` : ""}
    <h4>Its detector</h4>
    ${r ? `<p>Cutoff <b>${f1(r.cutoff)}</b>, learned from ${fmt(r.train_flows)} benign flows of ${source}${r.learned_at ? ` at ${hhmmss(new Date(r.learned_at * 1000))}` : ""}.
        ${pct(r.benign_rate)} of its ${r.held_windows} held-out benign windows sit above the cutoff${r.held_windows < 30 ? "; that is few windows, so a longer listen gives a steadier cutoff" : ""}.</p>
      <p class="muted">Alert after ${r.persistence} flagged windows in a row, release after ${r.clear_windows} clean ones; visits are forgotten after ${r.forget_seconds} s;
        each window is scored ${r.lateness + 1} s after it ends.</p>`
      : `<p>${tap.watching ? "None yet." : esc(machineNote(tap)[0].toUpperCase() + machineNote(tap).slice(1)) + "."}</p>`}
    <div id="d-learn"></div>
    ${tap.watching ? `<div class="row"><button id="d-relearn" ${tap.learning || st.busy ? "disabled" : ""}
        title="Take this tap's next seconds of traffic as benign and learn from it. The old machine keeps scoring until the new one is ready; nothing restarts.">Re-learn from the next</button>
      <select id="d-seconds">${choices.map(n => `<option value="${n}" ${n === st.learnSeconds ? "selected" : ""}>${n} s</option>`).join("")}</select>
      <span class="spacer"></span><button id="d-stop">Stop watching</button></div>`
      : `<div class="row"><button class="primary" id="d-watch">Watch this tap</button></div>`}`);
  box.select("#d-seconds").on("change", function () { st.learnSeconds = +this.value; });
  box.select("#d-relearn").on("click", () => act(`Asking ${tap.label} to re-learn`, "/api/learn", { taps: [tap.label], seconds: st.learnSeconds }));
  box.select("#d-stop").on("click", () => act(`Stopping ${tap.label}`, "/api/taps/stop", { taps: [tap.label] }));
  box.select("#d-watch").on("click", () => act(`Starting ${tap.label}`, "/api/taps/start", { taps: [tap.label], record: st.record }));
  detailLive();
}

// the trace behind the latest flagged window of the last half minute, if there is one
function culprit(label) {
  const rows = st.windows.get(label) || [], floor = now() - 30;
  for (let i = rows.length - 1; i >= 0 && rows[i].wall >= floor; i--) if (rows[i].top) return rows[i];
  return null;
}

function detailLive() {
  const tap = st.taps.get(st.selected);
  if (!tap || d3.select("#d-pill").empty()) return;
  const v = verdict(tap.label) || { cls: "", text: "Not watched" }, last = lastWindow(tap.label);
  d3.select("#d-pill").attr("class", `pill ${v.cls}`);
  d3.select("#d-pill-text").text(v.text);
  d3.select("#d-why").text(why(tap.label));
  if (tap.watching) {
    drawChart(d3.select("#d-chart"), tap.label, { h: 150, big: true });
    d3.select("#d-facts").classed("bad", Boolean(last && last.behind)).text(!last ? ""
      : `${fmt(last.packets)} packets · ${last.flows} whole flows (${last.dropped} cut by the second's edges) · ${last.new_endpoints} new of ${last.endpoints} endpoints`
        + (last.behind ? ` · scoring ${f1(last.lag)} s behind: the tap is not keeping up` : ""));
    const hit = culprit(tap.label);
    d3.select("#d-top").html(hit ? `<h4>Why · the trace behind the peak at ${hhmmss(new Date(hit.wall * 1000))}</h4>
      <div class="chips">${hit.top.symbols.map(s => `<span class="chip">${esc(s)}</span>`).join("")}</div>
      <div class="pairs">${hit.top.pairs.map(([a, b]) => `${esc(nameOf(a))} → ${esc(nameOf(b))}`).join(" · ")}</div>` : "");
  }
  const job = tap.learning;
  d3.select("#d-learn").html(!job ? (tap.learn_error && tap.ready ? `<p class="facts bad">Last re-learn failed: ${esc(tap.learn_error)}</p>` : "")
    : job.phase === "fitting" ? `<p class="facts">Learning the machine from what it heard …</p><div class="prog busy"><i></i></div>`
    : `<p class="facts">Listening: ${esc(learningText(tap).replace("listening ", ""))} of benign traffic${tap.ready ? "; the current machine keeps scoring" : ""}.</p>
       <div class="prog"><i style="width:${(100 * Math.min((serverNow() - (job.started || serverNow())) / job.seconds, 1)).toFixed(1)}%"></i></div>`);
}

// ---------------------------------------------------------------- attacks

function attacks() {
  const info = st.info, box = d3.select("#attacks");
  if (!info || !info.profile || !info.can_attack) return box.html("");
  const any = watched().length, learning = watched().some(t => t.learning);
  const off = info.attack || !any || learning || st.busy;
  box.html(`<h3>Attacks <span class="sub">${!any ? "watch a tap first" : learning ? "wait for learning to finish" : "shaded on every chart"}</span></h3>
    <div class="row"><label class="check">Length <input id="k-seconds" type="number" min="${info.attack_seconds[0]}" max="${info.attack_seconds[1]}" value="${st.attackSeconds}"> s</label></div>
    <div class="row" style="margin-top:8px">${info.scenarios.map(s => `<button class="attack-btn" data-scenario="${esc(s.name)}" ${off ? "disabled" : ""} title="${esc(s.target)}">
      <b>${esc(s.name)}</b><span>${esc(s.kind === "exec" ? s.target : s.target ? "→ " + s.target : "")}</span></button>`).join("")}</div>
    <div class="row" id="k-live" style="margin-top:8px"></div>
    <p class="muted" style="margin-top:8px">Only this cluster's own scenarios, against the local k3d cluster.</p>`);
  box.select("#k-seconds").on("change", function () { st.attackSeconds = +this.value || 30; });
  box.selectAll(".attack-btn").on("click", function () {
    act(`Launching ${this.dataset.scenario}`, "/api/attack", { scenario: this.dataset.scenario, seconds: st.attackSeconds });
  });
  attackLive();
}

function attackLive() {
  const box = d3.select("#k-live"), a = st.info && st.info.attack;
  if (box.empty()) return;
  if (!a) return box.html("");
  const left = Math.max(0, Math.round(a.ends - serverNow()));
  if (box.select("#k-stop").empty()) {
    box.html(`<span class="attack-live"><b>${esc(a.scenario)}</b> running · <span id="k-left"></span> s left</span><button class="small" id="k-stop">Stop attack</button>`);
    box.select("#k-stop").on("click", () => act("Stopping the attack", "/api/attack/stop", {}));
  }
  box.select("#k-left").text(left);
  if (left <= 0 && Date.now() - st.refreshAt > 2500) refresh();
}

// ---------------------------------------------------------------- events

function line(ev) {
  const tap = `<b>${esc(ev.label)}</b>`;
  switch (ev.kind) {
    case "started": return [`Watching ${ev.taps.map(esc).join(", ")}${ev.recording ? ", recording packets" : ""}.`, ""];
    case "stopped": return [`Stopped. Session in <span class="mono">${esc(ev.session)}</span>.`, "dim"];
    case "attack": return [ev.phase === "start" ? `<b>${esc(ev.scenario)}</b> launched for ${ev.seconds} s.`
      : `<b>${esc(ev.scenario)}</b> ${ev.early ? "stopped early" : "ended"}.`, "attack"];
    case "alert": return [`${tap} alert` + (ev.attack ? ` · ${f1(ev.since_start)} s after ${esc(ev.attack)} began` : st.info && st.info.can_attack ? " · no attack running" : ""), "bad"];
    case "release": return [`${tap} released after ${f1(ev.lasted)} s` + (ev.attack && ev.since_end != null ? ` · ${f1(ev.since_end)} s after ${esc(ev.attack)} ended` : ""), "good"];
    case "ready": return [`${tap} learned its machine from ${ev.source === "stream" ? "its own stream" : "a recording"} · cutoff ${f1(ev.cutoff)}`, ""];
    case "learn": return ev.phase === "failed" ? [`${tap} could not learn: ${esc(ev.error)}`, "bad"]
      : ev.phase === "collecting" ? [`${tap} ${ev.extended ? "heard too little, listening longer" : "listening"}: ${ev.seconds} s of traffic taken as benign`, "dim"] : null;
    case "tap": return ev.state === "failed" ? [`${tap} stopped: ${esc(ev.error)}`, "bad"]
      : ev.state === "stalled" ? [`${tap} stalled: ${esc(ev.error)}`, "bad"]
      : ev.state === "ended" ? [`${tap} reached the end of its recording.`, "dim"] : null;
    case "note": return [esc(ev.text), "dim"];
    default: return null;
  }
}

function log() {
  const lines = [];
  for (let i = st.events.length - 1; i >= 0 && lines.length < 100; i--) {
    const made = line(st.events[i]);
    if (made) lines.push(`<div class="${made[1]}"><time>${hhmmss(new Date(st.events[i].at * 1000))}</time>${made[0]}</div>`);
  }
  const html = lines.join("") || `<p class="muted">Alerts, releases, attacks and tap changes show up here.</p>`;
  const box = document.getElementById("log");
  if (box.dataset.html !== html) { box.dataset.html = html; box.innerHTML = html; }
}

// ---------------------------------------------------------------- the cluster map

function showTip(event, html) {
  tip.html(html).classed("on", true);
  const pad = 14, box = tip.node().getBoundingClientRect();
  let x = event.clientX + pad, y = event.clientY + pad;
  if (x + box.width > window.innerWidth - 8) x = event.clientX - box.width - pad;
  if (y + box.height > window.innerHeight - 8) y = event.clientY - box.height - pad;
  tip.style("left", `${x}px`).style("top", `${y}px`);
}
const hideTip = () => tip.classed("on", false);
const hover = (selection, html) => selection
  .on("pointerenter pointermove", (event, d) => showTip(event, html(d)))
  .on("pointerleave", hideTip);
const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|f[cd]|fe80)/i.test(ip);

// the running cluster in renderCluster's shape: members from the inventory (Kubernetes
// itself, nothing inferred), conversations from the address pairs the watched taps saw lately
function clusterModel() {
  const c = st.info.inventory;
  const hostId = n => `host:${n.ip}`;
  const nodeOf = new Map(c.nodes.map(n => [n.k3d, n]));
  const elementOf = new Map();
  const hosts = c.nodes.map(n => {
    elementOf.set(n.ip, hostId(n));
    // flannel gives each node's pod subnet a .0 (VTEP) and a .1 (cni bridge): both are the node
    const base = (n.pod_cidr || "").match(/^(\d+\.\d+\.\d+)\.0\/24$/);
    if (base) for (const last of [0, 1]) elementOf.set(`${base[1]}.${last}`, hostId(n));
    return { id: hostId(n), name: n.name, ip: n.ip, roles: [n.control_plane ? "control-plane" : "worker"], pod_cidr: n.pod_cidr };
  });
  const pods = c.pods.map(p => {
    const n = nodeOf.get(p.node);
    const id = p.host_network || !p.ip ? `pod:${p.name}` : `pod:${p.ip}`;
    if (!p.host_network && p.ip) elementOf.set(p.ip, id);
    return { id, ip: p.host_network ? (n && n.ip) : p.ip, name: p.role ? `pod-${p.app}` : p.app,
             host: n ? hostId(n) : null, host_network: p.host_network, new: p.role === "attack", pod: p.name };
  });
  const services = c.services.map(x => {
    elementOf.set(x.ip, `svc:${x.ip}`);
    return { id: `svc:${x.ip}`, ip: x.ip, name: x.name,
             port_names: [`${x.name}${x.ports.length ? " :" + x.ports.map(p => p.port).join("/") : ""}`] };
  });
  // the same packet crosses several taps, so a pair counts what its busiest tap saw
  const floor = now() - MAP_SPAN, byPair = new Map();
  for (const [label, rows] of st.windows) {
    for (let i = rows.length - 1; i >= 0 && rows[i].wall >= floor; i--) {
      for (const [a, b, n] of rows[i].pairs || []) {
        const key = a < b ? `${a}|${b}` : `${b}|${a}`;
        const entry = byPair.get(key) || { a, b, taps: new Map() };
        entry.taps.set(label, (entry.taps.get(label) || 0) + n);
        byPair.set(key, entry);
      }
    }
  }
  const outside = id => id.startsWith("lan:") || id === "internet";
  const place = ip => elementOf.get(ip) || (isPrivate(ip) ? `lan:${ip}` : "internet");
  const merged = new Map(), totals = new Map();
  for (const { a, b, taps } of byPair.values()) {
    const src = place(a), dst = place(b);
    if (src === dst) continue;
    const packets = d3.max([...taps.values()]);
    const key = src < dst ? `${src}|${dst}` : `${dst}|${src}`;
    merged.set(key, { key, src, dst, packets: (merged.get(key)?.packets || 0) + packets, ports: [] });
    for (const id of [src, dst]) if (outside(id)) totals.set(id, (totals.get(id) || 0) + packets);
  }
  const kept = new Set([...totals.entries()].sort((x, y) => y[1] - x[1]).slice(0, 16).map(e => e[0]));
  const external = [...kept].sort().map(id => id === "internet" ? { id, kind: "internet", ip: "internet" }
    : { id, kind: "lan", ip: id.slice(4), note: "an address outside the cluster's nodes, pods and services" });
  const edges = [...merged.values()].filter(e => [e.src, e.dst].every(id => !outside(id) || kept.has(id)));
  const vantages = [...st.taps.values()].map(t => {
    const element = t.level === "pod" ? (pods.find(p => p.name === t.label) || {}).id
      : t.level === "node" ? (hosts.find(h => h.name === t.label.slice(5)) || {}).id
      : t.label === "router-any" ? "uplink" : "overlay";
    return { label: t.label, level: t.level, element };
  }).filter(v => v.element);
  return { hosts, pods, services, external, edges, vantages, place };
}

function drawMap(force = false) {
  const info = st.info, card = d3.select("#map-card");
  const has = Boolean(info && info.inventory && info.inventory.nodes.length);
  card.style("display", has ? null : "none");
  if (!has) return;
  const svg = d3.select("#map"), width = svg.node().clientWidth, height = svg.node().clientHeight;
  const model = clusterModel();
  // drawn again only when what it shows has changed, and never under the reader's pointer
  const sig = JSON.stringify([width, st.selected, model.pods.map(p => p.id + (p.new ? "!" : "")), model.edges.map(e => e.key).sort(),
                              model.external.map(e => e.id), model.vantages.map(v => v.label + Boolean(st.taps.get(v.label).watching))]);
  // A redraw while the pointer is over the map moves the thing being aimed at, and it can wipe
  // the focus just as the dwell fires. So the map is left alone from the moment the pointer
  // enters it until it leaves: the reader is looking at it, so it should hold still.
  const busy = svg.select(".focusing").size() || tip.classed("on") || mapHover;
  if (force || (sig !== st.mapSig && !busy && Date.now() - st.mapAt > 1500)) {
    st.mapSig = sig; st.mapAt = Date.now(); st.map = model;
    svg.selectAll("*").remove();
    hideTip();
    const g = svg.append("g");
    renderCluster(g, model, { x: 8, y: 6, w: width - 16, h: height - 12 }, {
      focus: st.selected, onTap: select, onPage: v => Boolean(st.taps.get(v.label).watching),
      tapNote: v => st.taps.get(v.label).watching ? `${(verdict(v.label) || {}).text || "watched"} · click to follow it` : "not watched · click to select it" });
    const n = watched().length;
    d3.select("#map-sub").text(`${model.hosts.length} nodes · ${model.pods.length} pods · ${model.services.length} services`
      + (n ? ` · who talked to whom in the last ${MAP_SPAN} s` : " · watch a tap to see conversations"));
  }
  mapLive();
}

function mapLive() {
  const svg = d3.select("#map");
  svg.selectAll(".tap").each(function (v) {
    const key = (verdict(v.label) || {}).key;
    d3.select(this).classed("alert", key === "alert").select(".tap-dot").style("fill", dotColor(v.label));
  });
  // the conversations behind the selected tap's latest flagged trace, in red
  const hit = st.selected && st.map ? culprit(st.selected) : null, hot = new Set();
  if (hit) for (const [a, b] of hit.top.pairs) {
    const src = st.map.place(a), dst = st.map.place(b);
    hot.add(src < dst ? `${src}|${dst}` : `${dst}|${src}`);
  }
  svg.selectAll(".link").classed("why", e => hot.has(e.key));
}

// The reader's map text size. The labels are SVG text sized off --map-text, and `fit` divides by
// the same factor, so a larger size truncates labels sooner instead of overflowing their boxes.
function applyTextScale(value) {
  TEXT_SCALE = textScale(value);
  document.documentElement.style.setProperty("--map-text", TEXT_SCALE);
  try { localStorage.setItem(TEXT_KEY, String(TEXT_SCALE)); } catch (e) { /* private mode */ }
  drawMap(true);
}

// The map's layout and focus behaviour began as a copy of the demo's (viz/template/page.js
// renderCluster); the two are free to move apart.
// Lay the cluster out inside `box` and draw it into `g`. Returns element positions by id
// so callers can draw on top (flows, taps). Everything is placed by rules over the bundle.
function renderCluster(g, cluster, box, { focus = null, compact = false, onTap = null, onPage = null, tapNote = null } = {}) {
  const tapOnPage = onPage || (() => true);
  const pos = new Map();
  const pad = compact ? 6 : 16;
  const rows = compact
    ? { top: 0.12, hosts: 0.62, overlay: 0.08, services: 0.18 }
    : { top: 0.13, hosts: 0.58, overlay: 0.09, services: 0.20 };
  let y = box.y;
  const band = key => { const r = { y, h: box.h * rows[key] }; y += r.h; return r; };
  const top = band("top"), hostRow = band("hosts"), overlay = band("overlay"), services = band("services");

  // hosts: control plane first, then capture-named hosts, then hosts only seen in traffic
  const pods = d3.group(cluster.pods, p => p.host);
  const unattributed = pods.get(null) || [];
  const hosts = [...cluster.hosts].sort((a, b) =>
    (b.roles.includes("control-plane") && b.name ? 1 : 0) - (a.roles.includes("control-plane") && a.name ? 1 : 0)
    || (b.name ? 1 : 0) - (a.name ? 1 : 0) || d3.ascending(a.name || a.ip, b.name || b.ip));
  // hosts no capture claimed and with no pods are drawn small, up with the outside world
  const drawnHosts = hosts.filter(h => h.name || pods.has(h.id));
  const strayHosts = hosts.filter(h => !h.name && !pods.has(h.id));
  // A node box is only as big as what it carries: the side grows with the pod mass on it, so the
  // gaps between boxes stay open and the conversations crossing them stay visible. Hovering or
  // pinning one scales the whole column (`.node.grow` in live.css).
  const massOf = p => (p.name ? 6 : 1);
  const columns = drawnHosts.map(h => {
    const own = pods.get(h.id) || [];
    return { kind: "host", host: h, pods: own, mass: d3.sum(own, massOf) };
  });
  if (unattributed.length) columns.push({ kind: "lane", pods: unattributed, mass: d3.sum(unattributed, massOf) });
  const gap = compact ? 6 : 14;
  const unit = compact ? 8 : 24;        // box side per sqrt of pod mass on the node
  const floor = compact ? 12 : 46;      // an empty node is still a box you can point at
  const tallest = hostRow.h - pad;
  for (const column of columns) {
    const ghost = column.kind === "lane" || !column.host.name;
    column.head = compact ? 14 : (ghost ? 30 : 58);
    const side = Math.min(tallest - column.head,
                          Math.max(floor, unit * Math.sqrt(Math.max(column.mass, 1))));
    column.w = Math.min(compact ? 44 : 172, Math.max(compact ? 22 : 84, side * 1.35));
    column.h = Math.min(tallest, side + column.head + 6);
  }
  const span = d3.sum(columns, c => c.w) + gap * Math.max(columns.length - 1, 0);
  // the room the boxes do not take is shared between them, up to a limit, and the row centred
  const spread = columns.length > 1
    ? Math.min(compact ? 8 : 70, Math.max(0, box.w - span) / (columns.length - 1)) : 0;
  let x = box.x + Math.max(0, (box.w - span - spread * Math.max(columns.length - 1, 0)) / 2);

  const hostG = g.append("g");
  for (const column of columns) {
    const r = { x, y: hostRow.y + (hostRow.h - column.h) / 2, w: column.w, h: column.h };
    x += column.w + gap + spread;
    const head = column.head;
    const cp = column.kind === "host" && column.host.roles.includes("control-plane");
    const ghost = column.kind === "lane" || !column.host.name;
    // one group per node, so hover and pin scale the box and everything drawn in it together
    const gNode = hostG.append("g").attr("class", "node")
      .attr("data-el", column.kind === "host" ? column.host.id : null);
    gNode.append("rect").attr("class", `host-box ${cp ? "cp" : ""} ${ghost ? "ghost" : ""}`)
      .attr("x", r.x).attr("y", r.y).attr("width", r.w).attr("height", r.h).attr("rx", compact ? 6 : 12);
    if (column.kind === "host") {
      const h = column.host;
      pos.set(h.id, { x: r.x + r.w / 2, y: r.y + head / 2 + 4, box: r, kind: "host" });
      if (!compact || h.name) {
        gNode.append("text").attr("class", compact ? "t-small" : "t-title").attr("data-for", h.id)
          .attr("x", r.x + (compact ? 6 : 12)).attr("y", r.y + (compact ? 12 : 20))
          .text(h.name || h.ip);
      }
      if (!compact) {
        const lines = h.name ? [`${h.ip} · ${h.roles.join(" · ")}`, h.pod_cidr ? `pods ${h.pod_cidr}` : "no pod subnet"]
                             : ["no pods"];
        lines.forEach((line, i) => gNode.append("text").attr("class", "t-small t-muted detail").attr("data-for", h.id)
          .attr("x", r.x + 12).attr("y", r.y + 35 + i * 13).text(fit(line, r.w - 24)));
      }
    } else if (!compact) {
      gNode.append("text").attr("class", "t-small t-muted detail").attr("x", r.x + 12).attr("y", r.y + 20)
        .text("pods with no node");
    }
    hover(gNode.append("rect").attr("x", r.x).attr("y", r.y).attr("width", r.w).attr("height", head)
      .attr("data-hit", column.kind === "host" ? column.host.id : null)
      .attr("fill", "transparent").datum(column), c => c.kind === "host"
        ? `<div class="tt-title">${c.host.name ? "node " + c.host.name : "host " + c.host.ip}</div>
           <div class="tt-row">${c.host.ip} · ${c.host.roles.join(", ")}</div>
           <div class="tt-row">${c.host.pod_cidr ? "pod subnet " + c.host.pod_cidr : "no pod subnet claimed"}</div>
           <div class="tt-row">${c.pods.length} pod${c.pods.length === 1 ? "" : "s"} seen</div>`
        : `<div class="tt-title">pods with no node</div><div class="tt-row">not scheduled yet</div>`);

    // pods packed inside the box; named and host-network pods are the ones a reader cares about
    if (column.pods.length) {
      const inner = { x: r.x + 6, y: r.y + head, w: r.w - 12, h: r.h - head - 6 };
      const root = d3.hierarchy({ children: column.pods })
        .sum(massOf)
        .sort((a, b) => d3.descending(a.value, b.value) || d3.ascending(a.data.id, b.data.id));
      d3.pack().size([inner.w, inner.h]).padding(compact ? 2 : 5)(root);
      for (const leaf of root.leaves()) {
        const p = leaf.data, cx = inner.x + leaf.x, cy = inner.y + leaf.y, rr = Math.max(leaf.r, 2.5);
        pos.set(p.id, { x: cx, y: cy, r: rr, kind: "pod" });
        const circle = gNode.append("circle")
          .attr("class", `pod ${p.host_network ? "hostnet" : p.name ? "named" : ""} ${p.new ? "new" : ""}`)
          .attr("data-id", p.id).attr("data-el", p.id).attr("cx", cx).attr("cy", cy).attr("r", rr).datum(p);
        hover(circle, d => `<div class="tt-title">${d.name || "pod " + d.ip}</div>
          <div class="tt-row">${d.host_network ? "host network: shares the node's address " + d.ip + ", so its traffic is drawn on the node" : "pod address " + d.ip}</div>
          ${d.new ? `<div class="tt-row">an attack pod</div>` : ""}`);
        if (p.name && !compact && rr > 16) {
          const label = p.name.replace(/^pod-/, "");
          gNode.append("text").attr("class", "t-small").attr("text-anchor", "middle").attr("data-for", p.id)
            .attr("x", cx).attr("y", cy + 4).text(label.length * 6 > rr * 2 ? label.slice(0, Math.floor(rr / 3.2)) + "…" : label)
            .style("pointer-events", "none");
          if (p.host_network) {
            gNode.append("text").attr("class", "t-small t-muted").attr("text-anchor", "middle").attr("data-for", p.id)
              .attr("x", cx).attr("y", cy + 16).text("host net").style("pointer-events", "none");
          }
        }
      }
    }
  }

  // outside world on top, joined to the hosts by the LAN uplink
  const outside = [...strayHosts.map(h => ({ id: h.id, ip: h.ip, kind: "host", roles: h.roles })),
                   ...cluster.external];
  const upY = top.y + top.h * 0.78;
  g.insert("rect", ":first-child").attr("class", "band uplink")
    .attr("x", box.x).attr("y", upY - 3).attr("width", box.w).attr("height", 6).attr("rx", 3);
  pos.set("uplink", { x: box.x + box.w * 0.92, y: upY, kind: "network" });
  if (!compact) {
    g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", upY - 8).text("LAN uplink");
    g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", top.y + top.h * 0.24 + 4)
      .text(box.w * 0.8 / Math.max(outside.length, 1) < 70 ? `outside · ${outside.length}` : "outside")
      .append("title").text("hover an address to name it");
  }
  // an IP label needs about 70 px; closer than that the labels overprint each other, so they
  // wait for focus (hover or click) instead, and the row's heading says how many there are
  const crowded = box.w * 0.8 / Math.max(outside.length, 1) < 70;
  outside.forEach((e, i) => {
    const ex = box.x + box.w * (0.16 + 0.8 * (i + 0.5) / outside.length), ey = top.y + top.h * 0.24;
    pos.set(e.id, { x: ex, y: ey, r: compact ? 5 : 9, kind: "external" });
    hover(g.append("circle").attr("class", `ext ${e.kind} ${e.new ? "new" : ""}`).attr("data-el", e.id).attr("cx", ex).attr("cy", ey).attr("r", compact ? 5 : 9).datum(e),
      d => (d.kind === "host"
        ? `<div class="tt-title">host ${d.ip}</div><div class="tt-row">${d.roles.join(", ")} · serves a cluster port; no capture of its own</div>`
        : `<div class="tt-title">${d.kind === "internet" ? "the internet" : "LAN device " + d.ip}</div>
           ${d.note ? `<div class="tt-row">${d.note}; not proven to be a node</div>` : ""}`)
        + (d.new ? `<div class="tt-row">an attack pod</div>` : ""));
    if (!compact) g.append("text").attr("class", `t-small t-2 detail ext-label ${crowded && e.kind !== "internet" ? "crowded" : ""}`)
      .attr("data-for", e.id).attr("text-anchor", "middle")
      .attr("x", ex).attr("y", ey + 23).text(e.kind === "internet" ? "internet" : e.ip);
  });

  // flannel overlay joins the pod subnets under the hosts
  const oy = overlay.y + overlay.h / 2;
  g.append("rect").attr("class", "band").attr("x", box.x).attr("y", oy - overlay.h * 0.3)
    .attr("width", box.w).attr("height", overlay.h * 0.6).attr("rx", 6);
  pos.set("overlay", { x: box.x + box.w * 0.92, y: oy, kind: "network" });
  if (!compact) g.append("text").attr("class", "t-section detail").attr("x", box.x + 10).attr("y", oy + 4)
    .text("flannel overlay · pod-to-pod across nodes");

  // services (the cluster's virtual IPs) along the bottom
  cluster.services.forEach((s, i) => {
    const sx = box.x + box.w * (i + 0.5) / Math.max(cluster.services.length, 1), sy = services.y + services.h * 0.5;
    // a pill per service, as wide as the row allows: seven services must not overprint
    const room = box.w / Math.max(cluster.services.length, 1) - 8;
    const w = compact ? Math.min(46, room) : Math.min(150, Math.max(room, 40)), h = compact ? 14 : 30;
    pos.set(s.id, { x: sx, y: sy - h / 2, kind: "service" });
    hover(g.append("rect").attr("class", `svc ${s.new ? "new" : ""}`).attr("data-el", s.id).attr("x", sx - w / 2).attr("y", sy - h / 2)
      .attr("width", w).attr("height", h).attr("rx", h / 2).datum(s),
      d => `<div class="tt-title">service ${d.ip}</div><div class="tt-row">${d.port_names.join(", ") || "no well-known port"}</div>`);
    if (!compact) g.append("text").attr("class", "detail").attr("data-for", s.id).attr("text-anchor", "middle").attr("x", sx).attr("y", sy + 4)
      .text(fit(s.name ? `${s.name} · ${s.ip}` : `${s.ip}${s.port_names.length ? " · " + s.port_names.join(", ") : ""}`, w - 12)).style("pointer-events", "none");
  });
  if (!compact && cluster.services.length) g.append("text").attr("class", "t-section detail")
    .attr("x", box.x).attr("y", services.y + 12).text("services");

  // conversations: one curve per element pair, width by log packets, behind everything
  const width = d3.scaleLog().domain(d3.extent(cluster.edges, e => Math.max(e.packets, 1))).range(compact ? [0.6, 2.5] : [1, 7]).clamp(true);
  const edgeG = g.insert("g", ":first-child");
  const edges = edgeG.selectAll("path").data(cluster.edges.filter(e => pos.has(e.src) && pos.has(e.dst)))
    .join("path").attr("class", e => `link ${e.new ? "new" : ""}`)
    .attr("d", e => curve(pos.get(e.src), pos.get(e.dst)))
    .attr("stroke-width", e => width(Math.max(e.packets, 1)));
  hover(edges, e => `<div class="tt-title">${label(e.src)} ↔ ${label(e.dst)}</div>
    <div class="tt-row">${fmt(e.packets)} packets in the last ${MAP_SPAN} s, at the tap that saw most of them</div>`);

  // capture taps: where each recording listened
  const taps = g.append("g");
  const networkTaps = cluster.vantages.filter(v => v.level === "router");
  for (const v of cluster.vantages) {
    const p = pos.get(v.element);
    if (!p) continue;
    let tx = p.x, ty = p.y;
    if (p.kind === "host") { tx = p.box.x + p.box.w - 14; ty = p.box.y + 14; }
    else if (p.kind === "pod") { tx = p.x + p.r * 0.72; ty = p.y - p.r * 0.72; }
    else if (p.kind === "network") { tx = box.x + box.w * (0.78 + 0.14 * networkTaps.indexOf(v) / Math.max(networkTaps.length, 1)); }
    const isFocus = v.label === focus, here = tapOnPage(v);
    const tg = taps.append("g")
      .attr("class", `tap ${isFocus ? "focus" : ""} ${here ? "on-page" : "off-page"}`)
      .attr("data-label", v.label).attr("transform", `translate(${tx},${ty})`).datum(v);
    if (isFocus) tg.append("circle").attr("class", "tap-halo").attr("r", compact ? 8 : 12);
    tg.append("circle").attr("class", "tap-dot").attr("r", compact ? 3.5 : 5);
    // a wider invisible target, so a 5 px dot is easy to click
    tg.append("circle").attr("class", "tap-hit").attr("r", compact ? 8 : 12);
    if (isFocus && !compact) tg.append("text").attr("class", "t-small halo").attr("x", 10).attr("y", -8).text(v.label);
    hover(tg, d => `<div class="tt-title">capture tap: ${d.label}</div><div class="tt-row">${d.level}-level tap</div>
      <div class="tt-row">${tapNote ? tapNote(d) : ""}</div>`);
    if (onTap) tg.style("cursor", "pointer").on("click", (event, d) => { event.stopPropagation(); hideTip(); onTap(d.label); });
    if (isFocus) pos.set("__focus__", { x: tx, y: ty });
  }
  if (!compact) clusterFocus(g, cluster, edges, box, label);
  return { pos, edges, taps };

  function label(id) {
    const host = cluster.hosts.find(h => h.id === id);
    if (host) return host.name || host.ip;
    const pod = cluster.pods.find(p => p.id === id);
    if (pod) return pod.name || pod.ip;
    return id.replace(/^\w+:/, "");
  }
}

// Focus on the full-size map: hovering an element brings it forward (it grows, its
// conversation partners and links stay lit, everything else fades) and a line under the map
// names it in larger type; clicking pins that focus until the background or the element is
// clicked again. The compact maps leave this off: their highlighting belongs to the replay.
function clusterFocus(g, cluster, edges, box, nameOf) {
  const near = new Map();
  for (const e of cluster.edges) {
    if (!near.has(e.src)) near.set(e.src, new Set());
    if (!near.has(e.dst)) near.set(e.dst, new Set());
    near.get(e.src).add(e.dst);
    near.get(e.dst).add(e.src);
  }
  const hostOf = new Map(cluster.pods.map(p => [p.id, p.host]));
  // The readout lives in HTML under the map, not inside the SVG. Inside, it had to be placed
  // somewhere over a map that fills its box edge to edge, so every position hid a pod or a chip;
  // out here it hides nothing, never jumps as the pointer moves, and cannot be clicked at all.
  const line = d3.select("#focus-line");
  let pinned = null;

  // the background takes the click that clears a pin
  g.insert("rect", ":first-child").attr("class", "focus-bg")
    .attr("x", box.x).attr("y", box.y).attr("width", box.w).attr("height", box.h)
    .on("click.focus", () => { pinned = null; cancelDwell(); set(null); });

  // [title, detail lines]: what the hover tooltip said, in the card instead
  function describe(id) {
    const host = cluster.hosts.find(h => h.id === id);
    if (host) {
      const count = cluster.pods.filter(p => p.host === id).length;
      return [host.name ? `node ${host.name}` : `host ${host.ip}`,
              [`${host.ip} · ${host.roles.join(", ") || "no role seen"}`,
               host.name ? `${host.pod_cidr ? "pod subnet " + host.pod_cidr : "no pod subnet claimed"} · ${count} pod${count === 1 ? "" : "s"}`
                         : "serves a cluster port; no capture of its own"]];
    }
    const pod = cluster.pods.find(p => p.id === id);
    if (pod) {
      const on = cluster.hosts.find(h => h.id === pod.host);
      const where = on ? ` on ${on.name || on.ip}` : "";
      return [pod.name ? pod.name.replace(/^pod-/, "") : `pod ${pod.ip}`,
              [pod.host_network ? `host network${where}: shares the node's address ${pod.ip}` : `pod ${pod.ip}${where}`,
               pod.new ? "an attack pod" : null]];
    }
    const svc = cluster.services.find(x => x.id === id);
    if (svc) return [`service ${svc.ip}`, [svc.port_names.join(", ") || "no well-known port", svc.new ? "an attack pod" : null]];
    const ext = cluster.external.find(x => x.id === id);
    if (ext) return [ext.kind === "internet" ? "the internet" : ext.ip,
                     [ext.kind === "internet" ? "addresses outside every private range"
                       : ext.note ? `LAN device: ${ext.note}; not proven to be a node` : "LAN device",
                      ext.new ? "an attack pod" : null]];
    return [nameOf(id), []];
  }

  function drawCard(id) {
    const [title, details] = describe(id);
    const partners = (near.get(id) || new Set()).size;
    const rows = [...details, `${partners} conversation partner${partners === 1 ? "" : "s"}`].filter(Boolean);
    line.html(`<span class="ft-title">${esc(title)}</span>`
      + rows.map(row => `<span class="ft-row">${esc(row)}</span>`).join(""));
  }

  function set(id, edge = null) {
    g.classed("focusing", Boolean(id || edge));
    g.selectAll(".lit").classed("lit", false);
    g.selectAll(".grow").classed("grow", false);
    edges.classed("lit", false);
    line.html("");
    if (!id && !edge) return;
    const lit = new Set(edge ? [edge.src, edge.dst] : [id, ...(near.get(id) || [])]);
    for (const x of [...lit]) if (hostOf.get(x)) lit.add(hostOf.get(x));
    g.selectAll("[data-el], [data-for]").classed("lit", function () { return lit.has(this.dataset.el || this.dataset.for); });
    edges.classed("lit", e => edge ? e === edge : e.src === id || e.dst === id);
    if (id) {
      // grow the element itself; a pod or address comes to the front with its own labels
      g.selectAll("[data-el]").filter(function () { return this.dataset.el === id; }).classed("grow", true)
        .each(function () { if (!this.classList.contains("host-box")) d3.select(this).raise(); });
      g.selectAll("[data-for]").filter(function () { return this.dataset.for === id; }).raise();
      g.selectAll(".tap").raise();
      drawCard(id);
    }
  }

  const keyOf = node => node.dataset.el || node.dataset.hit;
  // A pointer crossing the map passes over many elements on the way to the one it wants, and
  // focusing each one as it goes made the map twitch and grow things the reader never meant.
  // Dwell first: focus only after the pointer has rested, and drop the pending focus on leave.
  const HOVER_DELAY = 140;
  let dwell = null;
  const cancelDwell = () => { if (dwell) { clearTimeout(dwell); dwell = null; } };
  const dwellOn = (id, edge = null) => {
    if (pinned) return;
    cancelDwell();
    dwell = setTimeout(() => { dwell = null; set(id, edge); }, HOVER_DELAY);
  };
  const settle = () => { cancelDwell(); set(pinned); };

  g.selectAll("[data-el], [data-hit]")
    .on("pointerenter", null).on("pointermove", null)   // the card replaces their tooltips
    .on("pointerenter.focus", function () { dwellOn(keyOf(this)); })
    .on("pointerleave.focus", settle)
    .on("click.focus", function (event) {
      event.stopPropagation();
      cancelDwell();                       // a click is immediate: no waiting on the dwell
      const id = keyOf(this);
      pinned = pinned === id ? null : id;
      set(pinned);                         // a second click clears, rather than falling back to hover
    });
  edges.on("pointerenter.focus", (event, e) => dwellOn(null, e))
    .on("pointerleave.focus", settle);
}

// shorten text to fit a pixel width at the current label size
function fit(text, width) {
  const max = Math.floor(width / (6 * TEXT_SCALE));
  return text.length > max ? text.slice(0, Math.max(max - 1, 1)) + "…" : text;
}

function curve(a, b) {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
  const bend = Math.min(60, len * 0.18);
  return `M${a.x},${a.y} Q${mx - dy / len * bend},${my + dx / len * bend} ${b.x},${b.y}`;
}

// ---------------------------------------------------------------- putting it together

// what changes when a tap changes state: rows, the selected tap's panel, the buttons
function structure() { header(); actions(); strips(); detail(); attacks(); }
// what moves every second
function live() { header(); stripsLive(); detailLive(); attackLive(); drawMap(); }
function renderAll() { banner(); structure(); drawMap(true); log(); }

d3.select("#theme").on("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
});
// the reader's saved map text size, and the two buttons that change it
document.documentElement.style.setProperty("--map-text", TEXT_SCALE);
d3.selectAll("#map-zoom button").on("click", function () {
  applyTextScale(TEXT_SCALE + Number(this.dataset.step) * 0.1);
});
let resizeTimer = null;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { live(); drawMap(true); }, 150); });
// the map holds still while the pointer is on it, and catches up once it leaves
d3.select("#map").on("pointerenter.hover", () => { mapHover = true; })
  .on("pointerleave.hover", () => { mapHover = false; drawMap(); });
setInterval(() => { live(); log(); }, 1000);
setInterval(() => { if (!st.busy) refresh(); }, 15000);     // pods come and go; the inventory is asked again now and then
refresh().then(connect);
})();
