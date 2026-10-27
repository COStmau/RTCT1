// The state-machine story renderer. It owns no data: everything comes from window.STORY,
// the bundle story.py builds from the pipeline. Positions come from the bundle's computed
// layouts or from layout rules below that read only the bundle; colors are CSS roles.
// Vendored D3: d3js.org v7.9.0, sha256 f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539
(() => {
"use strict";
const S = window.STORY;
const svg = d3.select("#svg");
const panel = d3.select("#panel");
const controls = d3.select("#controls");
const tip = d3.select("#tooltip");
const fmt = d3.format(",");
const f2 = d3.format(".2f");
const f1 = d3.format(".1f");

// ---------------------------------------------------------------- shared helpers

// State identity: categorical slots in fixed order. Slots 1 (blue) and 8 (red) are
// reserved for ALERGIA's candidate and kept states, so states start at slot 3.
const STATE_SLOTS = ["--s3", "--s4", "--s5", "--s6", "--s7", "--s2"];
const stateColor = id => `var(${STATE_SLOTS[id] || "--other"})`;
const PROTO_SLOTS = ["--s1", "--s2", "--s3"];
const protocols = [...new Set(S.learning.symbols.map(s => s.proto))];
const protoColor = proto => {
  const i = protocols.indexOf(proto);
  return `var(${PROTO_SLOTS[i] || "--other"})`;
};

function size() {
  const node = document.getElementById("canvas");
  return { w: node.clientWidth, h: node.clientHeight };
}

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

function symbolParts(symbol) {
  const parts = symbol.split("_");
  return { proto: parts[0], bytes: parts[parts.length - 2], duration: parts[parts.length - 1] };
}

function binText(kind, bin) {
  const edges = S.learning.bins[kind];
  const index = +String(bin).slice(1);
  if (!edges || !(index >= 0) || index + 1 >= edges.length) return bin;
  const unit = kind === "bytes" ? " B" : " s";
  const show = v => kind === "bytes" ? fmt(Math.round(v)) : (v < 0.01 ? v.toExponential(1) : f2(v));
  return `${show(edges[index])}–${show(edges[index + 1])}${unit}`;
}

function symbolTip(symbol) {
  const p = symbolParts(symbol);
  return `<div class="tt-title mono">${symbol}</div>
    <div class="tt-row">protocol ${p.proto}</div>
    <div class="tt-row">bytes bin ${p.bytes}: ${binText("bytes", p.bytes)}</div>
    <div class="tt-row">duration bin ${p.duration}: ${binText("duration", p.duration)}</div>`;
}

function chip(symbol, extra = "") {
  return `<span class="chip ${extra}"><span class="sw" style="background:${protoColor(symbolParts(symbol).proto)}"></span>${symbol}</span>`;
}

// SVG arrowheads, one per role so they inherit the role's color
function defs() {
  const d = svg.append("defs");
  for (const [id, color] of [["arrow", "var(--ink-2)"], ["arrow-hot", "var(--accent)"],
                             ["arrow-red", "var(--red)"]]) {
    d.append("marker").attr("id", id).attr("viewBox", "0 0 10 10").attr("refX", 9)
      .attr("refY", 5).attr("markerWidth", 7).attr("markerHeight", 7)
      .attr("orient", "auto-start-reverse")
      .append("path").attr("d", "M0,0 L10,5 L0,10 z").attr("fill", color);
  }
}

// ---------------------------------------------------------------- act 1: the cluster

// Lay the cluster out inside `box` and draw it into `g`. Returns element positions by id
// so callers can draw on top (flows, taps). Everything is placed by rules over the bundle.
function renderCluster(g, cluster, box, { focus = null, compact = false } = {}) {
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
  const columns = drawnHosts.map(h => ({ kind: "host", host: h, pods: pods.get(h.id) || [],
                                         weight: 1 + Math.sqrt((pods.get(h.id) || []).length) }));
  if (unattributed.length) columns.push({ kind: "lane", pods: unattributed, weight: 0.9 });
  const total = d3.sum(columns, c => c.weight);
  const gap = compact ? 6 : 12;
  const usable = box.w - gap * (columns.length - 1);
  let x = box.x;

  const hostG = g.append("g");
  for (const column of columns) {
    const w = usable * column.weight / total;
    const r = { x, y: hostRow.y + pad / 2, w, h: hostRow.h - pad };
    x += w + gap;
    const cp = column.kind === "host" && column.host.roles.includes("control-plane");
    const ghost = column.kind === "lane" || !column.host.name;
    hostG.append("rect").attr("class", `host-box ${cp ? "cp" : ""} ${ghost ? "ghost" : ""}`)
      .attr("x", r.x).attr("y", r.y).attr("width", r.w).attr("height", r.h).attr("rx", compact ? 6 : 12);
    const head = compact ? 14 : (ghost ? 30 : 58);
    if (column.kind === "host") {
      const h = column.host;
      pos.set(h.id, { x: r.x + r.w / 2, y: r.y + head / 2 + 4, box: r, kind: "host" });
      if (!compact || h.name) {
        hostG.append("text").attr("class", compact ? "t-small" : "t-title")
          .attr("x", r.x + (compact ? 6 : 12)).attr("y", r.y + (compact ? 12 : 20))
          .text(h.name || h.ip);
      }
      if (!compact) {
        const lines = h.name ? [`${h.ip} · ${h.roles.join(" · ")}`, h.pod_cidr ? `pods ${h.pod_cidr}` : "no pod subnet"]
                             : ["seen in traffic only"];
        lines.forEach((line, i) => hostG.append("text").attr("class", "t-small t-muted")
          .attr("x", r.x + 12).attr("y", r.y + 35 + i * 13).text(fit(line, r.w - 24)));
      }
    } else if (!compact) {
      hostG.append("text").attr("class", "t-small t-muted").attr("x", r.x + 12).attr("y", r.y + 20)
        .text("pods with no claimed node");
    }
    hover(hostG.append("rect").attr("x", r.x).attr("y", r.y).attr("width", r.w).attr("height", head)
      .attr("fill", "transparent").datum(column), c => c.kind === "host"
        ? `<div class="tt-title">${c.host.name ? "node " + c.host.name : "host " + c.host.ip}</div>
           <div class="tt-row">${c.host.ip} · ${c.host.roles.join(", ")}</div>
           <div class="tt-row">${c.host.pod_cidr ? "pod subnet " + c.host.pod_cidr : "no pod subnet claimed"}</div>
           <div class="tt-row">${c.pods.length} pod${c.pods.length === 1 ? "" : "s"} seen</div>`
        : `<div class="tt-title">unattributed pods</div><div class="tt-row">their /24 was not claimed by any node capture</div>`);

    // pods packed inside the box; named and host-network pods are the ones a reader cares about
    if (column.pods.length) {
      const inner = { x: r.x + 6, y: r.y + head, w: r.w - 12, h: r.h - head - 6 };
      const root = d3.hierarchy({ children: column.pods })
        .sum(p => p.name ? 6 : 1)
        .sort((a, b) => d3.descending(a.value, b.value) || d3.ascending(a.data.id, b.data.id));
      d3.pack().size([inner.w, inner.h]).padding(compact ? 2 : 5)(root);
      for (const leaf of root.leaves()) {
        const p = leaf.data, cx = inner.x + leaf.x, cy = inner.y + leaf.y, rr = Math.max(leaf.r, 2.5);
        pos.set(p.id, { x: cx, y: cy, r: rr, kind: "pod" });
        const circle = hostG.append("circle")
          .attr("class", `pod ${p.host_network ? "hostnet" : p.name ? "named" : ""}`)
          .attr("cx", cx).attr("cy", cy).attr("r", rr).datum(p);
        hover(circle, d => `<div class="tt-title">${d.name || "pod " + d.ip}</div>
          <div class="tt-row">${d.host_network ? "host network: shares the node's address " + d.ip : "pod address " + d.ip}</div>`);
        if (p.name && !compact && rr > 16) {
          const label = p.name.replace(/^pod-/, "");
          hostG.append("text").attr("class", "t-small").attr("text-anchor", "middle")
            .attr("x", cx).attr("y", cy + 4).text(label.length * 6 > rr * 2 ? label.slice(0, Math.floor(rr / 3.2)) + "…" : label)
            .style("pointer-events", "none");
          if (p.host_network) {
            hostG.append("text").attr("class", "t-small t-muted").attr("text-anchor", "middle")
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
    g.append("text").attr("class", "t-section").attr("x", box.x).attr("y", upY - 8).text("LAN uplink");
    g.append("text").attr("class", "t-section").attr("x", box.x).attr("y", top.y + top.h * 0.24 + 4).text("outside");
  }
  outside.forEach((e, i) => {
    const ex = box.x + box.w * (0.16 + 0.8 * (i + 0.5) / outside.length), ey = top.y + top.h * 0.24;
    pos.set(e.id, { x: ex, y: ey, r: compact ? 5 : 9, kind: "external" });
    hover(g.append("circle").attr("class", `ext ${e.kind}`).attr("cx", ex).attr("cy", ey).attr("r", compact ? 5 : 9).datum(e),
      d => d.kind === "host"
        ? `<div class="tt-title">host ${d.ip}</div><div class="tt-row">${d.roles.join(", ")} · seen in traffic only, no capture of its own</div>`
        : `<div class="tt-title">${d.kind === "internet" ? "the internet" : "LAN device " + d.ip}</div>`);
    if (!compact) g.append("text").attr("class", "t-small t-2").attr("text-anchor", "middle")
      .attr("x", ex).attr("y", ey + 23).text(e.kind === "internet" ? "internet" : e.ip);
  });

  // flannel overlay joins the pod subnets under the hosts
  const oy = overlay.y + overlay.h / 2;
  g.append("rect").attr("class", "band").attr("x", box.x).attr("y", oy - overlay.h * 0.3)
    .attr("width", box.w).attr("height", overlay.h * 0.6).attr("rx", 6);
  pos.set("overlay", { x: box.x + box.w * 0.92, y: oy, kind: "network" });
  if (!compact) g.append("text").attr("class", "t-section").attr("x", box.x + 10).attr("y", oy + 4)
    .text("flannel overlay · pod-to-pod across nodes");

  // services (the cluster's virtual IPs) along the bottom
  cluster.services.forEach((s, i) => {
    const sx = box.x + box.w * (i + 0.5) / Math.max(cluster.services.length, 1), sy = services.y + services.h * 0.5;
    const w = compact ? 46 : 150, h = compact ? 14 : 30;
    pos.set(s.id, { x: sx, y: sy - h / 2, kind: "service" });
    hover(g.append("rect").attr("class", "svc").attr("x", sx - w / 2).attr("y", sy - h / 2)
      .attr("width", w).attr("height", h).attr("rx", h / 2).datum(s),
      d => `<div class="tt-title">service ${d.ip}</div><div class="tt-row">${d.port_names.join(", ") || "no well-known port"}</div>`);
    if (!compact) g.append("text").attr("text-anchor", "middle").attr("x", sx).attr("y", sy + 4)
      .text(`${s.ip}${s.port_names.length ? " · " + s.port_names.join(", ") : ""}`).style("pointer-events", "none");
  });
  if (!compact && cluster.services.length) g.append("text").attr("class", "t-section")
    .attr("x", box.x).attr("y", services.y + 12).text("services");

  // conversations: one curve per element pair, width by log packets, behind everything
  const width = d3.scaleLog().domain(d3.extent(cluster.edges, e => Math.max(e.packets, 1))).range(compact ? [0.6, 2.5] : [1, 7]).clamp(true);
  const edgeG = g.insert("g", ":first-child");
  const edges = edgeG.selectAll("path").data(cluster.edges.filter(e => pos.has(e.src) && pos.has(e.dst)))
    .join("path").attr("class", "link")
    .attr("d", e => curve(pos.get(e.src), pos.get(e.dst)))
    .attr("stroke-width", e => width(Math.max(e.packets, 1)));
  hover(edges, e => `<div class="tt-title">${label(e.src)} ↔ ${label(e.dst)}</div>
    <div class="tt-row">${fmt(e.packets)} packets at the best vantage</div>
    <div class="tt-row">${e.ports.join(", ") || "ephemeral ports"}</div>`);

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
    const isFocus = v.label === focus;
    const tg = taps.append("g").attr("class", `tap ${isFocus ? "focus" : ""}`).attr("transform", `translate(${tx},${ty})`).datum(v);
    if (isFocus) tg.append("circle").attr("class", "tap-halo").attr("r", compact ? 8 : 12);
    tg.append("circle").attr("class", "tap-dot").attr("r", compact ? 3.5 : 5);
    if (isFocus && !compact) tg.append("text").attr("class", "t-small halo").attr("x", 10).attr("y", -8).text(`listening: ${v.label}`);
    hover(tg, d => `<div class="tt-title">capture tap: ${d.label}</div><div class="tt-row">${d.level}-level recording</div>`);
    if (isFocus) pos.set("__focus__", { x: tx, y: ty });
  }
  return { pos, edges, taps };

  function label(id) {
    const host = cluster.hosts.find(h => h.id === id);
    if (host) return host.name || host.ip;
    const pod = cluster.pods.find(p => p.id === id);
    if (pod) return pod.name || pod.ip;
    return id.replace(/^\w+:/, "");
  }
}

// shorten text to fit a pixel width at the small label size
function fit(text, width) {
  const max = Math.floor(width / 6);
  return text.length > max ? text.slice(0, Math.max(max - 1, 1)) + "…" : text;
}

function curve(a, b) {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
  const bend = Math.min(60, len * 0.18);
  return `M${a.x},${a.y} Q${mx - dy / len * bend},${my + dx / len * bend} ${b.x},${b.y}`;
}

function actCluster() {
  const { w, h } = size();
  const c = S.cluster;
  const focus = c.vantages.find(v => v.label === S.meta.vantage);
  const box = { x: 28, y: 20, w: w - 56, h: h - 40 };
  renderCluster(svg.append("g"), c, box, { focus: S.meta.vantage });

  const named = c.hosts.filter(h => h.name);
  const cp = c.hosts.find(h => h.name && h.roles.includes("control-plane"));
  const focusPod = c.pods.find(p => p.id === (focus && focus.element));
  const focusHost = c.hosts.find(h => h.id === (focusPod ? focusPod.host : focus && focus.element));
  const where = focusPod
    ? (focusPod.host_network
        ? `a <b>host-network pod</b> on <b>${focusHost ? focusHost.name || focusHost.ip : "an unknown node"}</b>: it shares the node's address, so it hears everything that node's network stack carries.`
        : `a pod with its own address (${focusPod.ip}) on <b>${focusHost ? focusHost.name || focusHost.ip : "an unattributed subnet"}</b>: it hears only that pod's traffic.`)
    : focus && focus.level === "node" ? "a whole node's interface."
    : "a router-level tap on the shared network.";
  panel.html(`
    <h2>The testbed</h2>
    <p class="big">${named.length} nodes, ${c.pods.filter(p => !p.host_network).length} pod addresses,
      ${c.services.length} services, ${c.vantages.length} capture taps.</p>
    <p>Nothing here is drawn from a diagram. Each element was <b>inferred from the benign
      recordings</b>: pod addresses live in the cluster's pod range, one /24 per node; each node
      capture claims the address it carries most; services live in the service range.</p>
    ${cp ? `<p>The control plane is <b>${cp.name}</b> (${cp.ip}): it serves the API server${cp.roles.includes("nfs") ? " and the shared NFS storage" : ""}, so every node talks to it.</p>` : ""}
    <h2>Where this story listens</h2>
    <p><span class="mono">${S.meta.vantage}</span> is ${where}</p>
    <h2>Reading the map</h2>
    <div class="legend" style="flex-direction:column;align-items:flex-start">
      <span><i class="disc" style="background:color-mix(in srgb,var(--accent) 16%,var(--surface));border:1.5px solid var(--accent)"></i>pod named by its own capture</span>
      <span><i class="disc" style="background:color-mix(in srgb,var(--s7) 14%,var(--surface));border:1.5px solid var(--s7)"></i>host-network pod (no address of its own)</span>
      <span><i class="disc" style="background:var(--surface-2);border:1px solid var(--axis)"></i>pod seen only in traffic</span>
      <span><i class="disc" style="background:var(--accent)"></i>the tap this story replays · other taps hollow</span>
      <span><i style="background:var(--muted);height:4px"></i>conversation, width by packets (log)</span>
    </div>
    <p style="margin-top:12px">Hover anything for its addresses, ports and packet counts.</p>`);
}

// ---------------------------------------------------------------- act 2: learning

const L = S.learning;
const ptaById = new Map(L.pta.map(n => [n.id, n]));
const ptaChildren = d3.group(L.pta.filter(n => n.parent !== null), n => n.parent);
const stateOfPta = new Map();
for (const s of L.pdfa.states) for (const id of s.pta_ids) stateOfPta.set(id, s.id);
// red (kept) PTA nodes in promotion order: the root, then every promoted blue
const promoted = [0, ...L.steps.filter(s => s.kind === "promote").map(s => s.blue)];

function subtree(id) {
  const out = [], stack = [id];
  while (stack.length) {
    const n = stack.pop();
    out.push(n);
    for (const c of ptaChildren.get(n) || []) stack.push(c.id);
  }
  return out;
}

const learn = { step: 0, timer: null };   // step 0: tree built; k: after step k; N+1: machine

function actLearning() {
  const total = L.steps.length;
  controls.html(`
    <button id="l-prev">◀</button>
    <button class="primary" id="l-play">▶ Play</button>
    <button id="l-next">▶</button>
    <input type="range" id="l-step" min="0" max="${total + 1}" value="${learn.step}">
    <span class="readout" id="l-readout"></span>`);
  const go = k => { learn.step = Math.max(0, Math.min(total + 1, k)); drawLearning(); };
  d3.select("#l-prev").on("click", () => { stopLearn(); go(learn.step - 1); });
  d3.select("#l-next").on("click", () => { stopLearn(); go(learn.step + 1); });
  d3.select("#l-step").on("input", e => { stopLearn(); go(+e.target.value); });
  d3.select("#l-play").on("click", () => {
    if (learn.timer) return stopLearn();
    if (learn.step >= total + 1) learn.step = 0;
    d3.select("#l-play").text("❚❚ Pause");
    learn.timer = d3.interval(() => {
      if (learn.step >= total + 1) return stopLearn();
      go(learn.step + 1);
    }, 1400);
  });
  buildLearning();
  drawLearning();
}

function stopLearn() {
  if (learn.timer) learn.timer.stop();
  learn.timer = null;
  d3.select("#l-play").text("▶ Play");
}

let LG = null;   // learning scene handles

function buildLearning() {
  const { w, h } = size();
  const g = svg.append("g");
  const streamH = 64;
  const tree = { x: 56, y: streamH + 44, w: w * 0.58 - 56, h: h - streamH - 70 };
  const machine = { x: w * 0.58 + 40, y: streamH + 54, w: w * 0.42 - 90, h: h - streamH - 110 };

  // the symbol stream: the training flows, one tick each, colored by protocol
  const stream = L.stream.slice(0, Math.floor((w - 80) / 6));
  const sx = d3.scaleBand().domain(d3.range(stream.length)).range([40, 40 + stream.length * 6]).paddingInner(0.2);
  g.append("text").attr("class", "t-section").attr("x", 40).attr("y", 18)
    .text(`training flows → symbols (${fmt(S.meta.train_flows)} flows, first ${stream.length} shown)`);
  hover(g.append("g").selectAll("rect").data(stream).join("rect")
    .attr("x", (d, i) => sx(i)).attr("y", 26).attr("width", sx.bandwidth()).attr("height", 22).attr("rx", 1.5)
    .attr("fill", d => protoColor(symbolParts(d.symbol).proto)), d => symbolTip(d.symbol)
      + `<div class="tt-row">at ${f1(d.t)} s</div>`);
  g.append("rect").attr("x", sx(0) - 2).attr("y", 23).attr("width", sx.step() * S.meta.trace_len + 2)
    .attr("height", 28).attr("rx", 4).attr("fill", "none").attr("stroke", "var(--ink)").attr("stroke-width", 1.5);
  g.append("text").attr("class", "t-small t-2").attr("x", sx(0) + sx.step() * S.meta.trace_len + 6).attr("y", 60)
    .text(`one trace = ${S.meta.trace_len} consecutive flows, sliding by one`);

  // the prefix tree as an icicle: depth = position in the trace, width = traces through it
  const depth = d3.max(L.pta, n => n.depth);
  const row = tree.h / (depth + 1);
  const x = v => tree.x + v * tree.w;
  g.append("text").attr("class", "t-section").attr("x", tree.x).attr("y", tree.y - 14)
    .text(`prefix tree of ${fmt(L.traces)} traces · ${fmt(L.pta.length)} nodes`);
  for (let d = 0; d <= depth; d++) {
    g.append("text").attr("class", "t-small t-muted").attr("text-anchor", "end")
      .attr("x", tree.x - 8).attr("y", tree.y + d * row + row / 2 + 4).text(d === 0 ? "start" : `flow ${d}`);
  }
  const rects = g.append("g").selectAll("rect").data(L.pta).join("rect")
    .attr("class", "pta-rect")
    .attr("x", n => x(n.x0)).attr("y", n => tree.y + n.depth * row + 1)
    .attr("width", n => Math.max(x(n.x1) - x(n.x0) - 1, 0.5)).attr("height", row - 2).attr("rx", 2);
  hover(rects, n => `<div class="tt-title">${n.symbol ? n.symbol : "start of every trace"}</div>
    <div class="tt-row">${fmt(n.visits)} traces pass here, ${fmt(n.final)} end here</div>
    <div class="tt-row">ends up in state ${stateOfPta.get(n.id)}</div>`);
  const rlabels = g.append("g").selectAll("text").data(L.pta.filter(n => (x(n.x1) - x(n.x0)) > 62 && n.symbol))
    .join("text").attr("class", "t-small halo").attr("x", n => x(n.x0) + 5)
    .attr("y", n => tree.y + n.depth * row + 15).text(n => n.symbol).style("pointer-events", "none");
  const marks = g.append("g");

  // the machine as it forms: states appear as they are promoted
  const mx = v => machine.x + v * machine.w, my = v => machine.y + v * machine.h;
  const rScale = d3.scaleSqrt().domain([0, d3.max(L.pdfa.states, s => s.visits)]).range([10, Math.min(34, machine.h / 8)]);
  g.append("text").attr("class", "t-section").attr("x", machine.x - 20).attr("y", tree.y - 14).text("the learned machine");
  const edgeG = g.append("g"), stateG = g.append("g"), arrowG = g.append("g");
  LG = { g, tree, machine, row, x, rects, rlabels, marks, mx, my, rScale, edgeG, stateG, arrowG };
}

function drawLearning() {
  const total = L.steps.length, k = learn.step;
  d3.select("#l-step").property("value", k);
  const done = L.steps.slice(0, Math.min(k, total));
  const current = k >= 1 && k <= total ? L.steps[k - 1] : null;
  const final = k > total;

  // which PTA nodes are settled: kept states, and every node folded by a finished merge
  const settled = new Set();
  const kept = new Set([0, ...done.filter(s => s.kind === "promote").map(s => s.blue)]);
  for (const s of done) if (s.kind === "merge") for (const id of subtree(s.blue)) settled.add(id);
  for (const id of kept) settled.add(id);
  if (final) for (const n of L.pta) settled.add(n.id);
  // unsettled bars show the raw tree by protocol; settled ones take their state's color
  LG.rects
    .style("fill", n => settled.has(n.id) ? stateColor(stateOfPta.get(n.id))
                     : n.symbol ? protoColor(symbolParts(n.symbol).proto) : "var(--muted)")
    .style("fill-opacity", n => kept.has(n.id) ? 1 : settled.has(n.id) ? 0.72 : 0.22);

  // the step's two states, ringed in the ALERGIA colors
  LG.marks.selectAll("*").remove();
  if (current) {
    for (const [id, role] of [[current.red, "red"], [current.blue, "blue"]]) {
      const n = ptaById.get(id);
      LG.marks.append("rect").attr("x", LG.x(n.x0) - 1).attr("y", LG.tree.y + n.depth * LG.row - 1)
        .attr("width", Math.max(LG.x(n.x1) - LG.x(n.x0) + 1, 4)).attr("height", LG.row + 2).attr("rx", 3)
        .attr("fill", "none").attr("stroke", `var(--${role})`).attr("stroke-width", 3);
    }
  }

  // machine: states present so far; edges only once learning is complete
  const visible = new Set([...kept].map(id => stateOfPta.get(id)));
  const states = L.pdfa.states.filter(s => final || visible.has(s.id));
  const sel = LG.stateG.selectAll("g.state").data(states, s => s.id);
  const enter = sel.enter().append("g").attr("class", "state")
    .attr("transform", s => `translate(${LG.mx(s.x)},${LG.my(s.y)})`).attr("opacity", 0);
  enter.append("circle").attr("class", "state-circle").attr("r", s => LG.rScale(s.visits)).attr("fill", s => stateColor(s.id));
  enter.append("text").attr("text-anchor", "middle").attr("y", 4).attr("class", "t-title halo").text(s => s.id);
  hover(enter, s => `<div class="tt-title">state ${s.id}</div><div class="tt-row">${fmt(s.visits)} training visits</div>
    <div class="tt-row">absorbed ${s.pta_ids.length} prefix-tree nodes</div>`);
  enter.transition().duration(500).attr("opacity", 1);
  sel.exit().transition().duration(300).attr("opacity", 0).remove();

  LG.edgeG.selectAll("*").remove();
  if (final) drawMachineEdges(LG.edgeG, L.pdfa, s => [LG.mx(s.x), LG.my(s.y)], s => LG.rScale(s.visits), { labels: true });

  // a merge points from the candidate into the state that absorbs it
  LG.arrowG.selectAll("*").remove();
  if (current && current.kind === "merge") {
    const n = ptaById.get(current.blue), target = L.pdfa.states.find(s => s.id === stateOfPta.get(current.red));
    const from = [LG.x((n.x0 + n.x1) / 2), LG.tree.y + n.depth * LG.row + LG.row / 2];
    const to = [LG.mx(target.x) - LG.rScale(target.visits) - 4, LG.my(target.y)];
    LG.arrowG.append("path").attr("d", `M${from[0]},${from[1]} C${(from[0] + to[0]) / 2},${from[1] - 60} ${(from[0] + to[0]) / 2},${to[1]} ${to[0]},${to[1]}`)
      .attr("fill", "none").attr("stroke", "var(--red)").attr("stroke-width", 2).attr("stroke-dasharray", "5 4")
      .attr("marker-end", "url(#arrow-red)");
  }
  learningPanel(current, final, k);
}

// transitions of a machine, one curve per state pair: the symbols that share a pair are
// listed on hover and their probabilities add up to the curve's width
function machineLinks(pdfa) {
  return d3.groups(pdfa.edges, e => `${e.src}>${e.dst}`).map(([key, group]) => ({
    key, src: group[0].src, dst: group[0].dst,
    prob: d3.sum(group, e => e.prob),
    symbols: group.slice().sort((a, b) => d3.descending(a.prob, b.prob)),
  }));
}

function drawMachineEdges(g, pdfa, at, radius, { labels = false } = {}) {
  const byId = new Map(pdfa.states.map(s => [s.id, s]));
  const links = machineLinks(pdfa);
  const sel = g.selectAll("path.edge").data(links, l => l.key).join("path").attr("class", "edge")
    .attr("stroke-width", l => 1 + 4.5 * Math.min(l.prob, 1))
    .attr("stroke-opacity", l => 0.3 + 0.55 * Math.min(l.prob, 1))
    .attr("marker-end", "url(#arrow)")
    .attr("d", edgePath);
  hover(sel, l => `<div class="tt-title">state ${l.src} → state ${l.dst}</div>
    <div class="tt-row">probability ${f2(l.prob)} over ${l.symbols.length} symbol${l.symbols.length === 1 ? "" : "s"}</div>
    ${l.symbols.slice(0, 8).map(e => `<div class="tt-row mono">${e.symbol} · ${f2(e.prob)}</div>`).join("")}
    ${l.symbols.length > 8 ? `<div class="tt-row">+${l.symbols.length - 8} more</div>` : ""}`);
  if (labels) {
    g.selectAll("text.edge-label").data(links.filter(l => l.prob >= 0.2), l => l.key).join("text")
      .attr("class", "edge-label halo").attr("text-anchor", "middle")
      .attr("x", l => labelAt(l)[0]).attr("y", l => labelAt(l)[1])
      .text(l => l.symbols.length === 1 ? `${l.symbols[0].symbol} ${f2(l.prob)}`
                                        : `${l.symbols.length} symbols · ${f2(l.prob)}`);
  }
  return sel;

  function geometry(l) {
    const a = byId.get(l.src), b = byId.get(l.dst);
    const [ax, ay] = at(a), [bx, by] = at(b);
    return { a, b, ax, ay, bx, by, ra: radius(a), rb: radius(b) };
  }
  function edgePath(l) {
    const { ax, ay, bx, by, ra, rb } = geometry(l);
    if (l.src === l.dst) {
      const x1 = ax - ra * 0.55, x2 = ax + ra * 0.55, y0 = ay - ra * 0.82, lift = ra + 26;
      return `M${x1},${y0} C${x1 - 16},${ay - lift} ${x2 + 16},${ay - lift} ${x2},${y0}`;
    }
    const dx = bx - ax, dy = by - ay, len = Math.hypot(dx, dy) || 1, bend = 22;
    const cx = (ax + bx) / 2 - dy / len * bend, cy = (ay + by) / 2 + dx / len * bend;
    const s0 = toward(ax, ay, cx, cy, ra + 2), s1 = toward(bx, by, cx, cy, rb + 5);
    return `M${s0[0]},${s0[1]} Q${cx},${cy} ${s1[0]},${s1[1]}`;
  }
  function labelAt(l) {
    const { ax, ay, bx, by, ra } = geometry(l);
    if (l.src === l.dst) return [ax, ay - ra - 26];
    const dx = bx - ax, dy = by - ay, len = Math.hypot(dx, dy) || 1;
    // a third of the way from the source, so labels of edges into one state do not stack
    return [ax + dx * 0.36 - dy / len * 16, ay + dy * 0.36 + dx / len * 16 + 3];
  }
}

function toward(x, y, tx, ty, distance) {
  const dx = tx - x, dy = ty - y, len = Math.hypot(dx, dy) || 1;
  return [x + dx / len * distance, y + dy / len * distance];
}

function learningPanel(step, final, k) {
  const total = L.steps.length;
  const promotes = L.steps.filter(s => s.kind === "promote").length;
  const readout = final ? `Learned: ${L.pdfa.states.length} states, ${L.pdfa.edges.length} transitions`
    : step ? `Step ${k} of ${total} · ${step.kind}` : "Prefix tree built";
  d3.select("#l-readout").text(readout);
  if (final) {
    panel.html(`
      <h2>The machine</h2>
      <p class="big">${fmt(L.pta.length)} prefix-tree nodes folded into <b>${L.pdfa.states.length} states</b>
        and ${L.pdfa.edges.length} transitions.</p>
      <p>Each circle is a state, sized by training visits; each arrow is a transition, wider when more
        likely. Labels show transitions taken at least a quarter of the time.</p>
      <p>A trace that needs an arrow the machine lacks has done something benign traffic never did:
        that is what the detection act watches for, alongside how <i>often</i> each state is visited.</p>
      <h2>Symbols the machine knows</h2>
      <div class="chips">${L.symbols.map(s => chip(s.symbol)).join("")}</div>
      <p style="margin-top:10px">Symbol = <span class="mono">protocol_bytes_duration</span>, sizes binned on
        benign quantiles. Hover a chip in the stream above for its byte and duration range.</p>
      ${protocolLegend()}`);
    return;
  }
  if (!step) {
    panel.html(`
      <h2>1 · Every trace, verbatim</h2>
      <p class="big">${fmt(L.traces)} benign traces become a prefix tree: one bar per distinct prefix,
        as wide as the number of traces that share it.</p>
      <p>The tree memorizes. It cannot generalize: any trace it has not seen exactly falls off it.</p>
      <h2>2 · Merge what behaves alike</h2>
      <p>ALERGIA walks the tree. The <b style="color:var(--blue)">blue</b> candidate is compared with each
        <b style="color:var(--red)">red</b> state already kept. If, for every next symbol, the two
        next-step probabilities differ by less than the <b>Hoeffding bound</b>, the candidate is folded
        into the red state; otherwise it is promoted to a new red state.</p>
      <p>${total} steps here: ${promotes} promotions, ${total - promotes} merges. Press <b>Play</b>.</p>
      ${protocolLegend()}`);
    return;
  }
  const passing = step.tests.filter(t => Math.abs(t.p_red - t.p_blue) < step.bound).length;
  const verdict = step.kind === "merge"
    ? `<b>Merged.</b> Every symbol's probabilities sit within ±${f2(step.bound)}, so the candidate (${fmt(step.blue_visits)} traces) folds into state ${stateOfPta.get(step.red)} (${fmt(step.red_visits)} traces).`
    : `<b>Promoted.</b> ${step.tests.length - passing} of ${step.tests.length} symbols differ by more than ±${f2(step.bound)} from the last red state tried, so the candidate becomes <b>state ${stateOfPta.get(step.blue)}</b>.`;
  panel.html(`
    <h2>Step ${k} of ${total}</h2>
    <p class="big">${verdict}</p>
    <p>Candidate path: ${(pathOf(step.blue).map(s => chip(s)).join(" ") || "<i>start</i>")}</p>
    <h2>The Hoeffding test</h2>
    <p>Next-symbol probability in the <b style="color:var(--red)">red</b> state and the
      <b style="color:var(--blue)">blue</b> candidate. The shaded band is red ± bound; blue must land
      inside it for every symbol.</p>
    <svg id="hoeffding" width="300"></svg>`);
  drawHoeffding(step);
}

function pathOf(id) {
  const path = [];
  for (let n = ptaById.get(id); n && n.symbol; n = ptaById.get(n.parent)) path.unshift(n.symbol);
  return path;
}

function protocolLegend() {
  return `<h2>Protocols</h2><div class="legend">${protocols.map(p =>
    `<span><i class="disc" style="background:${protoColor(p)}"></i>${p}</span>`).join("")}</div>`;
}

function drawHoeffding(step) {
  const tests = step.tests.slice().sort((a, b) => (a.symbol === "#") - (b.symbol === "#")
    || d3.descending(Math.max(a.p_red, a.p_blue), Math.max(b.p_red, b.p_blue))).slice(0, 12);
  const rowH = 24, left = 118, w = 300, h = tests.length * rowH + 26;
  const g = d3.select("#hoeffding").attr("height", h).attr("viewBox", `0 0 ${w} ${h}`);
  const x = d3.scaleLinear().domain([0, 1]).range([left, w - 26]);
  g.append("g").attr("class", "axis").attr("transform", `translate(0,${h - 18})`)
    .call(d3.axisBottom(x).ticks(4).tickSize(3));
  tests.forEach((t, i) => {
    const y = i * rowH + 12, ok = Math.abs(t.p_red - t.p_blue) < step.bound;
    g.append("text").attr("class", "t-small mono").attr("x", 0).attr("y", y + 4)
      .text(t.symbol === "#" ? "(trace ends)" : t.symbol);
    g.append("line").attr("x1", x(0)).attr("x2", x(1)).attr("y1", y).attr("y2", y).attr("stroke", "var(--grid)");
    g.append("rect").attr("x", x(Math.max(0, t.p_red - step.bound))).attr("y", y - 6)
      .attr("width", x(Math.min(1, t.p_red + step.bound)) - x(Math.max(0, t.p_red - step.bound)))
      .attr("height", 12).attr("rx", 3).attr("fill", "var(--red)").attr("fill-opacity", 0.14);
    g.append("circle").attr("cx", x(t.p_red)).attr("cy", y).attr("r", 4.5).attr("fill", "var(--red)").attr("stroke", "var(--surface)").attr("stroke-width", 2);
    g.append("circle").attr("cx", x(t.p_blue)).attr("cy", y).attr("r", 4.5).attr("fill", "var(--blue)").attr("stroke", "var(--surface)").attr("stroke-width", 2);
    g.append("text").attr("x", w - 4).attr("y", y + 4).attr("text-anchor", "end")
      .attr("fill", ok ? "var(--good-ink)" : "var(--critical)").style("fill", ok ? "var(--good-ink)" : "var(--critical)")
      .text(ok ? "✓" : "✗");
  });
}

// ---------------------------------------------------------------- act 3: detection
function actDetection() {
  panel.html(`<h2>Detection</h2><p>Coming in the next step.</p>`);
}

// ---------------------------------------------------------------- app shell

const ACTS = { cluster: actCluster, learning: actLearning, detection: actDetection };
let currentAct = "cluster";

function show(act) {
  stopLearn();
  if (window.__stopPlayer) window.__stopPlayer();
  currentAct = act;
  d3.selectAll(".acts button").attr("aria-selected", function () { return this.dataset.act === act; });
  svg.selectAll("*").remove();
  controls.html("");
  hideTip();
  defs();
  ACTS[act]();
  try { localStorage.setItem("story-act", act); } catch (e) { /* storage may be blocked */ }
}

d3.selectAll(".acts button").on("click", function () { show(this.dataset.act); });
d3.select("#theme").on("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
});
d3.select("#subtitle").text(`${S.meta.vantage} · ${S.meta.trace_len}-flow traces · `
  + `${S.meta.forget_seconds} s anomaly clock · built ${S.meta.generated.slice(0, 10)}`);
let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => show(currentAct), 150);
});
let start = "cluster";
try { start = new URLSearchParams(location.search).get("act") || localStorage.getItem("story-act") || start; } catch (e) { /* ignore */ }
show(ACTS[start] ? start : "cluster");
})();
