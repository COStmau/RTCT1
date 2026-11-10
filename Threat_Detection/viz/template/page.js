// The state-machine page renderer. It owns no data: everything comes from window.VIZ,
// the bundle viz/page.py builds from the pipeline. Served by viz/serve.py (VIZ_SERVER), the
// Data tab can replace that bundle with one built from other captures; load() swaps it in. Positions come from the bundle's computed
// layouts or from layout rules below that read only the bundle; colors are CSS roles.
// Vendored D3: d3js.org v7.9.0, sha256 f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539
(() => {
"use strict";
// the page carries several vantages around one shared cluster; S is the selected one, laid
// out as a single-vantage block (meta, learning, playback, cluster) so every act reads it alike
let B = window.VIZ;
const SERVER = Boolean(window.VIZ_SERVER);
let VANTAGES = B ? Object.keys(B.vantages) : [];
let S = null;
let mode = "detail";   // "detail": the three acts; "demo": the short concept walkthrough
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
let protocols = [];   // the selected vantage's, in its symbol order
const protoColor = proto => {
  const i = protocols.indexOf(proto);
  return `var(${PROTO_SLOTS[i] || "--other"})`;
};

function size() {
  const node = document.getElementById("canvas");
  return { w: node.clientWidth, h: node.clientHeight };
}

function showTip(event, html) {
  if (mode === "demo") return;
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
  const unit = kind === "bytes" ? " B" : " s";
  const show = v => kind === "bytes" ? fmt(Math.round(v)) : (v < 0.01 && v > 0 ? v.toExponential(1) : f2(v));
  // every training flow tied on one value, so there is one edge and no range
  if (edges && edges.length === 1) return `${show(edges[0])}${unit} (every training flow)`;
  if (!edges || !(index >= 0) || index + 1 >= edges.length) return bin;
  return `${show(edges[index])}–${show(edges[index + 1])}${unit}`;
}

function symbolTip(symbol) {
  const p = symbolParts(symbol);
  return `<div class="tt-title mono">${symbol}</div>
    <div class="tt-row">protocol ${p.proto}</div>
    <div class="tt-row">bytes bin ${p.bytes}: ${binText("bytes", p.bytes)}</div>
    <div class="tt-row">duration bin ${p.duration}: ${binText("duration", p.duration)}</div>`;
}

// machine transitions at or above this probability carry a label, here and in the copy
const LABEL_MIN = 0.25;

// a row of legend items laid out by their measured text width, wrapping inside maxWidth;
// items are [text, draw(g)] where draw puts a 18x10 swatch at the origin. Returns height.
function legendRow(g, items, maxWidth, { align = "start" } = {}) {
  const rows = [[]];
  let x = 0;
  for (const [text, draw] of items) {
    const item = g.append("g");
    draw(item);
    const label = item.append("text").attr("class", "t-small t-2").attr("x", 24).attr("y", 0).text(text);
    const width = 24 + label.node().getComputedTextLength() + 16;
    if (x > 0 && x + width > maxWidth) { rows.push([]); x = 0; }
    rows[rows.length - 1].push([item, x, width]);
    x += width;
  }
  rows.forEach((row, r) => {
    const used = row.length ? row[row.length - 1][1] + row[row.length - 1][2] - 16 : 0;
    const shift = align === "end" ? maxWidth - used : 0;
    for (const [item, ix] of row) item.attr("transform", `translate(${shift + ix},${r * 16})`);
  });
  return rows.length * 16;
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
function renderCluster(g, cluster, box, { focus = null, compact = false, onTap = null } = {}) {
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
        lines.forEach((line, i) => hostG.append("text").attr("class", "t-small t-muted detail")
          .attr("x", r.x + 12).attr("y", r.y + 35 + i * 13).text(fit(line, r.w - 24)));
      }
    } else if (!compact) {
      hostG.append("text").attr("class", "t-small t-muted detail").attr("x", r.x + 12).attr("y", r.y + 20)
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
          .attr("class", `pod ${p.host_network ? "hostnet" : p.name ? "named" : ""} ${p.new ? "new" : ""}`)
          .attr("data-id", p.id).attr("cx", cx).attr("cy", cy).attr("r", rr).datum(p);
        hover(circle, d => `<div class="tt-title">${d.name || "pod " + d.ip}</div>
          <div class="tt-row">${d.host_network ? "host network: shares the node's address " + d.ip + ", so its traffic is drawn on the node" : "pod address " + d.ip}</div>
          ${d.new ? `<div class="tt-row">never seen in benign traffic</div>` : ""}`);
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
    g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", upY - 8).text("LAN uplink");
    g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", top.y + top.h * 0.24 + 4).text("outside");
  }
  outside.forEach((e, i) => {
    const ex = box.x + box.w * (0.16 + 0.8 * (i + 0.5) / outside.length), ey = top.y + top.h * 0.24;
    pos.set(e.id, { x: ex, y: ey, r: compact ? 5 : 9, kind: "external" });
    hover(g.append("circle").attr("class", `ext ${e.kind} ${e.new ? "new" : ""}`).attr("cx", ex).attr("cy", ey).attr("r", compact ? 5 : 9).datum(e),
      d => (d.kind === "host"
        ? `<div class="tt-title">host ${d.ip}</div><div class="tt-row">${d.roles.join(", ")} · serves a cluster port; no capture of its own</div>`
        : `<div class="tt-title">${d.kind === "internet" ? "the internet" : "LAN device " + d.ip}</div>
           ${d.note ? `<div class="tt-row">${d.note}; not proven to be a node</div>` : ""}`)
        + (d.new ? `<div class="tt-row">never seen in benign traffic</div>` : ""));
    if (!compact) g.append("text").attr("class", "t-small t-2 detail").attr("text-anchor", "middle")
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
    const w = compact ? 46 : 150, h = compact ? 14 : 30;
    pos.set(s.id, { x: sx, y: sy - h / 2, kind: "service" });
    hover(g.append("rect").attr("class", `svc ${s.new ? "new" : ""}`).attr("x", sx - w / 2).attr("y", sy - h / 2)
      .attr("width", w).attr("height", h).attr("rx", h / 2).datum(s),
      d => `<div class="tt-title">service ${d.ip}</div><div class="tt-row">${d.port_names.join(", ") || "no well-known port"}</div>`);
    if (!compact) g.append("text").attr("class", "detail").attr("text-anchor", "middle").attr("x", sx).attr("y", sy + 4)
      .text(`${s.ip}${s.port_names.length ? " · " + s.port_names.join(", ") : ""}`).style("pointer-events", "none");
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
    ${e.new ? `<div class="tt-row">never seen in benign traffic · ${fmt(e.packets)} flow${e.packets === 1 ? "" : "s"} in this recording</div>`
            : `<div class="tt-row">${fmt(e.packets)} packets at the best vantage</div>
               <div class="tt-row">${e.ports.join(", ") || "ephemeral ports"}</div>`}`);

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
    const isFocus = v.label === focus, onPage = Boolean(B.vantages[v.label]);
    const tg = taps.append("g")
      .attr("class", `tap ${isFocus ? "focus" : ""} ${onPage ? "on-page" : "off-page"}`)
      .attr("data-label", v.label).attr("transform", `translate(${tx},${ty})`).datum(v);
    if (isFocus) tg.append("circle").attr("class", "tap-halo").attr("r", compact ? 8 : 12);
    tg.append("circle").attr("class", "tap-dot").attr("r", compact ? 3.5 : 5);
    // a wider invisible target, so a 5 px dot is easy to click
    tg.append("circle").attr("class", "tap-hit").attr("r", compact ? 8 : 12);
    if (isFocus && !compact) tg.append("text").attr("class", "t-small halo").attr("x", 10).attr("y", -8).text(`listening: ${v.label}`);
    hover(tg, d => `<div class="tt-title">capture tap: ${d.label}</div><div class="tt-row">${d.level}-level recording</div>
      <div class="tt-row">${d.label === focus ? "the tap this page replays"
        : B.vantages[d.label] ? "click to replay from this tap"
        : absentWhy(d.label)}</div>`);
    if (onTap && onPage && !isFocus) tg.on("click", (event, d) => { hideTip(); onTap(d.label); });
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

// why a tap on the map has no block on this page: bulk transfer is policy, anything else
// was just not chosen when the page was built
function absentWhy(label) {
  const reason = (B.absent || {})[label];
  return reason === "bulk transfer"
    ? "not on this page: a bulk-transfer tap never sets a cutoff (rebuild with --allow-bulk)"
    : reason === "too few flows"
      ? "not on this page: its benign capture has too few flows to learn a machine from"
      : "not on this page: not chosen when it was built (add it with --vantages)";
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
  renderCluster(svg.append("g"), c, box, { focus: S.meta.vantage, onTap: switchTo });
  const absent = c.vantages.filter(v => !B.vantages[v.label]).map(v => v.label);

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
    <h2>Where this page listens</h2>
    <p><span class="mono">${S.meta.vantage}</span> is ${where}</p>
    <p>This page carries <b>${VANTAGES.length} taps</b>. Click any other tap on the map, or pick one
      at the top, and the learning and detection acts replay from there.${absent.length
        ? ` Not on this page (drawn faint): ${[["bulk transfer", "a bulk-transfer tap never sets a cutoff, so it is left out unless the page is built with <span class=\"mono\">--allow-bulk</span>"],
                                               ["too few flows", "its benign capture has too few flows to learn a machine from (long-lived connections, such as a connection pool, make few flows)"],
                                               ["not chosen", "not chosen when the page was built; add with <span class=\"mono\">--vantages</span>"]]
            .map(([reason, why]) => {
              const these = absent.filter(l => ((B.absent || {})[l] || "not chosen") === reason);
              return these.length ? `${these.map(l => `<span class="mono">${l}</span>`).join(", ")} (${why})` : "";
            }).filter(Boolean).join("; ")}.`
        : ""}</p>
    <h2>Reading the map</h2>
    <div class="legend" style="flex-direction:column;align-items:flex-start">
      <span><i class="disc" style="background:color-mix(in srgb,var(--accent) 16%,var(--surface));border:1.5px solid var(--accent)"></i>pod named by its own capture</span>
      <span><i class="disc" style="background:color-mix(in srgb,var(--s7) 14%,var(--surface));border:1.5px solid var(--s7)"></i>host-network pod (no address of its own)</span>
      <span><i class="disc" style="background:var(--surface-2);border:1px solid var(--axis)"></i>pod seen only in traffic</span>
      <span><i class="disc" style="background:var(--accent)"></i>the tap this page replays · hollow taps switch to theirs</span>
      <span><i style="background:var(--muted);height:4px"></i>conversation, width by packets (log)</span>
    </div>
    <p style="margin-top:12px">Hover anything for its addresses, ports and packet counts.</p>`);
}

// ---------------------------------------------------------------- act 2: learning

// the selected vantage's learning, and its prefix-tree indexes (set by selectVantage)
let L = null, ptaById = null, stateOfPta = null;
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
    .text(`training flows → symbols (${fmt(S.meta.train_flows)} flows, first ${stream.length} shown`
      + `${S.meta.dropped_flows ? ` · ${fmt(S.meta.dropped_flows)} crossed a window boundary and were dropped` : ""})`);
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

  // a bar takes its state's colour once it belongs to a kept state at this step. viz/page.py
  // replays the folds: a merged candidate's children fold into the kept state's children,
  // which may still be candidates, so they settle later, never before their state exists
  const kept = new Set([0, ...done.filter(s => s.kind === "promote").map(s => s.blue)]);
  const settled = n => final || n.settled_step <= k;
  LG.rects
    .style("fill", n => settled(n) ? stateColor(stateOfPta.get(n.id))
                     : n.symbol ? protoColor(symbolParts(n.symbol).proto) : "var(--muted)")
    .style("fill-opacity", n => kept.has(n.id) ? 1 : settled(n) ? 0.72 : 0.22);

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
    g.selectAll("text.edge-label").data(links.filter(l => l.prob >= LABEL_MIN), l => l.key).join("text")
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
  const total = L.steps.length, all = L.steps_total;
  const promotes = L.steps.filter(s => s.kind === "promote").length;
  const capped = all > total ? ` (first ${fmt(total)} of ${fmt(all)} shown; the rest land at the end)` : "";
  const readout = final ? `Learned: ${L.pdfa.states.length} states, ${L.pdfa.edges.length} transitions`
    : step ? `Step ${k} of ${total}${all > total ? ` (of ${all})` : ""} · ${step.kind}` : "Prefix tree built";
  d3.select("#l-readout").text(readout);
  if (final) {
    panel.html(`
      <h2>The machine</h2>
      <p class="big">${fmt(L.pta.length)} prefix-tree nodes folded into <b>${L.pdfa.states.length} states</b>
        and ${L.pdfa.edges.length} transitions.</p>
      <p>Each circle is a state, sized by training visits; each arrow is a transition, wider when more
        likely. Labels show transitions taken at least ${Math.round(LABEL_MIN * 100)}% of the time.</p>
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
      <p>${total} steps here${capped}: ${promotes} promotions, ${total - promotes} merges. Press <b>Play</b>.</p>
      ${protocolLegend()}`);
    return;
  }
  // every kept state the candidate was tested against, in order; the last one decided it
  const failing = a => a.tests.filter(t => Math.abs(t.p_red - t.p_blue) >= a.bound)
    .sort((x, y) => d3.descending(Math.abs(x.p_red - x.p_blue), Math.abs(y.p_red - y.p_blue)));
  const tried = step.attempts.map((a, i) => {
    const worst = failing(a)[0];
    return `<button class="attempt" data-i="${i}" aria-pressed="${i === step.attempts.length - 1}">
      <span class="sid" style="background:${stateColor(stateOfPta.get(a.red))}">${stateOfPta.get(a.red)}</span>
      ${worst ? `✗ <span class="mono">${worst.symbol === "#" ? "(ends)" : worst.symbol}</span> differs by ${f2(Math.abs(worst.p_red - worst.p_blue))} &gt; ±${f2(a.bound)}`
              : `✓ every symbol within ±${f2(a.bound)}`}</button>`;
  }).join("");
  const earlier = step.attempts.length - 1;
  const verdict = step.kind === "merge"
    ? `<b>Merged</b> into state ${stateOfPta.get(step.red)}${earlier ? ` after failing against ${earlier} earlier kept state${earlier === 1 ? "" : "s"}` : ""}: the candidate (${fmt(step.blue_visits)} traces) behaves like it.`
    : `<b>Promoted.</b> The candidate failed against every kept state (${step.attempts.length}), so it becomes <b>state ${stateOfPta.get(step.blue)}</b>.`;
  panel.html(`
    <h2>Step ${k} of ${total}${all > total ? ` (of ${fmt(all)})` : ""}</h2>
    <p class="big">${verdict}</p>
    <p>Candidate path: ${(pathOf(step.blue).map(s => chip(s)).join(" ") || "<i>start</i>")}</p>
    <h2>Tested against</h2>
    <div class="attempts">${tried}</div>
    <h2>The Hoeffding test · against state <span id="h-state"></span></h2>
    <p>Next-symbol probability in the <b style="color:var(--red)">red</b> state and the
      <b style="color:var(--blue)">blue</b> candidate. The shaded band is red ± bound; blue must land
      inside it for every symbol. Pick another state above to see its test.</p>
    <svg id="hoeffding" width="300"></svg>`);
  const pick = i => {
    d3.selectAll(".attempt").attr("aria-pressed", function () { return +this.dataset.i === i; });
    d3.select("#h-state").text(stateOfPta.get(step.attempts[i].red));
    d3.select("#hoeffding").selectAll("*").remove();
    drawHoeffding(step.attempts[i]);
  };
  d3.selectAll(".attempt").on("click", function () { pick(+this.dataset.i); });
  pick(step.attempts.length - 1);
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

// the rows the Hoeffding chart shows: failing symbols first, so a promotion always shows
// why, then the most probable; at most 12
function hoeffdingRows(step) {
  const fails = t => Math.abs(t.p_red - t.p_blue) >= step.bound;
  return step.tests.slice().sort((a, b) => fails(b) - fails(a)
    || (a.symbol === "#") - (b.symbol === "#")
    || d3.descending(Math.max(a.p_red, a.p_blue), Math.max(b.p_red, b.p_blue))).slice(0, 12);
}
window.VIZ_CHECKS = { hoeffdingRows };

function drawHoeffding(step) {
  const tests = hoeffdingRows(step);
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
// The replay: one Player clock drives every view. Views subscribe with player.on("tick").
const HEAT = ["--div-n3", "--div-n2", "--div-n1", "--div-0", "--div-p1", "--div-p2", "--div-p3"];
const HEAT_EDGES = [-2, -1, -0.4, 0.4, 1, 2];   // log2(visits in clock / visits expected)
const heatColor = ratio => `var(${HEAT[d3.bisectRight(HEAT_EDGES, Math.log2(ratio))]})`;

// view: "tap" replays one tap in full; "taps" lines the same scenario up across every tap
const player = {
  capture: 0, t: 0, view: "tap", playing: false, speed: 2, timer: null, last: null, listeners: [],
  on(name, fn) { this.listeners.push(fn); },
  emit() { for (const fn of this.listeners) fn(this.t); },
  play() {
    const c = capture();
    if (this.t >= c.end - 1e-6) this.t = c.begin;
    this.playing = true; this.last = null;
    d3.select("#d-play").text("❚❚ Pause");
    if (!this.timer) this.timer = d3.timer(elapsed => this.frame(elapsed));
  },
  pause() {
    this.playing = false;
    d3.select("#d-play").text("▶ Play");
    if (this.timer) { this.timer.stop(); this.timer = null; }
  },
  frame(elapsed) {
    if (this.last !== null) this.t += (elapsed - this.last) / 1000 * this.speed;
    this.last = elapsed;
    const c = capture();
    if (this.t >= c.end) { this.t = c.end; this.pause(); }
    this.emit();
  },
  seek(t) { const c = capture(); this.t = Math.max(c.begin, Math.min(c.end, t)); this.emit(); },
};
window.__stopPlayer = () => player.pause();

// per-capture indexes, built once: every state visit in time order, for the anomaly clock
const prepared = new Map();
function capture() {
  const i = player.capture;
  if (!prepared.has(i)) {
    const c = S.playback.captures[i];
    const vt = [], vs = [];
    for (const tr of c.traces) for (const s of tr.states) { vt.push(tr.t); vs.push(s); }
    const [begin, end] = replaySpan(c, i, S.meta.window_size);
    prepared.set(i, { c, vt, vs, tt: c.traces.map(tr => tr.t), begin, end });
  }
  return prepared.get(i);
}

// [first, last] second a capture's replay shows, on its own clock. Capture 0 is the held-out
// benign: it starts at its first held-out window, since the earlier seconds trained the model
function replaySpan(c, i, ws) {
  return [i === 0 ? Math.floor(c.start_s / ws) * ws : 0, c.duration_s];
}

function actDetection() {
  const caps = S.playback.captures;
  controls.html(`
    <select id="d-cap" aria-label="recording">${caps.map((c, i) =>
      `<option value="${i}" ${i === player.capture ? "selected" : ""}>${c.scenario}${c.scored_windows ? "" : " · no scored windows"}</option>`).join("")}</select>
    <div class="seg" id="d-view" role="group" aria-label="view">${[["tap", "This tap"], ["taps", "Across taps"]].map(([v, text]) =>
      `<button data-v="${v}" aria-pressed="${v === player.view}">${text}</button>`).join("")}</div>
    <button class="primary" id="d-play">▶ Play</button>
    <div class="seg" id="d-speed">${[1, 2, 4, 8].map(v =>
      `<button data-v="${v}" aria-pressed="${v === player.speed}">${v}×</button>`).join("")}</div>
    <span class="readout" id="d-time"></span>
    <span class="spacer"></span>
    <span class="readout">clock ${S.meta.forget_seconds} s · alert after ${S.meta.persistence} flagged windows in a row</span>`);
  d3.select("#d-cap").on("change", e => { player.pause(); player.capture = +e.target.value; player.t = capture().begin; rebuild(); });
  d3.selectAll("#d-view button").on("click", function () {
    player.view = this.dataset.v;
    d3.selectAll("#d-view button").attr("aria-pressed", function () { return this.dataset.v === player.view; });
    rebuild();
  });
  d3.select("#d-play").on("click", () => player.playing ? player.pause() : player.play());
  d3.selectAll("#d-speed button").on("click", function () {
    player.speed = +this.dataset.v;
    d3.selectAll("#d-speed button").attr("aria-pressed", function () { return +this.dataset.v === player.speed; });
  });
  if (player.t < capture().begin || player.t > capture().end) player.t = capture().begin;
  rebuild();
}

function rebuild() {
  svg.selectAll("*").remove();
  defs();
  player.listeners = [];
  const { w, h } = size();
  if (player.view === "taps") {
    acrossTaps(svg.append("g"), { x: 20, y: 16, w: w - 40, h: h - 24 });
  } else {
    const top = { x: 24, y: 16, w: w * 0.62 - 24, h: h * 0.56 - 16 };
    const inset = { x: w * 0.64, y: 34, w: w * 0.36 - 20, h: h * 0.56 - 40 };
    const strip = { x: 70, y: h * 0.59, w: w - 100, h: h * 0.41 - 30 };
    machineView(svg.append("g"), top);
    clusterInset(svg.append("g"), inset);
    scoreStrip(svg.append("g"), strip);
    detectionPanel();
  }
  window.onkeydown = e => {
    // keys belong to the playback only when nothing focusable has them
    const owner = e.target.closest && e.target.closest("button, input, select, textarea, a");
    if (currentAct !== "detection" || owner) return;
    if (e.code === "Space") { e.preventDefault(); player.playing ? player.pause() : player.play(); }
    if (e.code === "ArrowRight") player.seek(player.t + 1);
    if (e.code === "ArrowLeft") player.seek(player.t - 1);
  };
  player.emit();
}

// index of the last trace at or before t, -1 if none
const traceAt = t => d3.bisectRight(capture().tt, t) - 1;

// where each state sits in `box`: the layout as computed; with `turn`, turned a quarter when
// that leaves the two closest states further apart; with `ring`, spaced evenly around an
// ellipse filling the box, start state at the top, in the computed layout's order around its
// middle. A layered layout lines a busy layer up in one row and its edges run over each
// other; on a ring no three states line up, so every edge has its own path.
function stateSpot(states, box, pad, { turn = false, ring = false } = {}) {
  const make = flip => s => {
    const u = flip ? s.y : s.x, v = flip ? s.x : s.y;
    return [box.x + pad + u * (box.w - 2 * pad), box.y + pad + v * (box.h - 2 * pad)];
  };
  if (ring) return ringSpot(states, box, pad, make(false));
  if (!turn) return make(false);
  const gap = at => d3.min(states.flatMap((a, i) => states.slice(i + 1)
    .map(b => Math.hypot(at(a)[0] - at(b)[0], at(a)[1] - at(b)[1])))) ?? Infinity;
  return gap(make(true)) > gap(make(false)) ? make(true) : make(false);
}

function ringSpot(states, box, pad, base) {
  const cx = box.x + box.w / 2, cy = box.y + box.h / 2 + 8;   // a little low: loops rise above states
  if (states.length < 2) return () => [cx, cy];
  const rx = Math.max(box.w / 2 - pad - 24, 10), ry = Math.max(box.h / 2 - pad - 8, 10);
  // clockwise order around the computed layout's middle, from the start state
  const mx = d3.mean(states, s => base(s)[0]), my = d3.mean(states, s => base(s)[1]);
  const turnOf = s => Math.atan2(base(s)[0] - mx, my - base(s)[1]);
  const start = states.find(s => s.id === 0) || states[0], a0 = turnOf(start);
  const order = states.slice().sort((a, b) => a === start ? -1 : b === start ? 1
    : ((turnOf(a) - a0 + 4 * Math.PI) % (2 * Math.PI)) - ((turnOf(b) - a0 + 4 * Math.PI) % (2 * Math.PI)));
  // equal steps along the ellipse itself, so a wide box does not bunch states at its ends
  const N = 720, pts = d3.range(N + 1).map(i => {
    const t = i / N * 2 * Math.PI;
    return [cx + rx * Math.sin(t), cy - ry * Math.cos(t)];
  });
  const run = [0];
  for (let i = 1; i <= N; i++) run.push(run[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
  const spot = new Map(order.map((s, k) => [s.id, pts[Math.min(N, d3.bisectLeft(run, run[N] * k / order.length))]]));
  return s => spot.get(s.id);
}

function machineView(g, box, { turn = false, ring = false } = {}) {
  const states = L.pdfa.states;
  const pad = 60;
  const at = stateSpot(states, box, pad, { turn, ring });
  // each state plus its clock ring must fit halfway to its own nearest neighbour
  const nearest = new Map(states.map(a => [a.id, d3.min(states.filter(b => b !== a),
    b => Math.hypot(at(a)[0] - at(b)[0], at(a)[1] - at(b)[1])) ?? Infinity]));
  const rScale = d3.scaleSqrt().domain([0, d3.max(states, s => s.visits)]).range([12, Math.min(40, box.h / 5)]);
  const radius = s => Math.max(9, Math.min(rScale(s.visits), nearest.get(s.id) / 2 - 22));
  g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", box.y + 4)
    .text("the machine · each dot circles its state's clock once, then is forgotten");
  const links = drawMachineEdges(g.append("g"), L.pdfa, at, radius);
  // a test trace counts the states it walks into, so the training rate is the same thing:
  // entries, not visits (the start state's visits also count every trace that began there)
  const forget = S.meta.forget_seconds, span = Math.max(S.meta.train_span_s, 1e-9);
  const expected = s => Math.max(s.entries * forget / span, 1e-3);
  const MAX_DOTS = 40;   // per state; past it the ring shows a sample and the count says how many

  const sg = g.append("g").selectAll("g").data(states).join("g")
    .attr("transform", s => `translate(${at(s)})`);
  sg.append("circle").attr("class", "clock-track").attr("r", s => radius(s) + 15);
  sg.append("line").attr("class", "clock-noon").attr("x1", 0).attr("x2", 0)
    .attr("y1", s => -radius(s) - 9).attr("y2", s => -radius(s) - 21);
  const heat = sg.append("circle").attr("class", "state-heat").attr("r", radius)
    .style("stroke", s => stateColor(s.id)).style("fill", "var(--div-0)");
  sg.append("text").attr("class", "t-title halo").attr("text-anchor", "middle").attr("y", 5).text(s => s.id);
  const countLabel = sg.append("text").attr("class", "t-small t-2 halo detail").attr("text-anchor", "middle")
    .attr("y", s => radius(s) + 34);
  hover(sg, s => {
    const n = clockCounts().get(s.id) || 0;
    return `<div class="tt-title">state ${s.id}</div>
      <div class="tt-row">${n} visit${n === 1 ? "" : "s"} on the clock now</div>
      <div class="tt-row">${f1(expected(s))} expected in ${forget} s at the training rate</div>
      ${s.id === 0 ? `<div class="tt-row">every trace starts here; only walks back in are counted.
        ${S.meta.train_counts === "visits"
          ? `The scorer's training count for this state (${fmt(s.visits)}) also includes ${fmt(s.visits - s.entries)} trace starts.`
          : `The scorer's training count for this state is its ${fmt(s.entries)} entries; its ${fmt(s.visits - s.entries)} trace starts are not counted.`}</div>` : ""}`;
  });

  const dots = g.append("g");
  const walk = g.append("g");
  const token = g.append("circle").attr("class", "token").attr("r", 6).attr("opacity", 0);
  const fall = g.append("g").attr("opacity", 0);
  fall.append("text").attr("class", "falloff").attr("text-anchor", "middle").text("✕");
  const fallLabel = fall.append("text").attr("class", "falloff-label halo").attr("text-anchor", "middle").attr("y", 18);
  const byId = new Map(states.map(s => [s.id, s]));
  let shownTrace = null;

  player.on("tick", t => {
    const { vt, vs, c } = capture();
    const lo = d3.bisectLeft(vt, t - forget), hi = d3.bisectRight(vt, t);
    const counts = new Map();
    for (let i = lo; i < hi; i++) counts.set(vs[i], (counts.get(vs[i]) || 0) + 1);
    heat.style("fill", s => (counts.get(s.id) || 0) === 0 ? "var(--surface-2)" : heatColor(counts.get(s.id) / expected(s)));
    countLabel.text(s => `${counts.get(s.id) || 0} on clock`);

    // visits orbit their state: angle is age, a full turn is the forgetting window. Visits of
    // one trace share a timestamp, so each takes its own lane and a small angular offset; a
    // busy state shows an even sample of its visits rather than thousands of dots
    const perState = new Map();
    for (let i = lo; i < hi; i++) {
      if (!perState.has(vs[i])) perState.set(vs[i], []);
      perState.get(vs[i]).push(i);
    }
    const placed = [];
    for (const [state, list] of perState) {
      const step = Math.max(1, list.length / MAX_DOTS);
      for (let j = 0; j < list.length && placed.length < 4000; j += step) {
        const i = list[Math.floor(j)];
        placed.push({ i, state, lane: Math.floor(j / step) % 4,
                      nudge: (i - d3.bisectLeft(vt, vt[i])) * 0.07 });
      }
    }
    const position = (d, axis) => {
      const s = byId.get(d.state), a = (t - vt[d.i]) / forget * 2 * Math.PI + d.nudge;
      const r = radius(s) + 9 + d.lane * 4;
      return axis === "x" ? at(s)[0] + Math.sin(a) * r : at(s)[1] - Math.cos(a) * r;
    };
    dots.selectAll("circle").data(placed, d => d.i).join("circle").attr("class", "visit").attr("r", 2.4)
      .attr("cx", d => position(d, "x")).attr("cy", d => position(d, "y"))
      .attr("opacity", d => 1 - 0.7 * (t - vt[d.i]) / forget);

    // the current trace walks the machine; a missing transition drops it off with a cross
    const k = traceAt(t);
    if (k === shownTrace) return;
    shownTrace = k;
    const trace = k >= 0 ? c.traces[k] : null;
    const path = trace ? [0, ...trace.states] : [];
    const keys = new Set(path.slice(1).map((s, i) => `${path[i]}>${s}`));
    links.classed("walk", l => keys.has(l.key)).attr("marker-end", l => keys.has(l.key) ? "url(#arrow-hot)" : "url(#arrow)");
    walk.selectAll("*").remove();
    if (!trace) { token.attr("opacity", 0); fall.attr("opacity", 0); return; }
    const points = path.map(s => at(byId.get(s)));
    token.interrupt().attr("opacity", 1).attr("cx", points[0][0]).attr("cy", points[0][1]);
    let tr = token.transition().duration(0);
    const hop = Math.max(40, 220 / player.speed);
    points.slice(1).forEach((p, i) => {
      if (path[i + 1] === path[i]) {
        // a self-loop: hop up over the state's loop and land back, so the step is visible
        const r = radius(byId.get(path[i]));
        tr = tr.transition().duration(hop / 2).attr("cy", p[1] - r - 22)
               .transition().duration(hop / 2).attr("cy", p[1]);
      } else {
        tr = tr.transition().duration(hop).attr("cx", p[0]).attr("cy", p[1]);
      }
    });
    if (trace.fell_off_at !== null) {
      const last = points[points.length - 1];
      fall.attr("opacity", 1).attr("transform", `translate(${last[0] + 26},${last[1] + 30})`);
      fallLabel.text(`unseen: ${trace.symbols[trace.fell_off_at]}`);
    } else {
      fall.attr("opacity", 0);
    }
  });

  function clockCounts() {
    const { vt, vs } = capture(), t = player.t;
    const counts = new Map();
    for (let i = d3.bisectLeft(vt, t - forget); i < d3.bisectRight(vt, t); i++) counts.set(vs[i], (counts.get(vs[i]) || 0) + 1);
    return counts;
  }
}

function clusterInset(g, box) {
  // the map is drawn from benign traffic; an attack's new addresses and new conversations
  // are added for this recording, dashed, so the most telling flows have somewhere to show
  const { c: shownCapture } = capture();
  const fresh = kind => shownCapture.new_elements.filter(e => e.kind === kind);
  const map = {
    ...S.cluster,
    pods: [...S.cluster.pods, ...fresh("pod")],
    services: [...S.cluster.services, ...fresh("service")],
    external: [...S.cluster.external, ...fresh("lan"), ...fresh("internet")],
    edges: [...S.cluster.edges, ...shownCapture.new_edges.map(e =>
      ({ src: e.src, dst: e.dst, packets: e.flows, ports: [], new: true }))],
  };
  const extra = shownCapture.new_edges.length;
  g.append("text").attr("class", "t-section detail").attr("x", box.x).attr("y", box.y - 14)
    .text(fit(`flows of the current trace${extra ? ` · ${extra} new (dashed)` : ""}`, box.w));
  const { edges } = renderCluster(g, map, box, { focus: S.meta.vantage, compact: true, onTap: switchTo });
  const halo = g.select(".tap.focus .tap-halo");
  // a host-network tap has no address of its own: its flows run on its node, so the pod
  // lights up whenever the node does
  const tap = S.cluster.vantages.find(v => v.label === S.meta.vantage);
  const tapPod = tap && S.cluster.pods.find(p => p.id === tap.element && p.host_network);
  const tapCircle = tapPod ? g.select(`circle[data-id="${tapPod.id}"]`) : null;
  let shown = null;
  player.on("tick", t => {
    const { c } = capture();
    const k = traceAt(t);
    const w = c.windows[Math.floor(t / S.meta.window_size)];
    halo.style("stroke", w && w.alert ? "var(--critical)" : w && (w.flagged || w.likelihood_flag) ? "var(--warning)" : "var(--accent)")
      .style("opacity", w && w.alert ? 0.9 : 0.35);
    if (k === shown) return;
    shown = k;
    const hot = new Set();
    if (k >= 0) {
      const tr = c.traces[k];
      for (const [a, b] of c.flow_edges.slice(tr.i, tr.i + S.meta.trace_len)) if (a && b) hot.add([a, b].sort().join("|"));
    }
    edges.classed("hot", e => hot.has([e.src, e.dst].sort().join("|")));
    if (tapCircle) tapCircle.classed("hot", [...hot].some(pair => pair.split("|").includes(tapPod.host)));
  });
}

function scoreStrip(g, box, { minimal = false } = {}) {
  const { c, begin, end } = capture();
  const traces = c.traces;
  const x = d3.scaleLinear().domain([begin, end]).range([box.x, box.x + box.w]);
  const hA = box.h * 0.48, hB = box.h * 0.24, gap = 14, bandH = 8;
  const yA0 = box.y, yB0 = yA0 + hA + gap, band0 = yB0 + hB + 8, band1 = band0 + bandH + 3;
  // the cumulative score is judged against benign at the same age (window index): it grows
  // with capture length alone, so no single line would be fair
  const ws = S.meta.window_size;
  const reference = c.cutoffs.cumulative_reference
    .map((v, w) => ({ w, v })).filter(d => d.v !== null && (d.w + 1) * ws > begin && d.w * ws < end);
  // A trace that falls off the machine scores only the states it reached, about 6.7 a state, so
  // drawn as a point it reads as a sudden calm exactly where behaviour is new. The frequency
  // lines join only the traces that walked every state; each fall-off is an ✕ on the floor,
  // and the likelihood line below is the detector that judges it.
  const whole = traces.filter(t => t.fell_off_at === null);
  const fell = traces.filter(t => t.fell_off_at !== null);
  const freq = whole.flatMap(t => [t.windowed, t.cumulative]).concat([c.cutoffs.windowed], reference.map(d => d.v));
  const yA = d3.scaleLinear().domain(d3.extent(freq.length ? freq : [0, 1])).nice().range([yA0 + hA, yA0 + 14]);
  const lik = traces.map(t => t.likelihood).concat([c.cutoffs.likelihood, 0]);
  const yB = d3.scaleLinear().domain(d3.extent(lik)).nice().range([yB0 + hB, yB0 + 12]);

  // the anomaly clock's window, behind the lines
  const clock = g.append("rect").attr("class", "clock-window").attr("y", yA0).attr("height", band1 + bandH - yA0).attr("rx", 3);

  for (const [y, top, h, ticks] of [[yA, yA0, hA, 4], [yB, yB0, hB, 3]]) {
    g.append("g").attr("class", "grid").attr("transform", `translate(${box.x},0)`)
      .call(d3.axisLeft(y).ticks(ticks).tickSize(-box.w).tickFormat("")).call(s => s.select(".domain").remove());
    g.append("g").attr("class", "axis").attr("transform", `translate(${box.x},0)`)
      .call(d3.axisLeft(y).ticks(ticks).tickSize(3)).call(s => s.select(".domain").remove());
  }
  g.append("text").attr("class", "t-section").attr("x", box.x).attr("y", yA0 + 4)
    .text(minimal ? "how unusual" : "SEQUENT frequency score · higher = more unusual");
  g.append("text").attr("class", "t-section").attr("x", box.x).attr("y", yB0 + 4)
    .text(minimal ? "how familiar" : "trace likelihood · lower = more unusual");

  // cutoff labels sit at opposite ends, so two close cutoffs never print on top of each other
  const cut = (y, value, color, text, end) => {
    g.append("line").attr("class", "cutoff").attr("x1", box.x).attr("x2", box.x + box.w)
      .attr("y1", y(value)).attr("y2", y(value)).style("stroke", color);
    g.append("text").attr("class", "t-small halo").attr("text-anchor", end ? "end" : "start")
      .attr("x", end ? box.x + box.w - 2 : box.x + 4).attr("y", y(value) - 4).text(text).style("fill", "var(--ink-2)");
  };
  cut(yA, c.cutoffs.windowed, "var(--s1)", minimal ? "cutoff"
      : `windowed cutoff ${f1(c.cutoffs.windowed)} · ${c.cutoffs.calibration.windowed_windows} held-out windows`, false);
  cut(yB, c.cutoffs.likelihood, "var(--muted)", minimal ? "cutoff" : `cutoff ${f2(c.cutoffs.likelihood)}`, true);

  if (reference.length && !minimal) {
    const steps = reference.flatMap(d => [[Math.max(begin, d.w * ws), d.v], [Math.min(end, (d.w + 1) * ws), d.v]]);
    g.append("path").attr("class", "series").attr("d", d3.line().x(p => x(p[0])).y(p => yA(p[1]))(steps))
      .style("stroke", "var(--s2)").attr("stroke-width", 1).attr("stroke-opacity", 0.55);
  }
  const line = (y, key, rows) => d3.line().x(d => x(d.t)).y(d => y(d[key]))(rows);
  if (whole.length) {
    g.append("path").attr("class", "series").attr("d", line(yA, "cumulative", whole))
      .style("stroke", "var(--s2)").attr("stroke-width", 1.5).attr("stroke-dasharray", "5 3");
    g.append("path").attr("class", "series").attr("d", line(yA, "windowed", whole)).style("stroke", "var(--s1)").attr("stroke-width", 2);
  }
  g.append("g").selectAll("text").data(fell).join("text").attr("class", "fell-mark")
    .attr("x", t => x(t.t)).attr("y", yA0 + hA - 2).attr("text-anchor", "middle").text("✕");
  if (traces.length) {
    g.append("path").attr("class", "series").attr("d", line(yB, "likelihood", traces)).style("stroke", "var(--ink-2)").attr("stroke-width", 1.5);
    g.append("g").selectAll("circle").data(traces.filter(t => t.likelihood < c.cutoffs.likelihood)).join("circle")
      .attr("cx", t => x(t.t)).attr("cy", t => yB(t.likelihood)).attr("r", 2.5).style("fill", "var(--warning)");
  }
  // legend for the series sharing chart A, right-aligned and wrapping to the space it has
  const swatchLine = (color, dash, opacity = 1) => item => item.append("line").attr("x1", 0).attr("x2", 18)
    .attr("y1", -4).attr("y2", -4).style("stroke", color).attr("stroke-width", 2)
    .attr("stroke-dasharray", dash).attr("stroke-opacity", opacity);
  const swatchFell = item => item.append("text").attr("class", "fell-mark").attr("x", 9).attr("y", 0)
    .attr("text-anchor", "middle").text("✕");
  legendRow(g.append("g").attr("transform", `translate(${box.x + box.w * 0.3},${yA0 - 4})`), minimal ? [
    ["forgets", swatchLine("var(--s1)", null)],
    ["never forgets", swatchLine("var(--s2)", "5 3")],
    ["fell off", swatchFell],
  ] : [
    [`windowed (forgets after ${S.meta.forget_seconds} s)`, swatchLine("var(--s1)", null)],
    ["cumulative (never forgets)", swatchLine("var(--s2)", "5 3")],
    ["benign cumulative, same age", swatchLine("var(--s2)", null, 0.55)],
    ["fell off the machine (judged by likelihood)", swatchFell],
  ], box.w * 0.7, { align: "end" });

  // window verdicts: flagged, alert (sustained), released; empty and warming windows say so
  const bands = g.append("g");
  // one row per detector: SEQUENT windows (flagged, alert) and likelihood windows (unseen)
  const shown = c.windows.filter(w => w.index * ws < end && (w.index + 1) * ws > begin);
  const wx = w => x(Math.max(begin, w.index * ws)) + 0.5;
  const ww = w => Math.max(x(Math.min(end, (w.index + 1) * ws)) - x(Math.max(begin, w.index * ws)) - 1, 1);
  for (const [y, label, fill] of [[band0, "SEQUENT", BAND_FILL.sequent], [band1, "likelihood", BAND_FILL.likelihood]]) {
    bands.append("text").attr("class", "t-small t-muted").attr("text-anchor", "end").attr("x", box.x - 6).attr("y", y + 7).text(label);
    bands.append("g").selectAll("rect").data(shown).join("rect")
      .attr("class", w => w.status === "nodata" ? "band-empty" : null)
      .attr("x", wx).attr("y", y).attr("width", ww).attr("height", bandH).attr("rx", 2).style("fill", fill);
  }
  bands.selectAll("text.rel").data(c.windows.filter(w => w.released && w.index * ws >= begin)).join("text")
    .attr("class", "rel").attr("text-anchor", "middle").attr("x", w => x((w.index + 0.5) * ws)).attr("y", band0 - 2)
    .style("fill", "var(--good-ink)").style("font-size", "12px").style("font-weight", 700).text("✓");
  g.append("g").attr("class", "axis").attr("transform", `translate(0,${band1 + bandH + 4})`)
    .call(d3.axisBottom(x).ticks(10).tickFormat(v => `${v}s`).tickSize(3));
  const swatch = (fill, cls = null) => item => item.append("rect").attr("class", cls).attr("x", 0).attr("y", -9)
    .attr("width", 18).attr("height", 9).attr("rx", 2).style("fill", fill);
  legendRow(g.append("g").attr("transform", `translate(${box.x},${band1 + bandH + 30})`), minimal ? [
    ["flagged", swatch("var(--warning)")],
    ["alert", swatch("var(--critical)")],
    ["unseen", swatch("var(--serious)")],
  ] : [
    ["flagged", swatch("var(--warning)")],
    [`alert: ${S.meta.persistence}+ in a row`, swatch("var(--critical)")],
    ["unseen behaviour (likelihood)", swatch("var(--serious)")],
    [`released: ${S.meta.clear_windows} clean scored windows`, item => item.append("text").attr("x", 4).attr("y", 0)
      .style("fill", "var(--good-ink)").style("font-weight", 700).text("✓")],
    ["no trace ended (no verdict)", swatch("none", "band-empty")],
    ["clock warming up", swatch("var(--grid)")],
    [`anomaly clock: the last ${S.meta.forget_seconds} s`, swatch(null, "clock-window")],
  ], box.w);

  // playhead, crosshair tooltip, click or drag to seek
  const head = g.append("line").attr("class", "playhead").attr("y1", yA0).attr("y2", band1 + bandH);
  const cross = g.append("line").attr("class", "crosshair").attr("y1", yA0).attr("y2", band1 + bandH).attr("opacity", 0);
  const overlay = g.append("rect").attr("x", box.x).attr("y", yA0).attr("width", box.w)
    .attr("height", band1 + bandH - yA0).attr("fill", "transparent").style("cursor", "pointer");
  const seekTo = e => player.seek(x.invert(d3.pointer(e)[0]));
  overlay.on("pointerdown", e => { seekTo(e); overlay.node().setPointerCapture(e.pointerId); })
    .on("pointermove", e => {
      if (e.buttons) seekTo(e);
      const t = x.invert(d3.pointer(e)[0]);
      const k = Math.max(0, d3.bisectRight(capture().tt, t) - 1);
      const tr = traces[k], w = c.windows[Math.floor(t / ws)];
      cross.attr("x1", x(t)).attr("x2", x(t)).attr("opacity", 1);
      if (!tr) return;
      showTip(e, `<div class="tt-title">${f1(t)} s · window ${Math.floor(t / ws)}</div>
        <div class="tt-row">${tr.fell_off_at === null ? `windowed ${f1(tr.windowed)} · cumulative ${f1(tr.cumulative)}`
          : `fell off after ${tr.fell_off_at} state${tr.fell_off_at === 1 ? "" : "s"}: frequency score not drawn`}</div>
        <div class="tt-row">likelihood ${f2(tr.likelihood)}</div>
        <div class="tt-row">${w ? STATUS[w.status].text.toLowerCase() : ""}</div>`);
    })
    .on("pointerleave", () => { cross.attr("opacity", 0); hideTip(); });

  player.on("tick", t => {
    head.attr("x1", x(t)).attr("x2", x(t));
    const left = Math.max(begin, t - S.meta.forget_seconds);
    clock.attr("x", x(left)).attr("width", Math.max(x(t) - x(left), 0));
    d3.select("#d-time").text(`${f1(t)} s / ${f1(end)} s`);
  });
}

// a window's fill in each detector's band, shared by the single-tap strip and the taps view
const BAND_FILL = {
  sequent: w => w.alert ? "var(--critical)" : w.flagged ? "var(--warning)"
    : w.status === "nodata" ? "none" : w.status === "warmup" ? "var(--grid)" : "var(--surface-2)",
  likelihood: w => w.likelihood_flag ? "var(--serious)" : w.status === "nodata" ? "none" : "var(--surface-2)",
};

const STATUS = {
  alert: { cls: "critical", text: "ALERT · sustained" },
  flagged: { cls: "warning", text: "FLAGGED window" },
  unseen: { cls: "warning", text: "UNSEEN BEHAVIOUR · likelihood" },
  nodata: { cls: "idle", text: "NO TRACE · no verdict" },
  warmup: { cls: "idle", text: "WARMING UP · clock not full" },
  released: { cls: "good", text: "RELEASED · forgotten" },
  normal: { cls: "good", text: "NORMAL" },
};
const windowAt = t => capture().c.windows[Math.floor(t / S.meta.window_size)];
const statusOf = t => { const w = windowAt(t); return w ? STATUS[w.status] : { cls: "idle", text: "NO DATA" }; };

// what each cutoff rests on. A 95th percentile of a dozen held-out windows sits next to
// their maximum, so the page says how many there were and how often they actually flag
const pct = d3.format(".0%");
const FEW_WINDOWS = 20;
function calibrationNote(c) {
  const k = c.cutoffs.calibration;
  return `<h2>How sure the cutoffs are</h2>
    <dl class="kv">
      <dt>windowed</dt><dd>${f1(c.cutoffs.windowed)} · from ${k.windowed_windows} held-out window${k.windowed_windows === 1 ? "" : "s"} · flags ${pct(k.windowed_benign_rate)} of them</dd>
      <dt>likelihood</dt><dd>${f2(c.cutoffs.likelihood)} · from ${fmt(k.likelihood_traces)} held-out traces · flags ${pct(k.likelihood_benign_rate)}</dd>
    </dl>
    <p style="font-size:12.5px">Both aim to flag ${pct(k.nominal_rate)} of held-out benign.
      ${k.windowed_windows < FEW_WINDOWS ? `With only ${k.windowed_windows} windows the windowed cutoff sits next to the
      largest held-out score, from one short recording: read a flag near the line as weak evidence.` : ""}</p>`;
}

function detectionPanel() {
  let shownKey = null;
  const ws = S.meta.window_size, forget = S.meta.forget_seconds;
  const heatLegend = `<div class="heatbar">${HEAT.map(v => `<span style="background:var(${v})"></span>`).join("")}</div>
    <div class="heatlabels"><span>quieter</span><span>as in training</span><span>busier</span></div>`;
  const warning = S.meta.calibration_warning
    ? `<div class="banner"><b>Calibration not trusted.</b> ${S.meta.calibration_warning}</div>` : "";
  player.on("tick", t => {
    const { c } = capture();
    const k = traceAt(t), w = windowAt(t), status = statusOf(t);
    const key = `${player.capture}:${k}:${w ? w.index : -1}:${status.text}`;
    if (key === shownKey) return;
    shownKey = key;
    const held = player.capture === 0;
    const span = held ? S.meta.holdout_span_s : c.duration_s;
    const totalAlerts = c.windows.filter(x => x.alert).length;
    const disclosure = `${c.dropped_flows ? `${fmt(c.dropped_flows)} flows crossed a ${ws} s window boundary and were dropped before symbolizing. ` : ""}`
      + `${c.warmup_s ? `The clock starts empty, so the first ${c.warmup_s} s are a warm-up.` : held ? "The clock was already warm: the training part ran first." : ""}`;
    const tr = k >= 0 ? c.traces[k] : null;
    if (!tr) {
      panel.html(`<div class="status ${status.cls}"><span class="dot"></span>${status.text}</div>${warning}
        <h2>${c.scenario}</h2>
        <p class="big">${c.traces.length} traces over ${f1(span)} s${held ? " (the held-out last 30%)" : ""}.
          ${totalAlerts} window${totalAlerts === 1 ? "" : "s"} in sustained alert.</p>
        <p>Press <b>Play</b> (or space). Each trace of ${S.meta.trace_len} flows walks the machine;
          every state it walks into drops a dot on that state's clock. A dot takes ${forget} s to go
          round once, then it is <b>forgotten</b>.</p>
        <p>The score asks: are states being visited more often, in the last ${forget} s, than
          training said they would be?</p>
        <p style="font-size:12.5px">${disclosure}</p>
        ${calibrationNote(c)}
        <h2>State fill · visits on the clock vs training rate</h2>${heatLegend}`);
      return;
    }
    const peak = w && w.peak !== null ? w.peak : null;
    const sentence = !w ? "Outside the recording."
      : w.status === "nodata" ? "No trace ended in this second, so there is nothing to judge. The clocks keep running; dots still expire."
      : w.status === "warmup" ? `The clock has run for under ${forget} s, so scores are low by construction: quiet here is not evidence of normal.`
      : w.alert ? `Its highest trace scores <b>${f1(peak)}</b>, over the cutoff ${f1(c.cutoffs.windowed)}, and ${S.meta.persistence}+ windows in a row have: <b>sustained alert</b>.`
      : w.flagged ? `Its highest trace scores <b>${f1(peak)}</b>, over the cutoff ${f1(c.cutoffs.windowed)}: flagged.`
      : w.status === "unseen" ? `Highest frequency score ${f1(peak)} is under the cutoff, but a trace fell below the likelihood cutoff: something benign never did.`
      : w.status === "released" ? `Back under the cutoff for ${S.meta.clear_windows} scored windows since the alert: <b>released</b>.`
      : `Its highest trace scores ${f1(peak)}, under the cutoff ${f1(c.cutoffs.windowed)}.`;
    const traceWindow = Math.floor(tr.t / ws);
    const stale = !w || traceWindow !== w.index;
    // a page over its size limit drops per-state terms from the taps it did not open on
    const detail = Array.isArray(tr.terms);
    const contributions = detail ? tr.visits.map(([clock, trained], i) => ({
      state: tr.states[i], total: d3.sum(tr.terms[i]), clock, trained })) : [];
    const maxC = d3.max(contributions, d => Math.abs(d.total)) || 1;
    const above = tr.windowed > c.cutoffs.windowed;
    const ref = c.cutoffs.cumulative_reference[traceWindow];
    const falloff = tr.fell_off_at !== null;
    const lostTime = Boolean(w && w.forgetting_shown);
    const starts = L.pdfa.states[0].visits - L.pdfa.states[0].entries;
    panel.html(`
      <div class="status ${status.cls}"><span class="dot"></span>${status.text}</div>${warning}
      <h2>Window ${f1(w ? w.index * ws : t)}–${f1(w ? (w.index + 1) * ws : t)} s</h2>
      <p class="big">${sentence}</p>
      <h2>Latest trace · ended ${f1(tr.t)} s${stale ? " · in an earlier window" : ""}</h2>
      <div class="chips">${tr.symbols.map((s, i) => chip(s, falloff && i >= tr.fell_off_at ? "off" : "")).join("")}</div>
      <p style="margin-top:8px">${falloff
        ? `Walks ${tr.fell_off_at === 0 ? "no state" : "states " + tr.states.join(" → ")}, then <b>falls off</b>: benign traffic never took <span class="mono">${tr.symbols[tr.fell_off_at]}</span> from there. Likelihood takes the floor (${f2(tr.likelihood)}). A fall-off visits fewer states, so it <i>lowers</i> the frequency score: unseen behaviour is the likelihood detector's catch, not SEQUENT's.`
        : `Starts at 0, walks ${tr.states.join(" → ")}. Likelihood ${f2(tr.likelihood)} (cutoff ${f2(c.cutoffs.likelihood)}).`}</p>
      <h2>This trace scores ${f1(tr.windowed)} · ${above ? "over" : "under"} the cutoff</h2>
      ${detail ? "" : "<p>This tap's per-state breakdown was dropped to keep the page under its size limit; its scores and verdicts are unchanged.</p>"}
      <div class="contrib">${contributions.map(d => `
        <span class="sid" style="background:${stateColor(d.state)}">${d.state}</span>
        <span class="bar" style="width:${Math.max(4, 100 * Math.abs(d.total) / maxC)}%"></span>
        <span class="num">${f1(d.total)}</span>
        <span class="sub">${fmt(d.clock)} on its clock · ${fmt(d.trained)} in training${d.state === 0 && S.meta.train_counts === "visits" ? ` (incl. ${fmt(starts)} trace starts)` : ""}</span>`).join("")
        || (detail ? "<p>No state reached: nothing to count.</p>" : "")}</div>
      <p style="margin-top:8px">Each state walked into adds log(clock visits + 1) − log(training entries + 1),
        plus the training total and how many states are on the clock. A window is judged on its
        highest trace, so one trace over the line flags the whole second.</p>
      <h2>Forgetting</h2>
      <dl class="kv">
        <dt>windowed</dt><dd>${f1(tr.windowed)} vs cutoff ${f1(c.cutoffs.windowed)} ${above ? "▲" : "✓"}</dd>
        <dt>cumulative</dt><dd>${f1(tr.cumulative)} vs benign ${ref === null || ref === undefined ? "— (older than the benign recording)" : `${f1(ref)} at this age ${tr.cumulative > ref ? "▲" : "✓"}`}</dd>
        <dt>forgot now</dt><dd>${detail ? `${tr.expired.length} visit${tr.expired.length === 1 ? "" : "s"} left the clock` : "— (dropped with the breakdown)"}</dd>
      </dl>
      ${lostTime ? `<p style="margin-top:8px"><b>This is why it forgets.</b> An alert fired earlier and the
        windowed score has let it go, but the cumulative score is still above anything benign reached by
        this age: without the ${forget} s clock it would hold on to the burst.</p>` : ""}
      <p style="margin-top:8px;font-size:12.5px">The cumulative score grows with recording length alone, so it is
        compared with the whole benign recording at the same age. That reference includes the 70% the
        machine learned from. ${disclosure}</p>
      ${calibrationNote(c)}
        <h2>State fill · visits on the clock vs training rate</h2>${heatLegend}`);
  });
}

// ---------------------------------------------------------------- act 3: across taps
// The same scenario at every tap on the page, small multiples on one capture-time axis. The
// taps recorded side by side, so each row is shifted by when its own first packet arrived;
// each row's verdicts are that tap's, against that tap's own cutoffs.

function tapRows(scenario) {
  const rows = VANTAGES.map(label => {
    const v = B.vantages[label];
    const i = v.playback.captures.findIndex(c => c.scenario === scenario);
    if (i < 0) return null;
    const c = v.playback.captures[i], [begin, end] = replaySpan(c, i, v.meta.window_size);
    return { label, v, i, c, begin, end };
  }).filter(Boolean);
  const origin = d3.min(rows, r => r.c.t0);
  for (const r of rows) {
    r.off = r.c.t0 - origin;
    const ws = r.v.meta.window_size;
    r.shown = r.c.windows.filter(w => (w.index + 1) * ws > r.begin && w.index * ws < r.end);
    const alerts = r.shown.filter(w => w.alert);
    r.alerts = alerts.length;
    r.firstAlert = alerts.length ? r.off + alerts[0].index * ws : null;
    r.unseen = r.shown.filter(w => w.likelihood_flag).length;
    r.flagged = r.shown.filter(w => w.flagged).length;
    // windows that could carry a verdict: a trace ended there and the clock was warm (a flag
    // in warm-up still counts, since a cold clock only lowers scores)
    r.judged = r.shown.filter(w => w.flagged || (w.status !== "nodata" && w.status !== "warmup")).length;
    r.blind = r.judged === 0 && r.unseen === 0;
  }
  return rows;
}

function acrossTaps(g, box) {
  const { c: current } = capture();
  const rows = tapRows(current.scenario);
  const selected = rows.find(r => r.label === S.meta.vantage);
  const left = box.x + 168, right = box.x + box.w - 118;
  const x = d3.scaleLinear()
    .domain([d3.min(rows, r => r.off + r.begin), d3.max(rows, r => r.off + r.end)])
    .range([left, right]);
  const top = box.y + 34, legendH = 40;
  const rowH = Math.max(28, Math.min(64, (box.h - 34 - legendH - 28) / rows.length));
  const bandA = Math.min(14, rowH * 0.32), bandB = Math.min(8, rowH * 0.18);

  g.append("text").attr("class", "t-section").attr("x", box.x).attr("y", box.y + 4)
    .text(fit(`${current.scenario} at ${rows.length} taps · one capture-time axis · each tap judged on its own cutoffs`, box.w));
  g.append("text").attr("class", "t-small t-muted").attr("x", left).attr("y", top - 10).text("SEQUENT windows, likelihood below");
  g.append("text").attr("class", "t-small t-muted").attr("text-anchor", "end").attr("x", box.x + box.w).attr("y", top - 10).text("alert windows");
  g.append("g").attr("class", "grid").attr("transform", `translate(0,${top - 4})`)
    .call(d3.axisBottom(x).ticks(10).tickSize(rows.length * rowH).tickFormat("")).call(s => s.select(".domain").remove());

  rows.forEach((r, k) => {
    const y = top + k * rowH, ws = r.v.meta.window_size, mine = r === selected;
    const rg = g.append("g").attr("class", `tap-row ${mine ? "selected" : ""}`).attr("data-label", r.label);
    rg.append("rect").attr("class", "tap-row-bg").attr("x", box.x).attr("y", y).attr("width", box.w)
      .attr("height", rowH - 4).attr("rx", 6);
    rg.append("text").attr("class", mine ? "t-title" : null).attr("x", box.x + 10).attr("y", y + rowH / 2 - 2).text(r.label);
    rg.append("text").attr("class", "t-small t-muted").attr("x", box.x + 10).attr("y", y + rowH / 2 + 11)
      .text(`${r.v.meta.level}${r.v.meta.calibration_warning ? " · inspection only" : ""}${mine ? " · replaying" : ""}`);
    const yA = y + (rowH - 4 - bandA - bandB - 3) / 2, yB = yA + bandA + 3;
    const wx = w => x(r.off + Math.max(r.begin, w.index * ws)) + 0.5;
    const ww = w => Math.max(x(r.off + Math.min(r.end, (w.index + 1) * ws)) - x(r.off + Math.max(r.begin, w.index * ws)) - 1, 1);
    for (const [yy, hh, fill] of [[yA, bandA, BAND_FILL.sequent], [yB, bandB, BAND_FILL.likelihood]]) {
      rg.append("g").selectAll("rect").data(r.shown).join("rect")
        .attr("class", w => w.status === "nodata" ? "band-empty" : null)
        .attr("x", wx).attr("y", yy).attr("width", ww).attr("height", hh).attr("rx", 1.5).style("fill", fill);
    }
    rg.append("g").selectAll("text").data(r.shown.filter(w => w.released)).join("text")
      .attr("text-anchor", "middle").attr("x", w => x(r.off + (w.index + 0.5) * ws)).attr("y", yA - 1)
      .style("fill", "var(--good-ink)").style("font-size", "10px").style("font-weight", 700).text("✓");
    rg.append("text").attr("class", r.alerts ? "t-title" : "t-small t-muted").attr("text-anchor", "end")
      .attr("x", box.x + box.w - 10).attr("y", y + rowH / 2 + 3)
      .style("fill", r.alerts ? "var(--critical)" : null)
      .text(r.alerts ? `${r.alerts}` : r.blind ? "no verdict" : "none");

    // hover reads the window under the pointer; a click replays this tap from that moment
    rg.append("rect").attr("x", left).attr("y", y).attr("width", right - left).attr("height", rowH - 4)
      .attr("fill", "transparent").style("cursor", "pointer")
      .on("pointermove", e => {
        const at = x.invert(d3.pointer(e)[0]), own = at - r.off, w = r.c.windows[Math.floor(own / ws)];
        showTip(e, `<div class="tt-title">${r.label} · ${f1(at)} s</div>
          <div class="tt-row">its own clock ${f1(own)} s · window ${Math.floor(own / ws)}</div>
          ${w && own >= r.begin && own <= r.end ? `<div class="tt-row">${STATUS[w.status].text.toLowerCase()}</div>
            <div class="tt-row">peak ${w.peak === null ? "—" : f1(w.peak)} vs cutoff ${f1(r.c.cutoffs.windowed)}
              (${r.c.cutoffs.calibration.windowed_windows} held-out windows)</div>`
            : `<div class="tt-row">outside this tap's recording</div>`}
          <div class="tt-row">click to replay this tap from here</div>`);
      })
      .on("pointerleave", hideTip)
      .on("click", e => replayFrom(r, x.invert(d3.pointer(e)[0]) - r.off));
  });

  const bottom = top + rows.length * rowH;
  g.append("g").attr("class", "axis").attr("transform", `translate(0,${bottom})`)
    .call(d3.axisBottom(x).ticks(10).tickFormat(v => `${v}s`).tickSize(3));
  const swatch = (fill, cls = null) => item => item.append("rect").attr("class", cls).attr("x", 0).attr("y", -9)
    .attr("width", 18).attr("height", 9).attr("rx", 2).style("fill", fill);
  legendRow(g.append("g").attr("transform", `translate(${left},${bottom + 34})`), [
    ["flagged", swatch("var(--warning)")],
    [`alert: ${S.meta.persistence}+ in a row`, swatch("var(--critical)")],
    ["unseen behaviour (likelihood)", swatch("var(--serious)")],
    ["no trace ended", swatch("none", "band-empty")],
    ["clock warming up", swatch("var(--grid)")],
    ["released", item => item.append("text").attr("x", 4).attr("y", 0)
      .style("fill", "var(--good-ink)").style("font-weight", 700).text("✓")],
  ], right - left);

  // the replaying tap's playhead, carried onto the shared axis
  const head = g.append("line").attr("class", "playhead").attr("y1", top - 4).attr("y2", bottom);
  player.on("tick", t => {
    const at = selected ? selected.off + t : null;
    head.attr("x1", at === null ? -10 : x(at)).attr("x2", at === null ? -10 : x(at));
    d3.select("#d-time").text(selected ? `${f1(at)} s on the shared axis` : "");
  });
  tapsPanel(current.scenario, rows);
}

// switch to one tap's own replay of this scenario, at a moment on that tap's own clock
function replayFrom(r, own) {
  hideTip();
  player.view = "tap";
  if (r.label !== S.meta.vantage) selectVantage(r.label);
  player.capture = r.i;
  prepared.clear();
  player.t = Math.max(r.begin, Math.min(r.end, own));
  show("detection");
}

function tapsPanel(scenario, rows) {
  const spread = d3.max(rows, r => r.off);
  const order = rows.slice().sort((a, b) => (a.firstAlert ?? Infinity) - (b.firstAlert ?? Infinity) || d3.ascending(a.label, b.label));
  const heard = rows.filter(r => r.alerts), blind = rows.filter(r => r.blind);
  const first = order[0];
  panel.html(`
    <h2>${scenario} · every tap</h2>
    <p class="big">${heard.length} of ${rows.length} taps raise a sustained alert${heard.length
      ? `; the first at <b>${first.label}</b>${first.v.meta.calibration_warning ? " (⚠ bulk transfer, inspection only)" : ""}, ${f1(first.firstAlert)} s in` : ""}.
      ${blind.length ? `${blind.length} could not judge it: no trace ended in a window past the clock's warm-up
        (${blind.map(r => `<span class="mono">${r.label}</span>`).join(", ")}).` : ""}</p>
    <p>Each row is one tap's replay of the same recording. Time is shared: 0 s is the first packet
      any of these taps saw, and the taps started up to ${f1(spread)} s apart. Each tap learned its own
      machine and is judged on <b>its own</b> cutoffs, so a row says what that tap would have reported.</p>
    <table class="taps">
      <thead><tr><th>tap</th><th>first alert</th><th>alerts</th><th>unseen</th><th>judged</th></tr></thead>
      <tbody>${order.map(r => `<tr class="${r.label === S.meta.vantage ? "selected" : ""}" data-label="${r.label}">
        <td class="mono">${r.label}${r.v.meta.calibration_warning ? " ⚠" : ""}</td>
        <td>${r.blind ? "no verdict" : r.firstAlert === null ? "—" : `${f1(r.firstAlert)} s`}</td>
        <td>${r.alerts}</td><td>${r.unseen}</td><td>${r.judged}</td></tr>`).join("")}</tbody>
    </table>
    <p style="margin-top:10px">Counts are windows of ${S.meta.window_size} s. <i>Judged</i> windows had a
      trace end in them on a warm clock; a tap with none gave <i>no verdict</i>, which is not the same as
      staying quiet. <i>Unseen</i> windows hold a trace benign never produced (the likelihood detector).
      Hover a row in the chart for a window's verdict, click it to replay from that moment; click a
      row here to replay that tap from its first alert.</p>
    ${rows.some(r => r.v.meta.calibration_warning) ? `<p style="font-size:12.5px">⚠ a bulk-transfer tap: its cutoff is not trusted, so its row is for inspection only.</p>` : ""}`);
  panel.selectAll("tr[data-label]").style("cursor", "pointer").on("click", function () {
    const r = rows.find(row => row.label === this.dataset.label);
    replayFrom(r, r.firstAlert === null ? r.begin : r.firstAlert - r.off);
  });
}

// ---------------------------------------------------------------- demo mode
// A short walkthrough for a live demo: one idea per slide, one real example from the bundle,
// almost no text. It draws with the acts' own renderers; it computes no new numbers.
const demoLayer = d3.select("#demo");
const demo = { slide: 0, timers: [], tl: null, speed: 1 };

function demoStop() { for (const t of demo.timers) t.stop(); demo.timers = []; }
const demoEvery = (ms, fn) => demo.timers.push(d3.interval(fn, ms));
const demoLater = (ms, fn) => demo.timers.push(d3.timeout(fn, ms));

// the recording this tap shows best: most sustained-alert windows, then most flags
function demoAttack() {
  let best = -1, most = -1;
  S.playback.captures.forEach((c, i) => {
    if (i === 0) return;
    const score = c.windows.filter(w => w.alert).length * 1e4
      + c.windows.filter(w => w.flagged || w.likelihood_flag).length;
    if (score > most) { most = score; best = i; }
  });
  return best;
}

function demoSlides() {
  const attack = demoAttack();
  const forgets = attack > 0 && S.playback.captures[attack].windows.some(w => w.released);
  // which recording a replay slide plays, said under its caption
  const source = i => `replaying <b>${S.playback.captures[i].scenario}</b> at ${S.meta.vantage}`;
  return [
    { topic: ["Packet capture", "taps on the cluster network"], title: "Where we listen", line: "We tap the cluster and record its traffic.", draw: slideCluster },
    { topic: ["Flow symbols", "percentile-binned size and duration"], title: "Every flow becomes a symbol", line: "Protocol, size and duration, binned into one word.", draw: slideSymbols },
    { topic: ["Sliding window", `traces of ${S.meta.trace_len} flows`], title: `A trace is ${S.meta.trace_len} flows in a row`, line: "It slides along the traffic one flow at a time.", draw: slideTraces },
    { topic: ["Prefix tree"], title: "Memorize every trace", line: `${fmt(L.traces)} benign traces become a tree of ${fmt(L.pta.length)} prefixes.`, draw: slideTree },
    { topic: ["ALERGIA", "state merging"], title: "Merge what behaves alike", line: "Same next-flow odds? Fold it in. Otherwise, a new state.", draw: slideMerge },
    { topic: ["PDFA", "probabilistic finite automaton"], title: "The learned machine", line: `${L.pdfa.states.length} states: a map of normal behaviour.`, draw: slideMachine },
    { topic: ["SEQUENT", "state-visit frequency score"], title: "Normal traffic walks the map", source: source(0), line: "Each state counts its recent visits on a short clock.", draw: box => slideReplay(box, 0) },
    ...(attack > 0 ? [{ topic: ["SEQUENT + likelihood", "too often · never seen"], title: "An attack lights it up", source: source(attack), line: "States visited far more than training predicts: alert.",
                        draw: box => slideReplay(box, attack) }] : []),
    ...(forgets ? [{ topic: ["Windowed SEQUENT", `${S.meta.forget_seconds} s forgetting clock`], title: "…then it forgets", source: source(attack), line: `Visits expire after ${S.meta.forget_seconds} s, so the alert clears.`,
                     draw: box => slideForget(box, attack) }] : []),
  ];
}

function drawSlide() {
  const slides = demoSlides();
  demo.slide = Math.max(0, Math.min(slides.length - 1, demo.slide));
  demo.tl = null;
  const slide = slides[demo.slide];
  const go = i => { demo.slide = Math.max(0, Math.min(slides.length - 1, i)); show(currentAct); };
  controls.html(`
    <button id="s-prev" aria-label="previous slide" ${demo.slide === 0 ? "disabled" : ""}>◀</button>
    <span class="dots">${slides.map((s, i) =>
      `<button data-i="${i}" class="${i === demo.slide ? "on" : ""}" title="${s.title}" aria-label="slide ${i + 1}"></button>`).join("")}</span>
    <button id="s-next" aria-label="next slide" ${demo.slide === slides.length - 1 ? "disabled" : ""}>▶</button>
    <span class="readout">${demo.slide + 1} / ${slides.length}</span>
    <span class="timeline" id="s-time"></span>
    <button id="s-again" title="Start this slide over">↺ Replay</button>`);
  d3.select("#s-prev").on("click", () => go(demo.slide - 1));
  d3.select("#s-next").on("click", () => go(demo.slide + 1));
  d3.select("#s-again").on("click", () => go(demo.slide));
  controls.selectAll(".dots button").on("click", function () { go(+this.dataset.i); });
  demoLayer.html(`<div class="demo-caption"><div class="demo-title">${slide.title}</div>
    <div class="demo-line">${slide.line}</div>
    ${slide.source ? `<div class="demo-source">${slide.source}</div>` : ""}</div>
    <div class="demo-corner">
      ${slide.topic ? `<div class="demo-topic"><b>${slide.topic[0]}</b>${slide.topic[1] ? `<span>${slide.topic[1]}</span>` : ""}</div>` : ""}
      <div class="status demo-status" id="demo-status" hidden></div></div>
    <div class="demo-cards" id="demo-cards"></div>`);
  const { w, h } = size();
  slide.draw({ x: 40, y: 118, w: w - 80, h: h - 150 });
  window.onkeydown = e => {
    if (e.target.closest && e.target.closest("select, textarea, input:not([type=range])")) return;
    if (["ArrowRight", "PageDown"].includes(e.code)) { e.preventDefault(); go(demo.slide + 1); }
    if (["ArrowLeft", "PageUp"].includes(e.code)) { e.preventDefault(); go(demo.slide - 1); }
    if (e.code === "Space" && demo.tl && !(e.target.closest && e.target.closest("button"))) {
      e.preventDefault(); demo.tl.toggle();
    }
  };
}

// 0 before `start`, 1 after `start + span`, linear between: a fade or move at slide time t
const ramp = (t, start, span) => Math.max(0, Math.min(1, (t - start) / span));
const DEMO_SPEEDS = [0.25, 0.5, 1, 2];
const speedText = v => ({ 0.25: "¼×", 0.5: "½×" })[v] || `${v}×`;

// One clock per slide. The scrubber, ▶/❚❚ and the speed buttons drive it; the slide redraws
// itself from the clock's time alone, so any moment can be scrubbed back to or slowed down.
// `duration` and `start` are in the slide's own units, `rate` units per second at 1×.
function demoTimeline({ duration, render, rate = 1, start = 0,
                        label = u => `${f1(u)} s / ${f1(duration)} s` }) {
  duration = Math.max(duration, 1e-6);
  const tl = { t: start, playing: false };
  d3.select("#s-time").html(`
    <button class="primary" id="tl-play"></button>
    <input type="range" id="tl-scrub" min="0" max="1000" step="1" aria-label="slide timeline">
    <span class="readout" id="tl-read"></span>
    <span class="seg" id="tl-speed">${DEMO_SPEEDS.map(v =>
      `<button data-v="${v}" aria-pressed="${v === demo.speed}" title="playback speed">${speedText(v)}</button>`).join("")}</span>`);
  const scrub = d3.select("#tl-scrub"), read = d3.select("#tl-read"), play = d3.select("#tl-play");
  const sync = () => { scrub.property("value", Math.round(tl.t / duration * 1000)); read.text(label(tl.t)); };
  tl.seek = u => { tl.t = Math.max(0, Math.min(duration, u)); render(tl.t); sync(); };
  tl.follow = u => { tl.t = Math.max(0, Math.min(duration, u)); sync(); };   // someone else moved the time
  tl.play = () => { if (tl.t >= duration) tl.seek(0); tl.playing = true; play.text("❚❚ Pause"); };
  tl.pause = () => { tl.playing = false; play.text("▶ Play"); };
  tl.toggle = () => tl.playing ? tl.pause() : tl.play();
  let last = null;
  demo.timers.push(d3.timer(elapsed => {
    const dt = last === null ? 0 : (elapsed - last) / 1000;
    last = elapsed;
    if (!tl.playing) return;
    tl.seek(tl.t + dt * rate * demo.speed);
    if (tl.t >= duration) tl.pause();
  }));
  scrub.on("input", e => { tl.pause(); tl.seek(+e.target.value / 1000 * duration); });
  play.on("click", tl.toggle);
  d3.selectAll("#tl-speed button").on("click", function () {
    demo.speed = +this.dataset.v;
    d3.selectAll("#tl-speed button").attr("aria-pressed", function () { return +this.dataset.v === demo.speed; });
  });
  demo.tl = tl;
  tl.seek(start);
  tl.play();
  return tl;
}

function slideCluster(box) {
  renderCluster(svg.append("g"), S.cluster, box, { focus: S.meta.vantage, onTap: switchTo });
}

// the first flows of training as bars, colored by protocol; the slide's clock fades them in
function demoStream(g, box, count, top, height) {
  const stream = L.stream.slice(0, count);
  const x = d3.scaleBand().domain(d3.range(stream.length)).range([box.x, box.x + box.w]).paddingInner(0.25);
  const bars = g.append("g").selectAll("rect").data(stream).join("rect")
    .attr("x", (d, i) => x(i)).attr("y", top).attr("width", x.bandwidth()).attr("height", height).attr("rx", 3)
    .attr("fill", d => protoColor(symbolParts(d.symbol).proto));
  const fadeIn = t => bars.attr("opacity", (d, i) => ramp(t, i * 0.012, 0.25));
  return { stream, x, fadeIn, end: stream.length * 0.012 + 0.25 };
}

function slideSymbols(box) {
  const top = box.y + 6, height = Math.min(56, box.h * 0.16);
  const s = demoStream(svg.append("g"), box, Math.min(96, Math.floor(box.w / 9)), top, height);
  const cards = d3.select("#demo-cards").style("top", `${top + height + 44}px`).html(L.symbols.slice(0, 3).map(s => `
    <div class="demo-card">
      <div class="demo-sym"><span class="sw" style="background:${protoColor(s.proto)}"></span>${s.symbol}</div>
      <div class="demo-parts">
        <span><b>${s.proto}</b>protocol</span>
        <span><b>${binText("bytes", s.bytes_bin)}</b>size</span>
        <span><b>${binText("duration", s.duration_bin)}</b>duration</span>
      </div>
      <div class="demo-count">${fmt(s.count)} training flows</div>
    </div>`).join(""));
  const card = cards.selectAll(".demo-card");
  demoTimeline({
    duration: s.end + 1.8,
    render: t => { s.fadeIn(t); card.style("opacity", (d, i) => ramp(t, s.end + i * 0.4, 0.4)); },
  });
}

function slideTraces(box) {
  const g = svg.append("g"), n = S.meta.trace_len;
  const top = box.y + 20, height = Math.min(72, box.h * 0.2);
  const s = demoStream(g, box, Math.min(40, Math.max(n + 8, Math.floor(box.w / 26))), top, height);
  const { stream, x } = s;
  const span = k => x(Math.min(k + n - 1, stream.length - 1)) + x.bandwidth() - x(k);
  const frame = g.append("rect").attr("class", "demo-frame").attr("y", top - 8)
    .attr("width", span(0) + 12).attr("height", height + 16).attr("rx", 8);
  const cards = d3.select("#demo-cards").style("top", `${top + height + 48}px`);
  const last = Math.max(stream.length - n, 0), step = 1.1, slide = 0.4;
  let shown = -1;
  demoTimeline({
    duration: s.end + (last + 1) * step,
    render: t => {
      s.fadeIn(t);
      // the frame rests on trace k, then glides to k + 1 over the first `slide` seconds of its step
      const u = Math.max(0, (t - s.end) / step), k = Math.min(Math.floor(u), last);
      const glide = k === 0 ? 0 : d3.easeCubicInOut(Math.min(1, (u - k) * step / slide));
      const from = Math.max(k - 1, 0);
      frame.attr("x", x(from) + (x(k) - x(from)) * glide - 6);
      if (k === shown) return;
      shown = k;
      cards.html(`<div class="demo-trace">${stream.slice(k, k + n).map(d => chip(d.symbol))
        .join('<span class="demo-arrow">→</span>')}</div>`);
    },
  });
}

// the prefix tree as an icicle, protocol-colored: depth is position in the trace
function demoIcicle(box) {
  const g = svg.append("g");
  const depth = d3.max(L.pta, n => n.depth), row = box.h / (depth + 1);
  const x = v => box.x + v * box.w;
  const rects = g.selectAll("rect").data(L.pta).join("rect").attr("class", "pta-rect")
    .attr("x", n => x(n.x0)).attr("y", n => box.y + n.depth * row + 1)
    .attr("width", n => Math.max(x(n.x1) - x(n.x0) - 1, 0.5)).attr("height", row - 2).attr("rx", 2)
    .style("fill", n => n.symbol ? protoColor(symbolParts(n.symbol).proto) : "var(--muted)");
  return { g, rects, x, row, box, depth };
}

function slideTree(box) {
  const tree = demoIcicle(box);
  demoTimeline({
    duration: 0.15 + tree.depth * 0.26 + 0.9,
    render: t => tree.rects.style("opacity", n => ramp(t, 0.15 + n.depth * 0.26, 0.4)),
  });
}

function slideMerge(box) {
  const tree = demoIcicle({ x: box.x, y: box.y, w: box.w - 360, h: box.h });
  const marks = svg.append("g");
  const total = L.steps.length;
  const firstMerge = L.steps.findIndex(s => s.kind === "merge");
  const cards = d3.select("#demo-cards").classed("side", true).style("top", `${box.y}px`);
  const paint = k => {
    const final = k > total;
    const kept = new Set([0, ...L.steps.slice(0, Math.min(k, total)).filter(s => s.kind === "promote").map(s => s.blue)]);
    const settled = n => final || n.settled_step <= k;
    tree.rects
      .style("fill", n => settled(n) ? stateColor(stateOfPta.get(n.id))
                       : n.symbol ? protoColor(symbolParts(n.symbol).proto) : "var(--muted)")
      .style("fill-opacity", n => kept.has(n.id) ? 1 : settled(n) ? 0.72 : 0.22);
    marks.selectAll("*").remove();
    const step = k >= 1 && k <= total ? L.steps[k - 1] : null;
    if (!step) return;
    for (const [id, role] of [[step.red, "red"], [step.blue, "blue"]]) {
      const n = ptaById.get(id);
      marks.append("rect").attr("x", tree.x(n.x0) - 1).attr("y", box.y + n.depth * tree.row - 1)
        .attr("width", Math.max(tree.x(n.x1) - tree.x(n.x0) + 1, 4)).attr("height", tree.row + 2).attr("rx", 3)
        .attr("fill", "none").attr("stroke", `var(--${role})`).attr("stroke-width", 3);
    }
  };
  // The side cards follow the scrubber: a running tally, then the step under the rings with
  // its own test, so every merge and every new state is a worked example of the one rule.
  const firstPromote = L.steps.findIndex(s => s.kind === "promote");
  cards.html(`<div class="demo-card" id="m-tally"></div><div class="demo-card" id="m-now"></div>`);
  const tally = cards.select("#m-tally"), now = cards.select("#m-now");
  const symText = s => s === "#" ? "trace ends" : s;
  const showTally = k => {
    const taken = L.steps.slice(0, Math.min(k, total));
    const ids = k > total ? L.pdfa.states.map(s => s.id)
      : [stateOfPta.get(0), ...taken.filter(s => s.kind === "promote").map(s => stateOfPta.get(s.blue))];
    const merged = taken.filter(s => s.kind === "merge").length;
    const left = k > total ? 0 : L.pta.filter(n => !(n.settled_step <= k)).length;
    tally.html(`<div class="demo-k">${k > total ? "learned" : k ? `step ${k} of ${total}` : "before merging"}</div>
      <div class="demo-tally"><span><b>${ids.length}</b>states</span><span><b>${merged}</b>merged</span>
        <span><b>${fmt(left)}</b>prefixes left</span></div>
      <div class="demo-swatches">${ids.map(id => `<span style="background:${stateColor(id)}">${id}</span>`).join("")}</div>`);
  };
  const showNow = k => {
    if (k > total) return now.html(`<div class="demo-k">result</div><div class="demo-big">${L.pdfa.states.length}</div>
      <div class="demo-count">states and ${L.pdfa.edges.length} transitions from ${fmt(L.pta.length)} prefixes</div>`);
    const step = k >= 1 ? L.steps[k - 1] : null;
    if (!step) return now.html(`<div class="demo-k">the rule</div>
      <p class="demo-rule">Take the next <b style="color:var(--blue)">candidate</b> prefix and compare its
        next-flow odds with each <b style="color:var(--red)">kept state</b>.</p>
      <p class="demo-rule">All within the band → <b>merge</b>.<br>Any outside every state → <b>new state</b>.</p>`);
    const test = step.attempts[step.attempts.length - 1], merged = step.kind === "merge";
    const off = hoeffdingRows(test).find(t => Math.abs(t.p_red - t.p_blue) >= test.bound);
    const path = pathOf(step.blue), tail = path.slice(-3);
    const example = k - 1 === firstMerge || k - 1 === firstPromote;
    const tried = step.attempts.length;
    now.html(`<div class="demo-k">${example ? "example · " : ""}step ${k}</div>
      <div class="demo-verdict ${merged ? "" : "new"}">${merged
        ? `✓ merged into state ${stateOfPta.get(step.red)}` : `★ new state ${stateOfPta.get(step.blue)}`}</div>
      <div class="demo-path">${path.length > 3 ? "<span>…</span>" : ""}${tail.map(s => chip(s)).join("") || "<i>start</i>"}</div>
      <div class="demo-count">${fmt(step.blue_visits)} traces reach this candidate${tried > 1
        ? ` · tried ${tried} kept states` : ""}</div>
      <div class="demo-key" style="margin-top:12px"><span><i style="background:var(--red)"></i>state ${stateOfPta.get(test.red)}</span>
        <span><i style="background:var(--blue)"></i>candidate</span></div>
      <svg id="hoeffding" width="300"></svg>
      <div class="demo-count">${merged ? "every next flow within the band"
        : `“${symText(off ? off.symbol : "?")}” falls outside the band${tried > 1 ? ", and did for every kept state" : ""}`}</div>`);
    drawHoeffding({ bound: test.bound, tests: hoeffdingRows(test).slice(0, 3) });
  };
  // when each step lands: a short lead, then every step gets the same time, enough to read its
  // card; a tap with many steps shortens them so the slide stays about half a minute
  const dt = Math.max(0.3, Math.min(1.4, 30 / Math.max(total, 1)));
  const at = d3.range(total + 1).map(i => 0.9 + i * dt);
  let shownK = -1;
  demoTimeline({
    duration: at[at.length - 1] + 1.2,
    label: t => { const k = d3.bisectRight(at, t);
      return k > total ? `done · ${total} steps` : `step ${k} / ${total}`; },
    render: t => {
      const k = d3.bisectRight(at, t);   // steps taken by time t
      if (k === shownK) return;
      shownK = k;
      paint(k); showTally(k); showNow(k);
    },
  });
}

function slideMachine(full) {
  // keep the layout near its natural proportions rather than stretched across a wide screen
  const w = Math.min(full.w, full.h * 1.7);
  const box = { x: full.x + (full.w - w) / 2, y: full.y, w, h: full.h };
  const g = svg.append("g"), states = L.pdfa.states, pad = 50;
  const at = stateSpot(states, box, pad, { ring: true });
  const r = d3.scaleSqrt().domain([0, d3.max(states, s => s.visits)]).range([14, Math.min(46, box.h / 7)]);
  const radius = s => r(s.visits);
  const edges = drawMachineEdges(g.append("g"), L.pdfa, at, radius);
  const sg = g.append("g").selectAll("g").data(states).join("g").attr("transform", s => `translate(${at(s)})`);
  sg.append("circle").attr("class", "state-circle").attr("r", radius).attr("fill", s => stateColor(s.id));
  sg.append("text").attr("class", "t-title halo").attr("text-anchor", "middle").attr("y", 5).text(s => s.id);
  const edgesAt = states.length * 0.14 + 0.2;
  demoTimeline({
    duration: edgesAt + 1.2,
    render: t => {
      sg.attr("opacity", (s, i) => ramp(t, i * 0.14, 0.4));
      edges.attr("opacity", ramp(t, edgesAt, 0.6));
    },
  });
}

// point the player at one recording and say where its story starts: the held-out benign
// from its beginning, an attack a few seconds before its first alert (or first flag)
function demoCue(i, lead) {
  player.capture = i;
  player.listeners = [];
  const { c, begin } = capture();
  const ws = S.meta.window_size;
  const w = i === 0 ? null : c.windows.find(w => w.alert) || c.windows.find(w => w.flagged || w.likelihood_flag);
  player.t = w ? Math.max(begin, w.index * ws - lead) : begin;
}

// the replay slides: the slide's clock is the recording's clock, `rate` recording seconds a second
function demoPlayback(rate) {
  const pill = d3.select("#demo-status").attr("hidden", null);
  let shown = null;
  player.on("tick", t => {
    const status = statusOf(t);
    if (status.text === shown) return;
    shown = status.text;
    pill.attr("class", `status demo-status ${status.cls}`).html(`<span class="dot"></span>${status.text}`);
  });
  const { begin, end } = capture();
  const tl = demoTimeline({
    duration: end - begin, start: player.t - begin, rate,
    label: u => `${f1(begin + u)} s / ${f1(end)} s`,
    render: u => player.seek(begin + u),
  });
  // a click on the score strip moves the player itself: keep the scrubber with it
  player.on("tick", t => tl.follow(t - begin));
}

function slideReplay(box, i) {
  demoCue(i, 3);
  // the machine gets the whole width: no cluster inset here, so the states can spread out
  const top = { x: box.x, y: box.y, w: box.w, h: box.h * 0.62 };
  const strip = { x: box.x + 30, y: box.y + box.h * 0.68, w: box.w - 40, h: box.h * 0.32 - 30 };
  machineView(svg.append("g"), top, { ring: true });
  scoreStrip(svg.append("g"), strip, { minimal: true });
  demoPlayback(i === 0 ? 4 : 2);
}

function slideForget(box, i) {
  demoCue(i, 2);
  scoreStrip(svg.append("g"), { x: box.x + 30, y: box.y + 20, w: box.w - 40, h: box.h - 80 }, { minimal: true });
  demoPlayback(2);
}

function setMode(next) {
  mode = next;
  d3.select(".app").classed("demo", mode === "demo");
  d3.selectAll(".mode button").attr("aria-pressed", function () { return this.dataset.mode === mode; });
  try { localStorage.setItem("viz-mode", mode); } catch (e) { /* storage may be blocked */ }
  show(currentAct);
}

// ---------------------------------------------------------------- act 1: data
// What the page is built from. Served by viz/serve.py, this tab scans folders, takes uploads,
// assigns each capture a role and tap, sets the cluster profile, and rebuilds the bundle every
// other act reads. As a static file it says what the baked bundle came from.

const dataView = d3.select("#dataview");
// API rows are plain JSON (paths as typed), so they are escaped here; bundle strings arrive
// escaped from Python and are inserted as they are.
const esc = value => String(value ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PROFILE_FIELDS = [
  ["pod_cidrs", "Pod CIDRs", "list"], ["service_cidrs", "Service CIDRs", "list"],
  ["pod_subnet_prefix", "Per-node pod subnet prefix", "int"],
  ["control_plane_ports", "Control-plane ports", "list"], ["kubelet_ports", "Kubelet ports", "list"],
  ["nfs_port", "Storage (NFS) port", "int"], ["overlay_name", "Overlay name", "text"],
  ["skip_bridge_hosts", "Skip .0/.1 of each pod subnet (flannel)", "bool"]];
const data = {
  ready: false, state: null, files: [], profile: null, preset: "k3s",
  scanPath: "", root: "", method: "tcp", forget: null, allowBulk: false, selected: "",
  busy: null, error: null, note: null,
  live: { source: null, rows: [], path: "", speed: "10", status: "idle" },
};

async function api(path, body, { raw = false, headers = {} } = {}) {
  const init = body === undefined ? {} : raw
    ? { method: "POST", headers, body }
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, init);
  let out = null;
  try { out = await res.json(); } catch (e) { throw new Error(`${res.status} ${res.statusText}`); }
  if (!res.ok || (out && out.error)) throw new Error((out && out.error) || res.statusText);
  return out;
}

const levelOf = tap => (["pod", "node", "router"].find(l => String(tap || "").startsWith(l + "-")) || "pod");
const rowFromSource = f => ({ path: f.path, name: f.name, kind: f.path.match(/\.pcap(ng)?$/i) ? "capture" : "csv",
  role: f.role, vantage: f.tap || "", level: levelOf(f.tap), scenario: f.scenario || "", problem: null });

async function dataInit() {
  if (data.ready || !SERVER) return;
  data.ready = true;
  try {
    const state = await api("/api/state");
    data.state = state;
    data.root = state.defaults.kubedata_root || "";
    data.forget = state.defaults.forget;
    data.profile = { ...state.profiles.k3s };
    if (state.source) {
      data.files = state.source.files.map(rowFromSource);
      data.profile = { ...state.source.profile };
      data.preset = state.profiles[data.profile.name] ? data.profile.name : "custom";
      data.forget = state.source.forget_seconds;
      data.allowBulk = state.source.allow_bulk;
      data.note = `Showing the ${state.source.files.length} captures the current page was built from (${esc(state.source.origin)}).`;
    }
    if ((state.notes || []).length) data.error = state.notes.join(" ");
    if (state.defaults.scan) { data.scanPath = state.defaults.scan; await dataScan(); return; }
  } catch (e) {
    data.error = `Could not reach the harness: ${e.message}`;
  }
  if (currentAct === "data") renderData();
}

async function dataRun(label, work) {
  data.busy = label; data.error = null; renderData();
  try { await work(); } catch (e) { data.error = e.message; }
  data.busy = null;
  if (currentAct === "data") renderData();
}

const dataScan = () => dataRun("Scanning", async () => {
  const out = await api("/api/scan", { paths: data.scanPath.split("\n").map(s => s.trim()).filter(Boolean), recursive: true });
  data.files = out.files;
  data.note = `${out.files.length} capture files found. Check each one's role and tap, then build.`;
});

const dataManifest = () => dataRun("Reading the manifest", async () => {
  const out = await api("/api/manifest", { root: data.root, method: data.method });
  data.files = out.files.map(f => ({ ...f, name: f.path.split(/[\\/]/).pop(), problem: null }));
  // a recording from localcluster/collect.py names its address plan; anything else is k3s
  const recorded = out.preset && data.state.profiles[out.preset] ? out.preset : null;
  data.preset = recorded || "k3s"; data.profile = { ...data.state.profiles[data.preset] };
  const kubedata = data.root === (data.state.defaults.kubedata_root || null);
  data.note = `${out.files.length} ${esc(data.method)} captures from the manifest at <span class="mono">${esc(data.root)}</span>`
    + (kubedata ? ": the same inputs the static page uses." : ".")
    + (recorded ? ` Its profile.json names the <b>${esc(recorded)}</b> address plan, so that preset is selected.` : "");
});

async function dataUpload(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  await dataRun(`Uploading ${files.length} file${files.length === 1 ? "" : "s"}`, async () => {
    for (const file of files) {
      const out = await api("/api/upload", file, { raw: true, headers: { "X-Filename": file.name } });
      data.files = data.files.filter(f => f.path !== out.file.path).concat([out.file]);
    }
    data.note = `Uploaded ${files.length} file${files.length === 1 ? "" : "s"}. Set each one's role and tap below.`;
  });
}

const dataBuild = () => dataRun("Building: learning the machine and replaying every capture", async () => {
  const assignments = data.files.map(({ path, role, vantage, level, scenario }) => ({ path, role, vantage, level, scenario }));
  const bundle = await api("/api/build", {
    assignments, profile: { ...data.profile, name: data.preset }, forget: Number(data.forget),
    allow_bulk: data.allowBulk, selected: data.selected || null,
    origin: data.files.some(f => f.method) && data.files.every(f => f.method === data.method) ? "KUBEDATA manifest" : "files",
  });
  data.state = await api("/api/state");
  load(bundle);
  data.note = `Built ${Object.keys(bundle.vantages).length} taps.${(bundle.source.notes || []).length ? " " + bundle.source.notes.join(" ") : ""}`;
  show("cluster");
});

function stopLive() {
  if (data.live.source) data.live.source.close();
  data.live.source = null;
  if (data.live.status === "streaming") data.live.status = "stopped";
}

function startLive() {
  stopLive();
  const live = data.live;
  live.rows = []; live.status = "connecting";
  const query = new URLSearchParams({ path: live.path, speed: live.speed });
  const source = new EventSource(`/api/live?${query}`);
  live.source = source;
  source.onmessage = e => {
    live.status = "streaming";
    live.rows.push(JSON.parse(e.data));
    if (live.rows.length > 900) live.rows.shift();
    drawLive();
  };
  source.addEventListener("end", () => { source.close(); live.source = null; live.status = "ended"; drawLive(); });
  source.onerror = () => {
    // EventSource retries a closed stream by itself; a replay that ended or failed should not
    if (live.source !== source) return;
    source.close(); live.source = null;
    live.status = live.rows.length ? "ended" : "failed: is the file a readable capture?";
    drawLive();
  };
  drawLive();
}

function drawLive() {
  const live = data.live;
  const box = dataView.select("#live-chart");
  if (box.empty()) return;
  d3.select("#live-status").text(live.status);
  const last = live.rows[live.rows.length - 1];
  d3.select("#live-now").html(last
    ? `second <b>${fmt(last.t)}</b> · ${fmt(last.packets)} packets · ${d3.format(".3s")(last.bytes)}B · `
      + `${fmt(last.flows)} flows · ${fmt(last.new_endpoints)} new endpoints (${fmt(last.endpoints)} seen)`
    : "no windows yet");
  const node = box.node(), w = Math.max(node.clientWidth, 300), h = 150;
  box.selectAll("*").remove();
  const s = box.append("svg").attr("width", w).attr("height", h).style("position", "static");
  if (!live.rows.length) return;
  const x = d3.scaleLinear().domain(d3.extent(live.rows, r => r.t)).range([40, w - 10]);
  const series = [["packets", "var(--s1)", 8, h / 2 - 6], ["bytes", "var(--s2)", h / 2 + 6, h - 18]];
  for (const [key, color, top, bottom] of series) {
    const y = d3.scaleLinear().domain([0, d3.max(live.rows, r => r[key]) || 1]).nice().range([bottom, top]);
    s.append("path").attr("d", d3.line().x(r => x(r.t)).y(r => y(r[key]))(live.rows))
      .attr("fill", "none").style("stroke", color).attr("stroke-width", 1.5);
    s.append("text").attr("class", "t-small t-2").attr("x", 40).attr("y", top + 10).text(`${key}/s`);
    s.append("g").attr("transform", "translate(38,0)").attr("class", "axis")
      .call(d3.axisLeft(y).ticks(2).tickFormat(d3.format(".2s")));
  }
  s.append("g").attr("class", "axis").attr("transform", `translate(0,${h - 16})`)
    .call(d3.axisBottom(x).ticks(6).tickFormat(d => `${d}s`));
}

function provenanceHtml(src, escaped) {
  if (!src) return `<p>This page carries no record of what it was built from.</p>`;
  const e = escaped ? (v => v ?? "") : esc;
  const rows = src.files.map(f => `<tr><td>${e(f.role)}</td><td class="mono">${e(f.tap)}</td><td>${e(f.scenario)}</td>
      <td class="mono" title="${e(f.path)}">${e(f.name)}</td></tr>`).join("");
  return `<dl class="kv">
      <dt>built</dt><dd>${e(src.built)}</dd><dt>from</dt><dd>${e(src.origin)}</dd>
      <dt>profile</dt><dd>${e(src.profile.name)} · pods ${e(src.profile.pod_cidrs.join(", "))} · services ${e(src.profile.service_cidrs.join(", "))}</dd>
      <dt>anomaly clock</dt><dd>${e(src.forget_seconds)} s</dd>
      <dt>taps drawn</dt><dd>${e(src.drawn.join(", "))}</dd></dl>
    ${(src.notes || []).length ? `<p class="data-warn">${src.notes.map(e).join("<br>")}</p>` : ""}
    <table class="data-table compact"><thead><tr><th>role</th><th>tap</th><th>scenario</th><th>file</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function actData() {
  panel.html(`<h2>Data</h2>
    <p>Every act draws one <b>bundle</b>: the machine learned from each tap's benign capture, and
    each capture replayed through it. This tab decides what goes in.</p>
    <h2>A capture</h2>
    <p>A packet CSV with <span class="mono">ts, frame_len, src_ip, dst_ip, src_port, dst_port, proto</span>
    (header spelling is forgiven), or a raw <b>pcap/pcapng</b>, converted to the same rows first.</p>
    <h2>Roles</h2>
    <p><b>benign</b> trains a tap: the first 70% is learned, the last 30% held out to set its cutoffs.
    Every benign capture also feeds the cluster map. <b>attack</b> is replayed against the tap
    with the same name. A tap needs exactly one benign capture.</p>
    <h2>Tap names</h2>
    <p>A tap is <span class="mono">level-name</span> (pod-nginx, node-child1, router-any). The level
    tells the map where it listened: a node tap claims a host, a pod tap names a pod.</p>
    <h2>Cluster profile</h2>
    <p>The address plan the map assumes. k3s is the testbed's; kubeadm uses 10.244/16 and 10.96/12.
    Pods outside the pod CIDRs are drawn as LAN devices.</p>`);
  if (!SERVER) {
    dataView.html(`<div class="data-wrap">
      <section class="data-card"><h3>This page is a static export</h3>
        <p>It carries one baked bundle and cannot load other data. To point it at other captures, run the harness
        from the <span class="mono">Threat_Detection</span> folder:</p>
        <pre class="mono">.venv/bin/python viz/serve.py --open</pre></section>
      <section class="data-card"><h3>Built from</h3>${provenanceHtml(B && B.source, true)}</section></div>`);
    return;
  }
  dataInit();
  renderData();
}

function renderData() {
  if (!data.ready && SERVER) return;
  const busy = Boolean(data.busy), dis = busy ? "disabled" : "";
  const roleOpts = r => ["benign", "attack", "ignore"].map(o => `<option ${o === r ? "selected" : ""}>${o}</option>`).join("");
  const levelOpts = l => ["pod", "node", "router"].map(o => `<option ${o === l ? "selected" : ""}>${o}</option>`).join("");
  const counts = d3.rollup(data.files, v => v.length, f => f.role);
  const rows = data.files.map((f, i) => `<tr class="${f.role === "ignore" ? "off" : ""}">
      <td><select data-i="${i}" data-k="role" ${dis}>${roleOpts(f.role)}</select></td>
      <td><select data-i="${i}" data-k="level" ${dis}>${levelOpts(f.level)}</select></td>
      <td><input data-i="${i}" data-k="vantage" value="${esc(f.vantage)}" ${dis} size="16"></td>
      <td><input data-i="${i}" data-k="scenario" value="${esc(f.role === "benign" ? "benign" : f.scenario)}" ${f.role === "benign" ? "disabled" : dis} size="14"></td>
      <td class="mono" title="${esc(f.path)}">${esc(f.name || f.path)}</td>
      <td>${esc(f.kind)}</td>
      <td class="data-warn">${esc(f.problem || "")}</td></tr>`).join("");
  const p = data.profile || {};
  const field = ([key, label, type]) => type === "bool"
    ? `<label class="check"><input type="checkbox" data-p="${key}" ${p[key] ? "checked" : ""} ${dis}> ${label}</label>`
    : `<label>${label}<input data-p="${key}" value="${esc(Array.isArray(p[key]) ? p[key].join(", ") : p[key])}" ${dis}></label>`;
  const presets = data.state ? Object.keys(data.state.profiles).concat(["custom"]) : ["k3s"];
  const liveFiles = data.files.filter(f => f.kind !== "unknown" && !f.problem);
  if (!liveFiles.some(f => f.path === data.live.path)) data.live.path = liveFiles.length ? liveFiles[0].path : "";
  const benignTaps = [...new Set(data.files.filter(f => f.role === "benign").map(f => f.vantage.startsWith(f.level + "-") ? f.vantage : `${f.level}-${f.vantage}`))].sort();

  dataView.html(`<div class="data-wrap">
    ${data.busy ? `<div class="data-busy">${esc(data.busy)} …</div>` : ""}
    ${data.error ? `<div class="data-error">${esc(data.error)}</div>` : ""}
    ${data.note && !data.error ? `<div class="data-note">${data.note}</div>` : ""}
    <section class="data-card"><h3>1 · Source</h3>
      <div class="data-row">
        <label class="grow">KUBEDATA root<input id="d-root" value="${esc(data.root)}" placeholder="/path/to/KUBEDATA" ${dis}></label>
        <span class="seg">${["tcp", "ptcp"].map(m => `<button data-method="${m}" aria-pressed="${data.method === m}" ${dis}>${m}</button>`).join("")}</span>
        <button id="d-manifest" ${dis}>Load manifest</button></div>
      <div class="data-row">
        <label class="grow">Folders or files (one per line; folders are searched recursively)
          <textarea id="d-scan" rows="2" placeholder="~/captures/my-cluster" ${dis}>${esc(data.scanPath)}</textarea></label>
        <button id="d-scan-go" ${dis}>Scan</button></div>
      <label class="drop" id="d-drop">Drop CSV, pcap or pcapng files here, or <u>choose files</u>
        <input type="file" id="d-file" multiple accept=".csv,.pcap,.pcapng,.cap" hidden ${dis}></label>
    </section>
    <section class="data-card"><h3>2 · Captures <span class="t-2">${data.files.length} files · ${counts.get("benign") || 0} benign · ${counts.get("attack") || 0} attack</span></h3>
      ${data.files.length ? `<div class="table-scroll"><table class="data-table"><thead><tr><th>role</th><th>level</th><th>tap name</th><th>scenario</th><th>file</th><th>kind</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>
        <div class="data-row small"><button id="d-all-ignore" ${dis}>Ignore all</button>
          <button id="d-clear" ${dis}>Clear list</button></div>`
        : `<p class="t-2">No captures yet: load the manifest, scan a folder, or drop files above.</p>`}
    </section>
    <section class="data-card"><h3>3 · Cluster profile</h3>
      <div class="data-row"><label>Preset<select id="d-preset" ${dis}>${presets.map(n => `<option ${n === data.preset ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label></div>
      <div class="data-grid">${PROFILE_FIELDS.map(field).join("")}</div>
    </section>
    <section class="data-card"><h3>4 · Parameters and build</h3>
      <div class="data-row">
        <label>Anomaly clock (s)<input id="d-forget" type="number" min="1" step="1" value="${esc(data.forget)}" ${dis}></label>
        <label>Open on tap<select id="d-selected" ${dis}><option value="">default</option>${benignTaps.map(t => `<option ${t === data.selected ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>
        <label class="check"><input type="checkbox" id="d-bulk" ${data.allowBulk ? "checked" : ""} ${dis}> draw bulk-transfer taps (inspection only)</label>
        <span class="spacer"></span>
        <button class="primary" id="d-build" ${dis || (counts.get("benign") ? "" : "disabled")}>Build page</button>
        <a class="button ${B ? "" : "disabled"}" href="/api/export" ${B ? "" : 'aria-disabled="true"'}>Export static page</a></div>
      ${B && B.source ? `<details><summary>Current page: built from</summary>${provenanceHtml(B.source, true)}</details>` : ""}
    </section>
    <section class="data-card"><h3>5 · Live input <span class="badge">preview</span></h3>
      <p class="t-2">A capture replayed as if it were arriving now, windowed per second. This is the shape a live
      collector will feed; detection is not wired to the stream yet, so nothing here is scored.</p>
      <div class="data-row">
        <label class="grow">Replay<select id="l-path">${liveFiles.map(f => `<option value="${esc(f.path)}" ${f.path === data.live.path ? "selected" : ""}>${esc(f.name || f.path)}</option>`).join("") || "<option value=''>no capture listed</option>"}</select></label>
        <label>Speed<select id="l-speed">${["1", "10", "50", "200"].map(s => `<option value="${s}" ${s === data.live.speed ? "selected" : ""}>${s}×</option>`).join("")}</select></label>
        <button class="primary" id="l-start" ${liveFiles.length ? "" : "disabled"}>Start</button>
        <button id="l-stop">Stop</button>
        <span class="readout" id="live-status">${esc(data.live.status)}</span></div>
      <div class="readout" id="live-now"></div>
      <div id="live-chart" class="live-chart"></div>
    </section></div>`);

  // table edits keep their state; a role change re-renders so the scenario cell follows it
  dataView.selectAll("[data-i]").on("change", function () {
    const f = data.files[+this.dataset.i];
    f[this.dataset.k] = this.value;
    if (this.dataset.k === "role" || this.dataset.k === "level") renderData();
  });
  dataView.selectAll("[data-p]").on("change", function () {
    const key = this.dataset.p, spec = PROFILE_FIELDS.find(f => f[0] === key);
    const value = spec[2] === "bool" ? this.checked : spec[2] === "int" ? Number(this.value)
      : spec[2] === "list" ? this.value.split(/[\s,]+/).filter(Boolean)
      : this.value;
    data.profile = { ...data.profile, [key]: spec[2] === "list" && /port/.test(key) ? value.map(Number) : value };
    data.preset = "custom";
    renderData();
  });
  d3.select("#d-preset").on("change", function () {
    data.preset = this.value;
    if (data.state.profiles[this.value]) data.profile = { ...data.state.profiles[this.value] };
    renderData();
  });
  d3.select("#d-root").on("change", function () { data.root = this.value; });
  dataView.selectAll("[data-method]").on("click", function () { data.method = this.dataset.method; renderData(); });
  d3.select("#d-manifest").on("click", dataManifest);
  d3.select("#d-scan").on("change", function () { data.scanPath = this.value; });
  d3.select("#d-scan-go").on("click", () => { data.scanPath = d3.select("#d-scan").property("value"); dataScan(); });
  d3.select("#d-file").on("change", function () { dataUpload(this.files); });
  d3.select("#d-drop")
    .on("dragover", e => { e.preventDefault(); d3.select("#d-drop").classed("over", true); })
    .on("dragleave", () => d3.select("#d-drop").classed("over", false))
    .on("drop", e => { e.preventDefault(); d3.select("#d-drop").classed("over", false); dataUpload(e.dataTransfer.files); });
  d3.select("#d-all-ignore").on("click", () => { data.files.forEach(f => { f.role = "ignore"; }); renderData(); });
  d3.select("#d-clear").on("click", () => { data.files = []; data.note = null; renderData(); });
  d3.select("#d-forget").on("change", function () { data.forget = this.value; });
  d3.select("#d-selected").on("change", function () { data.selected = this.value; });
  d3.select("#d-bulk").on("change", function () { data.allowBulk = this.checked; });
  d3.select("#d-build").on("click", dataBuild);
  d3.select("#l-path").on("change", function () { data.live.path = this.value; });
  d3.select("#l-speed").on("change", function () { data.live.speed = this.value; });
  d3.select("#l-start").on("click", startLive);
  d3.select("#l-stop").on("click", () => { stopLive(); drawLive(); });
  drawLive();
}

// The other acts with nothing built yet: say so, and where to start.
function actEmpty() {
  panel.html(`<h2>Nothing loaded</h2><p>Every act draws a built page. Choose captures on the <b>Data</b> tab and build one.</p>`);
  dataView.html(`<div class="data-wrap"><section class="data-card"><h3>No page built yet</h3>
    <p>${SERVER ? "Pick captures on the Data tab, then Build." : "This file carries no bundle."}</p>
    ${SERVER ? `<button class="primary" id="d-go">Go to Data</button>` : ""}</section></div>`);
  d3.select("#d-go").on("click", () => show("data"));
}

// ---------------------------------------------------------------- app shell

const ACTS = { data: actData, cluster: actCluster, learning: actLearning, detection: actDetection };
let currentAct = "cluster";

function show(act) {
  stopLearn();
  demoStop();
  if (window.__stopPlayer) window.__stopPlayer();
  window.onkeydown = null;
  if (act !== "data") stopLive();
  currentAct = act;
  d3.selectAll(".acts button").attr("aria-selected", function () { return this.dataset.act === act; });
  svg.selectAll("*").remove();
  controls.html("");
  demoLayer.html("");
  dataView.html("");
  hideTip();
  defs();
  try { localStorage.setItem("viz-act", act); } catch (e) { /* storage may be blocked */ }
  // the demo walkthrough hides the tabs and needs a bundle; the data tab is a detail-mode form
  const form = act === "data" || !B;
  d3.select(".app").classed("form-act", form);
  if (B && mode === "demo") return drawSlide();
  if (act === "data") return actData();
  if (!B) return actEmpty();
  ACTS[act]();
}

// Point every act at one vantage. The replay keeps its scenario and, through the taps'
// shared timebase, its moment in the recording, when the new tap has that scenario.
function selectVantage(label) {
  const before = S ? S.playback.captures[player.capture] : null;
  const beforeT = player.t;
  S = { ...B.vantages[label], cluster: B.cluster };
  L = S.learning;
  ptaById = new Map(L.pta.map(n => [n.id, n]));
  stateOfPta = new Map();
  for (const s of L.pdfa.states) for (const id of s.pta_ids) stateOfPta.set(id, s.id);
  protocols = [...new Set(L.symbols.map(s => s.proto))];
  learn.step = 0;
  prepared.clear();
  const same = before ? S.playback.captures.findIndex(c => c.scenario === before.scenario) : -1;
  player.capture = Math.max(same, 0);
  player.t = same >= 0 ? beforeT + before.t0 - S.playback.captures[same].t0 : capture().begin;
  d3.select("#vantage").property("value", label);
  d3.select("#subtitle").text(`${S.meta.vantage} · ${S.meta.trace_len}-flow traces · `
    + `${S.meta.forget_seconds} s anomaly clock · built ${S.meta.generated.slice(0, 10)}`);
  try { localStorage.setItem(TAP_KEY, label); } catch (e) { /* storage may be blocked */ }
}

// the remembered tap is keyed to the build, so a page rebuilt with --vantage opens there
let TAP_KEY = null;

// Make `bundle` the page's data: the tap picker, the remembered-tap key, the selected tap.
// The Data tab calls it after a build; start-up calls it with the baked bundle (or none).
function load(bundle, tap = null) {
  stopLearn();
  player.pause();
  B = bundle;
  S = null;
  VANTAGES = B ? Object.keys(B.vantages) : [];
  d3.select(".pick").style("display", B ? null : "none");
  if (!B) {
    TAP_KEY = null;
    d3.select("#vantage").html("");
    d3.select("#subtitle").text(SERVER ? "nothing built yet · start on the Data tab" : "no bundle");
    return;
  }
  TAP_KEY = `viz-vantage:${B.vantages[B.selected].meta.generated}:${B.selected}`;
  d3.select("#vantage").html(VANTAGES.map(label =>
    `<option value="${label}">${label}${B.vantages[label].meta.calibration_warning ? " (inspection only)" : ""}</option>`).join(""));
  selectVantage(tap && B.vantages[tap] ? tap : B.selected);
}

function switchTo(label) {
  if (!B || !B.vantages[label] || label === S.meta.vantage) return;
  stopLearn();
  player.pause();
  selectVantage(label);
  show(currentAct);
}
window.VIZ_SWITCH = switchTo;

d3.select("#vantage").on("change", e => switchTo(e.target.value));
d3.selectAll(".acts button").on("click", function () { show(this.dataset.act); });
d3.select("#theme").on("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
});
let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => show(currentAct), 150);
});
d3.selectAll(".mode button").on("click", function () { setMode(this.dataset.mode); });
let start = B ? "cluster" : "data", tap = null, startMode = "detail";
load(B);
try {
  const query = new URLSearchParams(location.search);
  start = query.get("act") || localStorage.getItem("viz-act") || start;
  startMode = query.get("mode") || localStorage.getItem("viz-mode") || startMode;
  // a remembered tap belongs to this build: a rebuilt page opens where --vantage says
  tap = query.get("vantage") || (TAP_KEY && localStorage.getItem(TAP_KEY));
} catch (e) { /* ignore */ }
if (B && tap && B.vantages[tap]) selectVantage(tap);
currentAct = !B ? "data" : ACTS[start] ? start : "cluster";
setMode(B && startMode === "demo" ? "demo" : "detail");
})();
