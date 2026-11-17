// The event log viewer: one recorded session's events, filtered by kind, tap and text.
// It reads /api/log (live/serve.py), which filters the raw lines before parsing them, so a
// 16 MB session with 31,000 window records opens without shipping them to the page.
(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? "").replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const f1 = v => (v === null || v === undefined || !isFinite(v)) ? "–" : Number(v).toFixed(1);
  // score and cutoff sit a fraction apart on every alert, so they carry two decimals
  const f2 = v => (v === null || v === undefined || !isFinite(v)) ? "–" : Number(v).toFixed(2);
  const stamp = at => at ? new Date(at * 1000).toTimeString().slice(0, 8) : "–";
  const size = n => n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} kB`;

  // every kind the sessions record; the response events are the ones an operator acts on
  const KINDS = [["alert", "alerts"], ["release", "releases"], ["attack", "attacks"],
                 ["tap", "tap changes"], ["learn", "learning"], ["ready", "machines"],
                 ["started", "session"], ["stopped", "session end"], ["note", "notes"],
                 ["window", "windows"]];
  const st = { session: null, kinds: new Set(["alert", "release", "attack"]), tap: "",
               q: "", limit: 400, data: null, selected: null, busy: false, timer: null };

  // ---------------------------------------------------------------- reading it
  async function load() {
    if (st.busy) return;
    st.busy = true;
    const params = new URLSearchParams({ kind: [...st.kinds].join(","), limit: st.limit });
    if (st.session) params.set("session", st.session);
    if (st.tap) params.set("tap", st.tap);
    if (st.q) params.set("q", st.q);
    try {
      const response = await fetch(`/api/log?${params}`);
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      st.data = data;
      st.session = data.session;
      renderSessions();
      renderKinds();
      renderTaps();
      renderRows();
    } catch (error) {
      $("subtitle").textContent = `could not read the log: ${error.message}`;
    } finally {
      st.busy = false;
    }
  }

  // ---------------------------------------------------------------- the controls
  function renderSessions() {
    const data = st.data, box = $("session");
    const options = data.sessions.map(s =>
      `<option value="${esc(s.name)}"${s.name === data.session ? " selected" : ""}>` +
      `${esc(s.name.replace(/^session-/, ""))} · ${size(s.bytes)}</option>`);
    if (box.dataset.html !== options.join("")) {
      box.dataset.html = options.join("");
      box.innerHTML = options.join("") || `<option value="">no sessions yet</option>`;
    }
    const events = data.total, counts = data.counts || {};
    const alerts = counts.alert || 0, released = counts.release || 0;
    $("subtitle").textContent = data.session
      ? `${alerts} alerts · ${released} releases · ${events} event${events === 1 ? "" : "s"} matching`
      : "no recorded session under this monitor's data directory";
  }

  function renderKinds() {
    const counts = (st.data && st.data.counts) || {};
    const box = $("kinds");
    const html = KINDS.map(([kind, label]) => {
      const on = st.kinds.has(kind) ? " on" : "";
      const count = counts[kind] ? ` ${counts[kind]}` : "";
      return `<button class="small kindchip${on}" data-kind="${kind}">${label}${count}</button>`;
    }).join("");
    if (box.dataset.html !== html) {
      box.dataset.html = html;
      box.innerHTML = html;
      box.querySelectorAll("[data-kind]").forEach(button => button.onclick = () => {
        const kind = button.dataset.kind;
        if (st.kinds.has(kind)) st.kinds.delete(kind); else st.kinds.add(kind);
        load();
      });
    }
  }

  function renderTaps() {
    const labels = new Set();
    for (const event of (st.data && st.data.events) || []) if (event.label) labels.add(event.label);
    const options = ["", ...[...labels].sort()].map(label =>
      `<option value="${esc(label)}"${label === st.tap ? " selected" : ""}>` +
      `${label ? esc(label) : "every tap"}</option>`);
    const box = $("tap");
    if (box.dataset.html !== options.join("")) {
      box.dataset.html = options.join("");
      box.innerHTML = options.join("");
    }
  }

  // ---------------------------------------------------------------- the rows
  const describe = event => {
    switch (event.kind) {
      case "alert": return ["bad", "alert", String(event.label || "")];
      case "release": return ["good", "released", String(event.label || "")];
      case "attack": return ["attack", event.phase === "start" ? "attack" : "attack end", ""];
      case "window": return ["", event.status || "window", String(event.label || "")];
      default: return ["", event.kind || "event", String(event.label || "")];
    }
  };

  function body(event) {
    switch (event.kind) {
      case "alert": {
        // sessions recorded before alerts carried their score simply have no numbers to show
        const parts = [];
        if (event.score != null) parts.push(`score <b>${f2(event.score)}</b> over cutoff ${f2(event.cutoff)}`);
        if (event.attack) parts.push(`${f1(event.since_start)} s into <b>${esc(event.attack)}</b>`);
        if (event.top && event.top.symbols) parts.push(`<span class="mono">${esc(event.top.symbols.slice(0, 3).join(" "))}</span>`);
        return parts.join(" · ") || "flagged";
      }
      case "release": {
        const parts = [`held ${f1(event.lasted)} s`];
        if (event.score != null) parts.push(`score ${f2(event.score)} over ${f2(event.cutoff)}`);
        if (event.attack && event.since_end != null) parts.push(`${f1(event.since_end)} s after ${esc(event.attack)} ended`);
        if (event.attack && event.since_end == null) parts.push(`${f1(event.since_start)} s into ${esc(event.attack)}`);
        return parts.join(" · ");
      }
      case "attack":
        return event.phase === "start" ? `<b>${esc(event.scenario)}</b> started for ${event.seconds} s`
          : `<b>${esc(event.scenario)}</b> ended${event.early ? " early" : ""}`;
      case "tap": return `tap ${esc(event.state)}${event.error ? ` · ${esc(event.error)}` : ""}`;
      case "learn":
        return event.phase === "failed" ? `could not learn: ${esc(event.error)}`
          : `${esc(event.phase)} ${event.seconds ? `${event.seconds} s` : ""}`;
      case "ready":
        return `machine from ${esc(event.source || "stream")} · cutoff ${f1(event.cutoff)}` +
          ` · ${event.train_flows} flows · ${event.held_windows} held windows`;
      case "started":
        return `watching ${event.taps.length} taps${event.recording ? ", recording" : ""}: ${esc(event.taps.join(", "))}`;
      case "stopped": return `session closed: ${esc(String(event.session || "").split("/").pop())}`;
      case "note": return esc(event.text);
      case "window":
        return `t ${event.t} · peak ${f1(event.peak)} · ${esc(event.status)}` +
          ` · ${event.packets} packets, ${event.flows} flows`;
      default: return esc(JSON.stringify(event).slice(0, 120));
    }
  }

  function renderRows() {
    const events = ((st.data && st.data.events) || []).slice().reverse();   // newest first
    const box = $("rows");
    $("count").textContent = st.data && st.data.session
      ? `${events.length} shown of ${st.data.total}` : "";
    if (!events.length) {
      box.innerHTML = `<p class="muted">${st.data && st.data.session
        ? "Nothing matches these filters."
        : "Watch a tap on the monitor and its session's log appears here."}</p>`;
      return;
    }
    box.innerHTML = events.map((event, index) => {
      const [cls, badge, tap] = describe(event);
      const selected = st.selected === index ? " sel" : "";
      return `<div class="logrow ${cls}${selected}" data-i="${index}" title="${esc(JSON.stringify(event).slice(0, 300))}">` +
        `<time>${stamp(event.wall || event.at)}</time><span class="rowtap">${esc(tap)}</span>` +
        `<span><span class="badge">${esc(badge)}</span> ${body(event)}</span></div>`;
    }).join("");
    box.querySelectorAll(".logrow").forEach(row => row.onclick = () => {
      st.selected = Number(row.dataset.i);
      renderRows();
      showDetail(events[st.selected]);
    });
    const selected = box.querySelector(".logrow.sel");
    if (selected) selected.scrollIntoView({ block: "nearest" });
  }

  function showDetail(event) {
    if (!event) return;
    $("detail-title").textContent = `${event.kind} · ${stamp(event.wall || event.at)}`;
    const pairs = (event.top && event.top.pairs) || [];
    const list = pairs.length
      ? `<h4>conversations in the peak trace</h4><ul class="pairs">${
          pairs.map(([a, b]) => `<li class="mono">${esc(a)} → ${esc(b)}</li>`).join("")}</ul>` : "";
    $("detail").innerHTML = `${list}<h4>the event as recorded</h4><pre>${esc(JSON.stringify(event, null, 2))}</pre>`;
    $("detail").classList.remove("muted");
  }

  // ---------------------------------------------------------------- wiring
  $("session").onchange = event => { st.session = event.target.value; st.selected = null; load(); };
  $("tap").onchange = event => { st.tap = event.target.value; st.selected = null; load(); };
  $("limit").onchange = event => { st.limit = Number(event.target.value); load(); };
  let typing = null;
  $("q").oninput = event => {
    clearTimeout(typing);
    typing = setTimeout(() => { st.q = event.target.value.trim(); st.selected = null; load(); }, 220);
  };
  $("refresh").onclick = () => load();
  $("follow").onchange = event => {
    clearInterval(st.timer);
    st.timer = event.target.checked ? setInterval(load, 3000) : null;
  };
  $("theme").onclick = () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
  };
  load();
})();
