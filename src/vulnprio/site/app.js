// vulnprio dashboard. Two modes, same page:
//  - static (GitHub Pages): reads precomputed data/index.json + data/<scan>.json
//  - live (served by the API at /ui/): reads /scans and /scans/{id}/findings, allows upload
// All scan-derived strings are untrusted and are only ever written via textContent.
"use strict";

const PRIORITIES = ["P1", "P2", "P3", "P4"];
const PRI_LABEL = { P1: "P1 · known exploited", P2: "P2 · likely exploited", P3: "P3 · plausible / critical impact", P4: "P4 · backlog" };
const PAGE = 100;
const $ = (id) => document.getElementById(id);

const state = { mode: null, scans: [], findings: [], filter: "ALL", q: "", fixable: false, shown: PAGE };

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "style") for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

const svgEl = (tag, attrs = {}) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};

const fmtEpss = (e) => (e == null ? "–" : e >= 0.1 ? (e * 100).toFixed(0) + "%" : e >= 0.001 ? (e * 100).toFixed(1) + "%" : "<0.1%");
const priColor = (p) => `var(--${p.toLowerCase()})`;

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: "application/json" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}

async function detectMode() {
  try {
    const idx = await getJson("data/index.json");
    state.mode = "static";
    state.scans = idx.scans;
    $("mode").textContent = "Demo: real Trivy/Grype scans of public images";
    $("foot").textContent =
      `Exploit data as of ${idx.generated_at.replace("T", " ")} UTC · CISA KEV catalog ${idx.kev_catalog_version} · EPSS from FIRST.org. ` +
      "Rebuilt by CI on every push and weekly.";
  } catch {
    state.mode = "live";
    state.scans = (await getJson("/scans")).scans;
    $("mode").textContent = "Live API";
    $("upload").hidden = false;
    $("foot").textContent = "Live mode: data from this vulnprio API instance.";
  }
}

async function loadScan(scanId) {
  $("status").textContent = "Loading…";
  if (state.mode === "static") {
    const doc = await getJson(`data/${encodeURIComponent(scanId)}.json`);
    state.findings = doc.findings;
  } else {
    // ponytail: pulls every page up front (fine to ~10k findings); switch to server-side filtering past that.
    let findings = [], cursor = null;
    do {
      const q = new URLSearchParams({ limit: "500", ...(cursor ? { cursor } : {}) });
      const page = await getJson(`/scans/${encodeURIComponent(scanId)}/findings?${q}`);
      findings = findings.concat(page.findings);
      cursor = page.next;
    } while (cursor);
    state.findings = findings;
  }
  const meta = state.scans.find((s) => s.scan_id === scanId);
  state.shown = PAGE;
  renderSummary(meta);
  renderScatter();
  renderTable();
  $("status").textContent = "";
}

function renderSummary(meta) {
  const s = meta.summary;
  $("t-total").textContent = s.total.toLocaleString();
  $("t-hc").textContent = s.high_or_critical.toLocaleString();
  $("t-act").textContent = s.act_now.toLocaleString();
  $("t-act-sub").textContent = `${s.fixable_act_now} with a fix available`;
  $("t-kev").textContent = s.kev.toLocaleString();
  const pct = s.high_or_critical ? Math.round((1 - s.act_now / s.high_or_critical) * 100) : 0;
  const h = $("headline");
  h.replaceChildren(
    `${meta.name}: ${s.total.toLocaleString()} findings, ${s.high_or_critical} rated HIGH/CRITICAL. `,
    el("b", {}, `${s.act_now} need action now`),
    s.act_now < s.high_or_critical ? ` (${pct}% fewer than severity-only triage).` : "."
  );
}

// --- scatter: CVSS (x, linear 0-10) vs EPSS (y, log 1e-4..1) ---
function renderScatter() {
  const svg = $("scatter");
  const W = svg.clientWidth || 800, H = svg.clientHeight || 340;
  const m = { l: 52, r: 12, t: 10, b: 38 };
  const x = (v) => m.l + (v / 10) * (W - m.l - m.r);
  const LOG_MIN = -4;
  const y = (e) => {
    const lv = Math.log10(Math.max(e, 1e-4));
    return m.t + (1 - (lv - LOG_MIN) / -LOG_MIN) * (H - m.t - m.b);
  };
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.replaceChildren();
  svg.append(svgEl("desc", { id: "scatter-desc" }));
  svg.firstChild.textContent = "Scatter plot of CVSS versus EPSS for every finding. The findings table lists the same data.";

  for (const e of [1e-4, 1e-3, 1e-2, 1e-1, 1]) {
    svg.append(svgEl("line", { class: "grid", x1: m.l, x2: W - m.r, y1: y(e), y2: y(e) }));
    const t = svgEl("text", { x: m.l - 6, y: y(e) + 4, "text-anchor": "end" });
    t.textContent = e >= 0.01 ? `${e * 100}%` : `${+(e * 100).toFixed(2)}%`;
    svg.append(t);
  }
  for (let v = 0; v <= 10; v += 2) {
    const t = svgEl("text", { x: x(v), y: H - m.b + 16, "text-anchor": "middle" });
    t.textContent = v;
    svg.append(t);
  }
  svg.append(svgEl("line", { class: "axis", x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b }));
  // tier thresholds
  svg.append(svgEl("line", { class: "thr", x1: m.l, x2: W - m.r, y1: y(0.1), y2: y(0.1) }));
  const thr = svgEl("text", { x: m.l + 6, y: y(0.1) - 5 });
  thr.textContent = "P2 threshold: EPSS 10%";
  svg.append(thr);
  const xt = svgEl("text", { class: "title", x: (W + m.l) / 2, y: H - 4, "text-anchor": "middle" });
  xt.textContent = "CVSS base score (impact)";
  const yt = svgEl("text", { class: "title", x: 12, y: m.t + 4, transform: `rotate(-90 12 ${m.t + 4})`, "text-anchor": "end" });
  yt.textContent = "EPSS (likelihood)";
  svg.append(xt, yt);

  // Draw low priorities first so P1/P2 sit on top.
  const pts = state.findings.filter((f) => f.cvss != null && f.epss != null);
  const order = [...pts].sort((a, b) => b.priority.localeCompare(a.priority));
  const tip = $("tip");
  for (const f of order) {
    // deterministic horizontal jitter so identical CVSS values don't stack into one column
    let h = 0;
    for (const ch of f.vuln_id + f.package) h = (h * 31 + ch.charCodeAt(0)) | 0;
    const jitter = ((h % 100) / 100 - 0.5) * 0.18;
    const c = svgEl("circle", {
      cx: x(Math.min(10, Math.max(0, f.cvss + jitter))),
      cy: y(f.epss),
      r: f.priority === "P4" ? 3 : 4.5,
      fill: priColor(f.priority),
      tabindex: f.priority <= "P2" ? "0" : "-1",
    });
    const show = () => {
      tip.replaceChildren(
        el("b", {}, `${f.vuln_id} · ${f.priority}`),
        `${f.package} ${f.installed_version || ""}`,
        el("br"),
        `EPSS ${fmtEpss(f.epss)} · CVSS ${f.cvss.toFixed(1)}${f.kev ? " · in CISA KEV" : ""}`
      );
      tip.hidden = false;
      const cx = +c.getAttribute("cx"), cy = +c.getAttribute("cy");
      const scale = svg.clientWidth / W;
      tip.style.left = Math.min(cx * scale + 12, svg.clientWidth - 290) + "px";
      tip.style.top = Math.max(cy * scale - 50, 0) + "px";
    };
    c.addEventListener("mouseenter", show);
    c.addEventListener("focus", show);
    c.addEventListener("mouseleave", () => (tip.hidden = true));
    c.addEventListener("blur", () => (tip.hidden = true));
    svg.append(c);
  }
}

function renderLegendAndChips() {
  $("legend").replaceChildren(...PRIORITIES.map((p) => el("span", { style: { "--c": priColor(p) } }, PRI_LABEL[p])));
  const chips = ["ALL", ...PRIORITIES].map((p) => {
    const b = el("button", { type: "button", "aria-pressed": String(state.filter === p) }, p === "ALL" ? "All" : p);
    b.addEventListener("click", () => {
      state.filter = p;
      state.shown = PAGE;
      for (const other of $("chips").children) other.setAttribute("aria-pressed", String(other === b));
      renderTable();
    });
    return b;
  });
  $("chips").replaceChildren(...chips);
}

function filtered() {
  const q = state.q.trim().toLowerCase();
  return state.findings.filter(
    (f) =>
      (state.filter === "ALL" || f.priority === state.filter) &&
      (!state.fixable || f.fixed_version) &&
      (!q || f.vuln_id.toLowerCase().includes(q) || (f.cve || "").toLowerCase().includes(q) || f.package.toLowerCase().includes(q))
  );
}

function vulnLink(f) {
  const id = f.cve || f.vuln_id;
  if (/^CVE-\d{4}-\d{4,}$/.test(id)) return el("a", { href: `https://nvd.nist.gov/vuln/detail/${id}`, rel: "noopener noreferrer", target: "_blank" }, f.vuln_id);
  if (/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/.test(f.vuln_id)) return el("a", { href: `https://github.com/advisories/${f.vuln_id}`, rel: "noopener noreferrer", target: "_blank" }, f.vuln_id);
  return document.createTextNode(f.vuln_id);
}

function renderTable() {
  const rows = filtered();
  const body = rows.slice(0, state.shown).map((f) =>
    el(
      "tr",
      {},
      el("td", {}, el("span", { class: `badge ${f.priority.toLowerCase()}`, style: { "--c": priColor(f.priority) } }, f.priority)),
      el("td", { class: "vid" }, vulnLink(f), f.kev ? el("span", { class: "kev", title: "In CISA Known Exploited Vulnerabilities catalog" }, "KEV") : null),
      el("td", { class: "pkg" }, f.package),
      el("td", { class: "ver" }, `${f.installed_version || "?"} → ${f.fixed_version || "no fix"}`),
      el("td", { class: "num" }, fmtEpss(f.epss)),
      el("td", { class: "num" }, f.cvss == null ? "–" : f.cvss.toFixed(1)),
      el("td", {}, f.severity),
      el("td", { class: "why" }, f.reasons.join(" · "))
    )
  );
  $("rows").replaceChildren(...body);
  $("count").textContent = `Showing ${Math.min(state.shown, rows.length)} of ${rows.length}`;
  $("more").hidden = state.shown >= rows.length;
}

async function upload(file) {
  $("status").textContent = `Uploading ${file.name}…`;
  const r = await fetch(`/scans?name=${encodeURIComponent(file.name.slice(0, 128))}`, { method: "POST", body: file });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    $("status").textContent = `Upload failed: ${body.detail || r.status}`;
    return;
  }
  state.scans = (await getJson("/scans")).scans;
  fillScanSelect(body.scan_id);
  await loadScan(body.scan_id);
}

function fillScanSelect(selected) {
  $("scan").replaceChildren(
    ...state.scans.map((s) => {
      const o = el("option", { value: s.scan_id }, `${s.name} (${s.summary.total} findings)`);
      if (s.scan_id === selected) o.selected = true;
      return o;
    })
  );
}

async function main() {
  renderLegendAndChips();
  $("q").addEventListener("input", (e) => { state.q = e.target.value; state.shown = PAGE; renderTable(); });
  $("fixable").addEventListener("change", (e) => { state.fixable = e.target.checked; state.shown = PAGE; renderTable(); });
  $("more").addEventListener("click", () => { state.shown += PAGE; renderTable(); });
  $("scan").addEventListener("change", (e) => loadScan(e.target.value));
  $("file").addEventListener("change", (e) => e.target.files[0] && upload(e.target.files[0]));
  let resizeTimer;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(renderScatter, 150); });
  try {
    await detectMode();
    if (!state.scans.length) {
      $("status").textContent = "No scans yet. Upload a Trivy/Grype JSON, SARIF, or CSV file.";
      return;
    }
    const wanted = new URLSearchParams(location.search).get("scan");
    const first = state.scans.find((s) => s.scan_id === wanted) || state.scans[0];
    fillScanSelect(first.scan_id);
    await loadScan(first.scan_id);
  } catch (err) {
    $("status").textContent = `Could not load data: ${err.message}`;
  }
}

main();
