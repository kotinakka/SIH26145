const API_BASE = window.location.origin;
const WS_PROTO = window.location.protocol === "https:" ? "wss:" : "ws:";
const WS_URL = `${WS_PROTO}//${window.location.host}/ws/alerts`;
// How close together (ms) two alerts with the same threat_class/src/dst have
// to be before they're folded into a single incident instead of a new row.
const AGGREGATION_WINDOW_MS = 30000;

// Maps the backend's threat_class values to the six official categories
// from the problem statement, plus the color used for that category.
const CATEGORY_MAP = {
  DDOS: { label: "DDoS", color: "#DC2626" },
  BOTNET_C2: { label: "C2 Beaconing", color: "#D97706" },
  DNS_TUNNEL: { label: "DGA / DNS Tunneling", color: "#7C3AED" },
  MALWARE_ENCRYPTED: { label: "Encrypted Session Anomaly", color: "#0891B2" },
  PORT_SCAN: { label: "Reconnaissance / Port Scan", color: "#EA580C" },
  DATA_EXFIL: { label: "Data Exfiltration", color: "#DB2777" },
};
const CATEGORY_ORDER = ["DDOS", "BOTNET_C2", "DNS_TUNNEL", "MALWARE_ENCRYPTED", "PORT_SCAN", "DATA_EXFIL"];

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const SEVERITY_COLORS = {
  CRITICAL: "#DC2626",
  HIGH: "#EA580C",
  MEDIUM: "#D97706",
  LOW: "#16A34A",
};

// ---------- State ----------

let lastSessionFlowsPerSec = null;
let timeBuckets = new Map(); // bucketStartSeconds -> count, for the traffic chart
let ws = null;
let isStreaming = false;

// Aggregated incidents. Keyed by `${threat_class}|${src_ip}|${dst_ip}` so
// repeated alerts from the same attack collapse into one row instead of
// flooding the table.
let incidentsByKey = new Map();
let incidentsList = []; // same objects as incidentsByKey, kept for stable ordering
let selectedIncidentId = null;
let activeCategoryFilter = null; // one of CATEGORY_ORDER, or null

// ---------- Elements ----------

const el = {
  connDot: document.getElementById("conn-dot"),
  connLabel: document.getElementById("conn-label"),
  streamSpeedLabel: document.getElementById("stream-speed-label"),
  clock: document.getElementById("clock"),
  pcapSelect: document.getElementById("pcap-select"),
  speedSelect: document.getElementById("speed-select"),
  startBtn: document.getElementById("start-stream-btn"),
  startBtnLabel: document.getElementById("start-stream-label"),
  fileInput: document.getElementById("file-input"),
  uploadBtn: document.getElementById("upload-btn"),
  statFlows: document.getElementById("stat-flows"),
  statAlerts: document.getElementById("stat-alerts"),
  statCritical: document.getElementById("stat-critical"),
  statFlowsps: document.getElementById("stat-flowsps"),
  statLatency: document.getElementById("stat-latency"),
  statStatus: document.getElementById("stat-status"),
  tableBody: document.getElementById("alert-table-body"),
  feedCount: document.getElementById("feed-count"),
  detailPanel: document.getElementById("detail-panel"),
  detailScrim: document.getElementById("detail-scrim"),
  detailBody: document.getElementById("detail-body"),
  detailClose: document.getElementById("detail-close"),
  threatChartEmpty: document.getElementById("threat-chart-empty"),
  severityChartEmpty: document.getElementById("severity-chart-empty"),
  trafficChartEmpty: document.getElementById("traffic-chart-empty"),
  trafficPanelSubtext: document.getElementById("traffic-panel-subtext"),
  timelineTrack: document.getElementById("timeline-track"),
  timelineEmpty: document.getElementById("timeline-empty"),
  threatCards: document.getElementById("threat-cards"),
  clearFilterBtn: document.getElementById("clear-filter-btn"),
  perfFlows: document.getElementById("perf-flows"),
  perfThroughput: document.getElementById("perf-throughput"),
  perfLatency: document.getElementById("perf-latency"),
  perfPackets: document.getElementById("perf-packets"),
  perfStatus: document.getElementById("perf-status"),
};

// The current /statistics and /ws/alerts contract only gives us discrete
// alert events, not a continuous flows/sec, packets/sec or bytes/sec feed,
// so the traffic graph plots event rate from the alert stream itself. This
// label says so plainly instead of pretending the missing metrics exist.
if (el.trafficPanelSubtext) {
  el.trafficPanelSubtext.textContent = "events/sec (packets/sec and bytes/sec need backend support)";
}
document.getElementById("time-chart").style.display = "none";

// ---------- Clock ----------

function tickClock() {
  el.clock.textContent = new Date().toUTCString().slice(17, 25) + " UTC";
}
setInterval(tickClock, 1000);
tickClock();

// ---------- Connection / system status ----------

function setConnStatus(state) {
  // state: "idle" | "live" | "error"
  el.connDot.className = "conn-dot " + state;
  el.connLabel.textContent =
    state === "live" ? "Live" : state === "error" ? "Connection error" : "Idle";
  setSystemStatus(state === "error" ? "offline" : "online");
}

function setSystemStatus(state) {
  // state: "online" | "offline"
  el.statStatus.textContent = state === "online" ? "ONLINE" : "OFFLINE";
  el.statStatus.className = "stat-value stat-status " + state;
  el.perfStatus.textContent = state === "online" ? "ONLINE" : "OFFLINE";
  el.perfStatus.className = "perf-value " + (state === "online" ? "online" : "");
}

// ---------- Charts ----------

function categoryOf(threatClass) {
  return CATEGORY_MAP[threatClass] || { label: threatClass, color: "#5B6472" };
}

const threatChart = new Chart(document.getElementById("threat-chart"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
  options: {
    plugins: { legend: { position: "bottom", labels: { font: { size: 11 }, boxWidth: 10 } } },
  },
});

const severityChart = new Chart(document.getElementById("severity-chart"), {
  type: "bar",
  data: {
    labels: SEVERITY_ORDER,
    datasets: [{ data: [0, 0, 0, 0], backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLORS[s]) }],
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { font: { size: 11 } }, grid: { display: false } },
      y: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } },
    },
  },
});

const timeChart = new Chart(document.getElementById("time-chart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "events/sec",
        data: [],
        borderColor: "#1D4ED8",
        backgroundColor: "rgba(29,78,216,0.08)",
        fill: true,
        tension: 0.25,
        pointRadius: 3,
      },
    ],
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { font: { size: 10 } } },
      y: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } },
    },
  },
});

function renderThreatChart() {
  const counts = {};
  for (const cat of CATEGORY_ORDER) counts[cat] = 0;
  for (const inc of incidentsList) counts[inc.threatClass] = (counts[inc.threatClass] || 0) + 1;

  const activeCats = CATEGORY_ORDER.filter((c) => counts[c] > 0);
  if (activeCats.length === 0) {
    el.threatChartEmpty.style.display = "block";
    document.getElementById("threat-chart").style.display = "none";
    return;
  }
  el.threatChartEmpty.style.display = "none";
  document.getElementById("threat-chart").style.display = "block";
  threatChart.data.labels = activeCats.map((c) => categoryOf(c).label);
  threatChart.data.datasets[0].data = activeCats.map((c) => counts[c]);
  threatChart.data.datasets[0].backgroundColor = activeCats.map((c) => categoryOf(c).color);
  threatChart.update();
}

function renderSeverityChart() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const inc of incidentsList) counts[inc.severity] = (counts[inc.severity] || 0) + 1;
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0);

  if (total === 0) {
    el.severityChartEmpty.style.display = "block";
    document.getElementById("severity-chart").style.display = "none";
    return;
  }
  el.severityChartEmpty.style.display = "none";
  document.getElementById("severity-chart").style.display = "block";
  severityChart.data.datasets[0].data = SEVERITY_ORDER.map((s) => counts[s]);
  severityChart.update();
}

function renderThreatCards() {
  el.threatCards.innerHTML = "";
  const counts = {};
  for (const cat of CATEGORY_ORDER) counts[cat] = 0;
  for (const inc of incidentsList) counts[inc.threatClass] = (counts[inc.threatClass] || 0) + 1;

  for (const cat of CATEGORY_ORDER) {
    const info = categoryOf(cat);
    const card = document.createElement("button");
    card.type = "button";
    card.className = "threat-card" + (activeCategoryFilter === cat ? " active" : "");
    card.innerHTML = `
      <span class="name">${info.label}</span>
      <span class="count" style="color:${info.color}">${counts[cat]}</span>
      <span class="count-label">incident${counts[cat] === 1 ? "" : "s"}</span>
    `;
    card.addEventListener("click", () => {
      activeCategoryFilter = activeCategoryFilter === cat ? null : cat;
      el.clearFilterBtn.hidden = !activeCategoryFilter;
      renderThreatCards();
      renderIncidentTable();
    });
    el.threatCards.appendChild(card);
  }
}

el.clearFilterBtn.addEventListener("click", () => {
  activeCategoryFilter = null;
  el.clearFilterBtn.hidden = true;
  renderThreatCards();
  renderIncidentTable();
});

function recordTrafficPoint(timestampIso) {
  const t = new Date(timestampIso).getTime() / 1000;
  const bucket = Math.floor(t / 10) * 10;
  timeBuckets.set(bucket, (timeBuckets.get(bucket) || 0) + 1);

  // Keep only the most recent 30 buckets (5 minutes of history)
  const sortedKeys = [...timeBuckets.keys()].sort((a, b) => a - b);
  while (sortedKeys.length > 30) {
    timeBuckets.delete(sortedKeys.shift());
  }

  const keys = [...timeBuckets.keys()].sort((a, b) => a - b);
  el.trafficChartEmpty.style.display = keys.length ? "none" : "block";
  document.getElementById("time-chart").style.display = keys.length ? "block" : "none";
  timeChart.data.labels = keys.map((k) =>
    new Date(k * 1000).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" })
  );
  timeChart.data.datasets[0].data = keys.map((k) => timeBuckets.get(k) / 10);
  timeChart.update();
}

// ---------- Timeline ----------

function renderTimeline() {
  el.timelineTrack.innerHTML = "";
  if (incidentsList.length === 0) {
    el.timelineEmpty.style.display = "block";
    return;
  }
  el.timelineEmpty.style.display = "none";

  const recent = incidentsList.slice(0, 25);
  const times = recent.map((i) => new Date(i.lastTimestamp).getTime());
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const span = maxT - minT || 1;

  for (const inc of recent) {
    const t = new Date(inc.lastTimestamp).getTime();
    const pct = ((t - minT) / span) * 100;
    const marker = document.createElement("button");
    marker.type = "button";
    marker.className = `timeline-marker sev-${inc.severity}`;
    marker.style.left = `${Math.min(97, Math.max(3, pct))}%`;
    marker.title = `${categoryOf(inc.threatClass).label} — ${inc.srcIp} → ${inc.dstIp}`;
    marker.innerHTML = `<span class="dot"></span><span class="tag">${categoryOf(inc.threatClass).label}</span>`;
    marker.addEventListener("click", () => {
      openDetailPanel(inc);
      highlightIncidentRow(inc.id);
    });
    el.timelineTrack.appendChild(marker);
  }
}

// ---------- Incident aggregation ----------

function severityMax(a, b) {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function incidentKey(alert) {
  // DDoS is many sources hitting one destination — group by the
  // victim, not by (source, destination), or a distributed flood
  // with 200 sources becomes 200 separate rows instead of one
  // incident. Everything else groups by both ends as before.
  if (alert.threat_class === "DDOS") {
    return `DDOS|${alert.dst_ip}`;
  }
  return `${alert.threat_class}|${alert.src_ip}|${alert.dst_ip}`;
}

// Folds a raw alert into the aggregated incident list. Returns
// { incident, isNew } so the caller can decide whether to animate.
function ingestAlert(alert) {
  const key = incidentKey(alert);
  const existing = incidentsByKey.get(key);
  const alertTime = new Date(alert.timestamp).getTime();

  if (existing && Math.abs(alertTime - new Date(existing.lastTimestamp).getTime()) <= AGGREGATION_WINDOW_MS) {
    existing.count += 1;
    existing.confidence = Math.max(existing.confidence, alert.confidence);
    existing.severity = severityMax(existing.severity, alert.severity);
    existing.evidence = alert.evidence;
    existing.riskScore = alert.risk_score;
    existing.protocol = alert.protocol;
    existing.srcPort = alert.src_port;
    existing.dstPort = alert.dst_port;
    existing.srcIps.add(alert.src_ip);
    if (alertTime > new Date(existing.lastTimestamp).getTime()) existing.lastTimestamp = alert.timestamp;
    if (alertTime < new Date(existing.firstTimestamp).getTime()) existing.firstTimestamp = alert.timestamp;
    return { incident: existing, isNew: false };
  }

  const incident = {
    id: `${key}|${alertTime}`,
    key,
    threatClass: alert.threat_class,
    srcIp: alert.src_ip,
    srcIps: new Set([alert.src_ip]),
    srcPort: alert.src_port,
    dstIp: alert.dst_ip,
    dstPort: alert.dst_port,
    protocol: alert.protocol,
    confidence: alert.confidence,
    severity: alert.severity,
    count: 1,
    firstTimestamp: alert.timestamp,
    lastTimestamp: alert.timestamp,
    evidence: alert.evidence,
    riskScore: alert.risk_score,
  };
  incidentsByKey.set(key, incident);
  incidentsList.unshift(incident);
  return { incident, isNew: true };
}

function visibleIncidents() {
  const sorted = [...incidentsList].sort(
    (a, b) => new Date(b.lastTimestamp) - new Date(a.lastTimestamp)
  );
  return activeCategoryFilter ? sorted.filter((i) => i.threatClass === activeCategoryFilter) : sorted;
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function renderIncidentTable() {
  const rows = visibleIncidents();
  el.tableBody.innerHTML = "";

  if (rows.length === 0) {
    el.tableBody.innerHTML = `<tr class="empty-row"><td colspan="6">${
      activeCategoryFilter
        ? "No incidents in this category yet."
        : "No alerts yet. Start a live stream or analyze a capture above."
    }</td></tr>`;
    el.feedCount.textContent = "0 shown";
    return;
  }

  for (const inc of rows) {
    const tr = document.createElement("tr");
    tr.className = `sev-${inc.severity}` + (inc.id === selectedIncidentId ? " selected" : "");
    tr.dataset.incidentId = inc.id;
    const time = new Date(inc.lastTimestamp).toLocaleTimeString();
    const countTag = inc.count > 1 ? `<span class="incident-count">&times;${inc.count}</span>` : "";

    const sourceCell = inc.srcIps.size > 1
      ? `${inc.srcIps.size} sources`
      : `${inc.srcIp}:${inc.srcPort}`;

    tr.innerHTML = `
      <td class="mono">${time}</td>
      <td class="mono">${sourceCell}</td>
      <td class="mono">${inc.dstIp}:${inc.dstPort}</td>
      <td class="threat-tag">${categoryOf(inc.threatClass).label}${countTag}</td>
      <td class="mono">${(inc.confidence * 100).toFixed(0)}%</td>
      <td>${severityBadge(inc.severity)}</td>
    `;
    tr.addEventListener("click", () => {
      openDetailPanel(inc);
      highlightIncidentRow(inc.id);
    });
    el.tableBody.appendChild(tr);
  }

  el.feedCount.textContent = `${rows.length} shown`;
}

function highlightIncidentRow(id) {
  selectedIncidentId = id;
  for (const tr of el.tableBody.querySelectorAll("tr")) {
    tr.classList.toggle("selected", tr.dataset.incidentId === id);
  }
}

function refreshAllVisuals() {
  renderThreatChart();
  renderSeverityChart();
  renderThreatCards();
  renderIncidentTable();
  renderTimeline();
}

// ---------- Evidence parsing & explanation ----------

// Evidence entries from the backend are free-text strings like
// "Unique destination ports: 100". Where an entry ends in a number we
// render it as a small bar so the "why" is visually explainable;
// anything else falls back to a plain bullet.
function parseEvidenceEntry(entry) {
  const match = String(entry).match(/^(.*?)[:\s]+([\d]+(?:\.[\d]+)?)\s*$/);
  if (!match) return null;
  return { label: match[1].trim(), value: parseFloat(match[2]) };
}

function renderEvidence(evidence) {
  if (!evidence || evidence.length === 0) {
    return `<p class="panel-empty">No evidence recorded for this incident.</p>`;
  }

  const parsed = evidence.map((e) => ({ raw: e, parsed: parseEvidenceEntry(e) }));
  const numeric = parsed.filter((p) => p.parsed);
  const maxVal = Math.max(1, ...numeric.map((p) => p.parsed.value));

  const bars = numeric
    .map(
      (p) => `
        <div class="evidence-bar-row">
          <div class="evidence-bar-label"><span>${p.parsed.label}</span><span class="val">${p.parsed.value}</span></div>
          <div class="evidence-bar-track"><div class="evidence-bar-fill" style="width:${(p.parsed.value / maxVal) * 100}%"></div></div>
        </div>`
    )
    .join("");

  const bullets = parsed
    .filter((p) => !p.parsed)
    .map((p) => `<li>${p.raw}</li>`)
    .join("");

  return `
    ${bars ? `<div class="evidence-bars">${bars}</div>` : ""}
    ${bullets ? `<ul class="evidence-list">${bullets}</ul>` : ""}
  `;
}

function explainIncident(inc) {
  const label = categoryOf(inc.threatClass).label;
  const bits = (inc.evidence || [])
    .map(parseEvidenceEntry)
    .filter(Boolean)
    .map((p) => `${p.label.toLowerCase()} of ${p.value}`);

  const factSummary = bits.length ? bits.slice(0, 3).join(", ") : "the traffic pattern observed for this flow";
  const groupNote = inc.count > 1 ? ` This incident groups ${inc.count} related events from the same source and destination.` : "";

  const sourceDesc = inc.srcIps.size > 1
    ? `${inc.srcIps.size} distinct sources`
    : `The source ${inc.srcIp}`;
  return `${sourceDesc} showed ${factSummary} toward ${inc.dstIp}, which is consistent with ${label.toLowerCase()} behavior.${groupNote}`;
}

// ---------- Detail panel ----------

function openDetailPanel(inc) {
  el.detailBody.innerHTML = `
    <div class="detail-flow">
      ${inc.srcIps.size > 1 ? `${inc.srcIps.size} sources` : `${inc.srcIp}:${inc.srcPort}`} &rarr; ${inc.dstIp}:${inc.dstPort}
      <div style="color: var(--ink-muted); margin-top:4px;">${inc.protocol || "—"} &middot; ${new Date(inc.lastTimestamp).toLocaleString()}</div>
    </div>

    <div class="detail-metric-row">
      <span class="label">Threat category</span>
      <span class="value">${categoryOf(inc.threatClass).label}</span>
    </div>
    <div class="detail-metric-row">
      <span class="label">Severity</span>
      <span class="value">${severityBadge(inc.severity)}</span>
    </div>
    <div class="detail-metric-row">
      <span class="label">Model confidence</span>
      <span class="value">${(inc.confidence * 100).toFixed(0)}%</span>
    </div>
    <div class="detail-metric-row">
      <span class="label">Events in this incident</span>
      <span class="value">${inc.count}</span>
    </div>

    <div class="detail-risk">
      <span class="value">${inc.riskScore ?? "—"}</span>
      <span class="label">Risk score / 100</span>
    </div>

    <h3 style="margin-top:8px;">Detection evidence</h3>
    ${renderEvidence(inc.evidence)}

    <div class="detail-explain">
      <strong>Why was this detected?</strong>
      ${explainIncident(inc)}
    </div>
  `;

  el.detailPanel.classList.add("open");
  el.detailScrim.classList.add("open");
}

function closeDetailPanel() {
  el.detailPanel.classList.remove("open");
  el.detailScrim.classList.remove("open");
}

el.detailClose.addEventListener("click", closeDetailPanel);
el.detailScrim.addEventListener("click", closeDetailPanel);

// ---------- Session scope ----------
//
// The dashboard shows ONLY the current session: what the live stream or
// the last batch upload produced. Nothing is loaded from alerts.db on
// page load and no cumulative /statistics totals are shown, so every run
// starts from a clean slate. The backend still persists alerts to
// alerts.db as its own record; the dashboard just doesn't display them.

let sessionAlerts = 0;
let sessionCritical = 0;

const runStatusEl = document.getElementById("run-status");

function setRunStatus(text) {
  runStatusEl.textContent = text;
}

function resetDashboard() {
  incidentsByKey = new Map();
  incidentsList = [];
  selectedIncidentId = null;
  activeCategoryFilter = null;
  el.clearFilterBtn.hidden = true;
  timeBuckets.clear();
  sessionAlerts = 0;
  sessionCritical = 0;
  lastSessionFlowsPerSec = null;

  timeChart.data.labels = [];
  timeChart.data.datasets[0].data = [];
  timeChart.update();
  el.trafficChartEmpty.style.display = "block";
  document.getElementById("time-chart").style.display = "none";

  for (const node of [
    el.statFlows, el.statAlerts, el.statCritical, el.statFlowsps, el.statLatency,
    el.perfFlows, el.perfThroughput, el.perfLatency, el.perfPackets,
  ]) {
    node.textContent = "—";
  }

  closeDetailPanel();
  refreshAllVisuals();
}

function beginSession() {
  resetDashboard();
  el.statAlerts.textContent = "0";
  el.statCritical.textContent = "0";
  setRunStatus("Processing traffic...");
}

function finishSession(totalFlows) {
  const incidents = incidentsList.length;
  if (sessionAlerts === 0) {
    setRunStatus(`Analysed ${totalFlows ?? "?"} flows — no threats detected.`);
  } else {
    setRunStatus(
      `Analysed ${totalFlows ?? "?"} flows — ${sessionAlerts} alert${sessionAlerts === 1 ? "" : "s"} ` +
      `grouped into ${incidents} incident${incidents === 1 ? "" : "s"}.`
    );
  }
}

// Backend reachability only (drives the System Status card). Uses /health,
// which carries no historical data.
async function checkBackend() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    setSystemStatus(res.ok ? "online" : "offline");
  } catch (err) {
    setSystemStatus("offline");
  }
}
setInterval(checkBackend, 10000);

document.getElementById("clear-btn").addEventListener("click", () => {
  if (isStreaming && ws) ws.close();
  resetDashboard();
  setRunStatus("No live traffic. Start a replay or upload a PCAP to begin analysis.");
});

// ---------- WebSocket: live streaming ----------

function startStream() {
  if (isStreaming) {
    if (ws) ws.close();
    return;
  }

  const pcapFile = el.pcapSelect.value;
  const speedFactor = Number(el.speedSelect.value);

  beginSession();

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    isStreaming = true;
    setConnStatus("live");
    el.startBtn.classList.add("is-streaming");
    el.startBtnLabel.textContent = "Stop live stream";
    el.streamSpeedLabel.hidden = false;
    el.streamSpeedLabel.textContent = `LIVE • ${speedFactor}× replay`;
    ws.send(JSON.stringify({ pcap_file: pcapFile, speed_factor: speedFactor }));
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === "alert") {
      const { isNew } = ingestAlert(data);
      recordTrafficPoint(data.timestamp);
      refreshAllVisuals();
      sessionAlerts += 1;
      el.statAlerts.textContent = String(sessionAlerts);
      if (data.severity === "CRITICAL") {
        sessionCritical += 1;
      }
      el.statCritical.textContent = String(sessionCritical);
      if (isNew) {
        const row = el.tableBody.querySelector(`tr[data-incident-id="${incidentKey(data)}|${new Date(data.timestamp).getTime()}"]`);
        if (row) {
          row.classList.add("row-enter");
          setTimeout(() => row.classList.remove("row-enter"), 500);
        }
      }
    }

    if (data.type === "summary") {
      el.statFlows.textContent = data.total_flows;
      el.perfFlows.textContent = typeof data.total_flows === "number" ? data.total_flows.toLocaleString() : data.total_flows;
      lastSessionFlowsPerSec = data.flows_per_second;
      el.statFlowsps.textContent = lastSessionFlowsPerSec ?? "—";
      el.perfThroughput.textContent = lastSessionFlowsPerSec != null ? `${lastSessionFlowsPerSec} flows/sec` : "—";

      // Real values from streaming.py's stream_detect() summary —
      // only shown once a live session has actually completed.
      const latencyMs = data.avg_detection_latency_ms;
      el.statLatency.textContent = latencyMs != null ? `${latencyMs} ms` : "—";
      el.perfLatency.textContent = latencyMs != null ? `${latencyMs} ms` : "—";
      el.perfPackets.textContent = data.total_packets != null ? data.total_packets.toLocaleString() : "—";
      finishSession(data.total_flows);
    }

    if (data.type === "error") {
      console.error("Stream error:", data.message);
      setConnStatus("error");
    }
  };

  ws.onclose = () => {
    isStreaming = false;
    setConnStatus("idle");
    el.startBtn.classList.remove("is-streaming");
    el.startBtnLabel.textContent = "Start live stream";
    el.streamSpeedLabel.hidden = true;
    if (runStatusEl.textContent === "Processing traffic...") {
      setRunStatus("Stream stopped before the replay finished.");
    }
  };

  ws.onerror = () => {
    setConnStatus("error");
  };
}

el.startBtn.addEventListener("click", startStream);

// ---------- REST: batch upload/analyze ----------

async function uploadAndAnalyze() {
  const file = el.fileInput.files[0];
  if (!file) {
    alert("Choose a PCAP file first.");
    return;
  }

  el.uploadBtn.disabled = true;
  el.uploadBtn.textContent = "Analyzing...";

  const formData = new FormData();
  formData.append("file", file);

  try {
    if (isStreaming && ws) ws.close();
    beginSession();

    const res = await fetch(`${API_BASE}/analyze`, { method: "POST", body: formData });
    const data = await res.json();

    for (const alert of data.alerts) {
      ingestAlert(alert);
      recordTrafficPoint(alert.timestamp);
      sessionAlerts += 1;
      if (alert.severity === "CRITICAL") sessionCritical += 1;
    }
    refreshAllVisuals();

    el.statAlerts.textContent = String(sessionAlerts);
    el.statCritical.textContent = String(sessionCritical);
    el.statFlows.textContent = data.total_flows != null ? data.total_flows.toLocaleString() : "—";
    el.perfFlows.textContent = el.statFlows.textContent;
    finishSession(data.total_flows);
    setSystemStatus("online");
  } catch (err) {
    console.error("Analyze failed", err);
    alert("Analyze request failed — check the backend is running on port 8000.");
  } finally {
    el.uploadBtn.disabled = false;
    el.uploadBtn.textContent = "Analyze (batch)";
  }
}

el.uploadBtn.addEventListener("click", uploadAndAnalyze);

// ---------- Initial load ----------

resetDashboard();
setRunStatus("No live traffic. Start a replay or upload a PCAP to begin analysis.");
checkBackend();
