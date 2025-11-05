const API_BASE = "http://127.0.0.1:8000";

const statusBox = document.getElementById("status-box");
const startBtn = document.getElementById("start");
const loading = document.getElementById("loading");

function show(msg) {
  statusBox.textContent = msg;
}

async function pollStatus(id) {
  loading.classList.remove("hidden");
  show("Running scan...");

  const interval = 2000;

  while (true) {
    const res = await fetch(`${API_BASE}/search/status/${id}`);
    const data = await res.json();

    // Live raw output
    show(JSON.stringify(data, null, 2));

    // Summary UI render
    if (data.status === "done" && data.results) {
      renderSummary(data.results);
      loading.classList.add("hidden");
      break;
    }

    if (data.status === "failed") {
      loading.classList.add("hidden");
      break;
    }

    await new Promise(r => setTimeout(r, interval));
  }
}

function renderSummary(res) {
  const summary = document.getElementById("summary-section");
  summary.classList.remove("hidden");

  const badge = document.getElementById("threat-badge");

  const score = res.threat_score || {};
  const level = score.risk_level || "unknown";

  badge.textContent = level.toUpperCase();
  badge.className = `badge ${level}`;

  // VirusTotal
  const vtStats = res.vt?.data?.data?.attributes?.last_analysis_stats || {};
  document.getElementById("vt-card").textContent =
    `VirusTotal\nMalicious: ${vtStats.malicious || 0}`;

  // AbuseIPDB
  const abuse = res.abuseipdb?.data || {};
  document.getElementById("abuse-card").textContent =
    `AbuseIPDB\nConfidence: ${abuse.abuseConfidenceScore || 0}`;

  // Shodan
  const shodan = res.shodan?.host || {};
  document.getElementById("shodan-card").textContent =
    `Shodan\nOpen Ports: ${shodan.ports ? shodan.ports.join(", ") : "None"}`;
}

startBtn.addEventListener("click", async () => {
  const query = document.getElementById("query").value;
  const source = document.getElementById("source").value;

  if (!query) return alert("Enter a query");

  loading.classList.remove("hidden");
  show("Submitting scan request...");

  const res = await fetch(`${API_BASE}/search/start`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ query, source })
  });

  const data = await res.json();
  show("Scan queued:\n" + JSON.stringify(data, null, 2));

  pollStatus(data.id);
});
