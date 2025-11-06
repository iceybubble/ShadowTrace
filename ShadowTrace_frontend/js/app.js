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

  const interval = 2500;

  while (true) {
    const res = await fetch(`${API_BASE}/search/status/${id}`);
    const data = await res.json();

    // Live JSON dump
    show(JSON.stringify(data, null, 2));

    if (data.status === "done" && data.results) {
      renderDashboard(data.results);
      loading.classList.add("hidden");
      break;
    }

    if (data.status === "failed") {
      show("❌ Scan failed:\n" + data.error);
      loading.classList.add("hidden");
      break;
    }

    await new Promise(r => setTimeout(r, interval));
  }
}

// Main rendering function
function renderDashboard(res) {
  renderSummary(res);
  renderIP(res);
  renderEmail(res);
  renderUsername(res);
  renderDomain(res);
}

// Summary cards
function renderSummary(res) {
  const summary = document.getElementById("summary-section");
  summary.classList.remove("hidden");

  const badge = document.getElementById("threat-badge");
  const score = res.threat_score || {};
  const level = score.risk_level || "unknown";

  badge.textContent = level.toUpperCase();
  badge.className = `badge ${level}`;

  const vtStats = res.vt?.data?.data?.attributes?.last_analysis_stats || {};
  document.getElementById("vt-card").textContent =
    `VirusTotal\nMalicious: ${vtStats.malicious || 0}`;

  const abuse = res.abuseipdb?.data || {};
  document.getElementById("abuse-card").textContent =
    `AbuseIPDB\nConfidence: ${abuse.abuseConfidenceScore || 0}`;

  const shodan = res.shodan?.host || {};
  document.getElementById("shodan-card").textContent =
    `Shodan\nOpen Ports: ${shodan.ports ? shodan.ports.join(", ") : "None"}`;
}

// IP Intelligence view
function renderIP(res) {
  if (!res.ip_rir || !res.ip_rir.ok) return;

  const data = res.ip_rir.rir || {};
  const addr = data.network?.cidr || "N/A";
  const org = data.network?.name || "N/A";
  const country = data.objects?.[Object.keys(data.objects)[0]]?.country || "Unknown";
  const descr = data.objects?.[Object.keys(data.objects)[0]]?.description || "No info";

  const geo = extractGeo(res);

  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `
    <h2>IP Intelligence</h2>
    <p><b>IP Range:</b> ${addr}</p>
    <p><b>Org:</b> ${org}</p>
    <p><b>Country:</b> ${country}</p>
    <p><b>Description:</b> ${descr}</p>
    ${geo ? `<iframe
      width="100%"
      height="250"
      style="border:0; margin-top:10px;"
      loading="lazy"
      allowfullscreen
      referrerpolicy="no-referrer-when-downgrade"
      src="https://www.google.com/maps?q=${geo.lat},${geo.lon}&output=embed">
    </iframe>` : ""}
  `;
  document.querySelector(".container").appendChild(div);
}

function extractGeo(res) {
  try {
    const attrs = res.vt?.data?.data?.attributes || {};
    const lat = attrs?.country?.location?.lat;
    const lon = attrs?.country?.location?.lon;
    if (lat && lon) return { lat, lon };
  } catch {}
  return null;
}

// Email OSINT (gravatar + HIBP)
function renderEmail(res) {
  if (!res.gravatar && !res.hibp) return;
  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `<h2>Email Intelligence</h2>`;

  // Gravatar
  if (res.gravatar?.exists) {
    div.innerHTML += `
      <p><b>Gravatar:</b></p>
      <img src="${res.gravatar.url}" alt="Gravatar" style="width:80px; border-radius:50%; margin:8px 0;">
    `;
  }

  // HIBP results
  if (res.hibp?.ok && res.hibp.data?.length) {
    const breaches = res.hibp.data.map(b => `
      <div class="card">
        <div class="card-title">${b.Title || b.Name}</div>
        <p><b>Domain:</b> ${b.Domain}</p>
        <p><b>Date:</b> ${b.BreachDate}</p>
        <p><b>Data:</b> ${b.DataClasses?.join(", ")}</p>
      </div>
    `).join("");
    div.innerHTML += `<h3>Breaches Found:</h3><div class="cards">${breaches}</div>`;
  } else if (res.hibp?.message) {
    div.innerHTML += `<p>No breaches found (safe)</p>`;
  }

  document.querySelector(".container").appendChild(div);
}

// Username OSINT (social probe)
function renderUsername(res) {
  if (!res.social) return;
  const socials = res.social;
  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `<h2>Username Intelligence</h2>`;

  Object.entries(socials).forEach(([platform, data]) => {
    const exists = data.exists ? "✅ Found" : "❌ Not Found";
    div.innerHTML += `<p><b>${platform}:</b> ${exists} - <a href="${data.url}" target="_blank">${data.url}</a></p>`;
  });

  document.querySelector(".container").appendChild(div);
}

// Domain Intelligence
function renderDomain(res) {
  if (!res.whois && !res.crtsh) return;
  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `<h2>Domain Intelligence</h2>`;

  if (res.whois?.ok) {
    const w = res.whois.data;
    div.innerHTML += `
      <p><b>Registrar:</b> ${w.registrar || "N/A"}</p>
      <p><b>Created:</b> ${w.creation_date || "N/A"}</p>
      <p><b>Expires:</b> ${w.expiration_date || "N/A"}</p>
      <p><b>Emails:</b> ${Array.isArray(w.emails) ? w.emails.join(", ") : w.emails || "N/A"}</p>
    `;
  }

  if (res.crtsh && res.crtsh !== "N/A") {
    div.innerHTML += `<h3>Certificates:</h3><ul>`;
    res.crtsh.forEach(c => {
      div.innerHTML += `<li>${c.name_value} (${c.issuer_name})</li>`;
    });
    div.innerHTML += `</ul>`;
  }

  document.querySelector(".container").appendChild(div);
}

startBtn.addEventListener("click", async () => {
  const query = document.getElementById("query").value;
  const source = document.getElementById("source").value;
  if (!query) return alert("Enter a query");

  // Reset dynamic sections
  document.querySelectorAll(".summary").forEach(e => e.classList.add("hidden"));
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
