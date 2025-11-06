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

// =============== Render Master ===============
function renderDashboard(res) {
  document.querySelectorAll(".summary").forEach(e => e.classList.remove("hidden"));
  renderSummary(res);
  renderIP(res);
  renderDomain(res);
  renderEmail(res);
  renderUsername(res);
}

// =============== Summary Section ===============
function renderSummary(res) {
  const badge = document.getElementById("threat-badge");
  const score = res.threat_score || {};
  const level = (score.risk_level || "low").toLowerCase();

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

// =============== IP Intelligence ===============
function renderIP(res) {
  if (!res.ip_rir?.ok) return;
  const data = res.ip_rir.rir || {};
  const org = data.network?.name || "N/A";
  const range = data.network?.cidr || "N/A";

  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `
    <h2>IP Intelligence</h2>
    <p><b>Network:</b> ${range}</p>
    <p><b>Organization:</b> ${org}</p>`;
  document.querySelector(".container").appendChild(div);
}

// =============== Domain Intelligence ===============
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
      <p><b>Emails:</b> ${Array.isArray(w.emails) ? w.emails.join(", ") : w.emails || "N/A"}</p>`;
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

// =============== Email Intelligence ===============
function renderEmail(res) {
  if (!res.gravatar && !res.hibp) return;

  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `<h2>Email Intelligence</h2>`;

  if (res.gravatar) {
    const g = res.gravatar;
    div.innerHTML += `
      <p><b>Gravatar:</b> ${g.exists ? " Exists" : " Not Found"} - 
      <a href="${g.url}" target="_blank">View</a></p>`;
  }

  if (res.hibp?.ok && res.hibp.data?.length) {
    const breaches = res.hibp.data.map(b => `
      <div class="card">
        <b>${b.Name || b.Title}</b><br>
        Domain: ${b.Domain}<br>
        Date: ${b.BreachDate}<br>
        Data: ${b.DataClasses?.join(", ")}
      </div>`).join("");
    div.innerHTML += `<h3>Breaches Found:</h3><div class="cards">${breaches}</div>`;
  } else {
    div.innerHTML += `<p><b>HIBP:</b> No breaches found or invalid key.</p>`;
  }

  document.querySelector(".container").appendChild(div);
}

// =============== Username OSINT (Enhanced) ===============
function renderUsername(res) {
  const social = res.social_profile || res.social;
  if (!social) return;

  const div = document.createElement("div");
  div.className = "summary";
  div.innerHTML = `<h2>Username Intelligence</h2>`;

  div.innerHTML += `<p><b>Overall Confidence:</b> ${social.confidence || 0}%</p>`;
  div.innerHTML += `
    <div class="confidence-bar">
      <div class="confidence-fill" style="width:${social.confidence || 0}%"></div>
    </div>`;

  // Avatar Analysis Section
  if (social.avatar_summary?.length) {
    div.innerHTML += `<h3>Avatar Analysis</h3><div class="cards">`;
    social.avatar_summary.forEach(a => {
      const faceFlag = a.likely_face
        ? `<span style="color:#00ff88;font-weight:bold;"> Likely Human Face</span> (${a.face_count})`
        : `<span style="color:#888;"> No Face Detected</span>`;
      div.innerHTML += `
        <div class="avatar-card">
          <b>${a.platform}</b><br>
          <code>${a.hash}</code><br>
          <small>${a.description}</small><br>
          ${faceFlag}
        </div>`;
    });
    div.innerHTML += `</div>`;
  }

  // Platform Cards
  div.innerHTML += `<h3>Platform Correlation</h3><div class="cards">`;

  for (const [platform, info] of Object.entries(social.platforms || {})) {
    const found = info.exists ? " Found" : " Not Found";
    const match = info.match_score ? `${info.match_score}% Match` : "N/A";
    const tags = (info.match_evidence || []).map(t => `<span class="evidence-tag">${t}</span>`).join(" ");
    const faceNote = info.likely_face
      ? `<p style="color:#00ff88;">Face detected (${info.face_count || 1})</p>`
      : info.face_count === 0
        ? `<p style="color:#aaa;">No face detected</p>` : "";

    div.innerHTML += `
      <div class="card">
        <div class="card-title">${platform.toUpperCase()}</div>
        <p>${found} — <a href="${info.url}" target="_blank">${info.url}</a></p>
        <div class="confidence-bar"><div class="confidence-fill" style="width:${info.match_score || 0}%"></div></div>
        <p><b>Confidence:</b> ${match}</p>
        ${faceNote}
        ${tags ? `<div class="evidence-tags">${tags}</div>` : ""}
      </div>`;
  }

  div.innerHTML += `</div>`;
  document.querySelector(".container").appendChild(div);
}

// =============== Start Button ===============
startBtn.addEventListener("click", async () => {
  const query = document.getElementById("query").value.trim();
  const source = document.getElementById("source").value;
  if (!query) return alert("Enter a query");

  document.querySelectorAll(".summary").forEach(e => e.classList.add("hidden"));
  loading.classList.remove("hidden");
  show("Submitting scan request...");

  const res = await fetch(`${API_BASE}/search/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, source })
  });

  const data = await res.json();
  show("Scan queued:\n" + JSON.stringify(data, null, 2));
  pollStatus(data.id);
});
