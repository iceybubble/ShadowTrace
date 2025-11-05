const API_URL = "http://127.0.0.1:8000";

async function startScan() {
    const val = document.getElementById("inputValue").value;
    if (!val) {
        alert("Enter a value first");
        return;
    }

    document.getElementById("status").innerText = "🚀 Starting scan...";

    const res = await fetch(`${API_URL}/scan/`, {
        method: "POST",
        headers: { "Content-Type": "application/json"},
        body: JSON.stringify({ input_value: val })
    });

    const data = await res.json();
    const qid = data.query_id;

    document.getElementById("status").innerText =
        `📡 Scan started. Tracking ID: ${qid}`;

    pollScan(qid);
}

async function pollScan(qid) {
    const interval = setInterval(async () => {
        const res = await fetch(`${API_URL}/scan/${qid}`);
        const data = await res.json();

        if (!data.status || data.status !== "scanning") {
            clearInterval(interval);
            showResult(data);
        }
    }, 1000);
}

function showResult(data) {
    document.getElementById("status").innerText = "✅ Scan complete";

    let html = `
        <div class="card p-3">
            <h5 class="fw-bold">Threat Actor Profile</h5>
            <p><b>Indicator:</b> ${data.indicator}</p>
            <p><b>Type:</b> ${data.type}</p>
            <p><b>Confidence:</b> 
                <span class="badge bg-${data.confidence > 70 ? 'danger' : data.confidence > 40 ? 'warning' : 'secondary'} badge-score">
                ${data.confidence}%
                </span>
            </p>
            <hr>
            <h6>Evidence Sources</h6>
    `;

    (data.sources || []).forEach(src => {
        html += `
            <div class="source-box">
                <b>${src.type || "Source"}:</b> ${src.title || "No title"}
                <br>
                <a href="${src.url || "#"}" target="_blank" class="text-info">view</a>
            </div>`;
    });

    html += `</div>`;

    document.getElementById("result").innerHTML = html;
}
