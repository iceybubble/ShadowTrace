const API_BASE = "http://127.0.0.1:8000"; 

const statusBox = document.getElementById("status-box");
const startBtn = document.getElementById("start");

function show(msg) {
  statusBox.textContent = msg;
}

async function pollStatus(id) {
  show("Scan started...");

  const interval = 2000;

  while (true) {
    const res = await fetch(`${API_BASE}/search/status/${id}`);
    const data = await res.json();
    show(JSON.stringify(data, null, 2));

    if (data.status === "done" || data.status === "failed") break;

    await new Promise(r => setTimeout(r, interval));
  }
}

startBtn.addEventListener("click", async () => {
  const query = document.getElementById("query").value;
  const source = document.getElementById("source").value;

  if (!query) return alert("Enter a query!");

  show("Submitting scan request...");

  const res = await fetch(`${API_BASE}/search/start`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({query, source})
  });

  const data = await res.json();
  show("Scan queued:\n" + JSON.stringify(data, null, 2));

  pollStatus(data.id);
});
