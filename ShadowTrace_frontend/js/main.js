// ----------------------------------------------------------------------
// ShadowTrace Frontend → Backend API Base URL
// ----------------------------------------------------------------------
const API_BASE = "http://127.0.0.1:8000";


// ======================================================================
// 1) START SPIDERFOOT SCAN (Triggered from scan.html)
// ======================================================================
document.addEventListener("DOMContentLoaded", () => {
    const startForm = document.getElementById("scanForm");

    if (startForm) {
        startForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const data = {
                case_id: document.getElementById("caseId").value,
                scan_name: document.getElementById("scanName").value,
                target: document.getElementById("target").value
            };

            try {
                const res = await fetch(`${API_BASE}/osint/start`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(data)
                });

                const json = await res.json();
                document.getElementById("response").innerText =
                    JSON.stringify(json, null, 2);

            } catch (err) {
                document.getElementById("response").innerText =
                    "Error: " + err.message;
            }
        });
    }
});


// ======================================================================
// 2) FETCH SCAN STATUS (Triggered from results.html)
// ======================================================================
async function checkStatus() {
    const scanId = document.getElementById("scanIdInput").value;

    if (!scanId) {
        alert("Enter Scan ID");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/osint/status/${scanId}`);
        const text = await res.text();

        document.getElementById("statusBox").innerText = text;
    } catch (err) {
        document.getElementById("statusBox").innerText =
            "Error: " + err.message;
    }
}


// ======================================================================
// 3) FETCH RAW SPIDERFOOT RESULTS
// ======================================================================
async function fetchResults() {
    const scanId = document.getElementById("scanIdInput").value;

    if (!scanId) {
        alert("Enter Scan ID");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/osint/results/${scanId}`);
        const text = await res.text();

        document.getElementById("resultsBox").innerText = text;
    } catch (err) {
        document.getElementById("resultsBox").innerText =
            "Error: " + err.message;
    }
}


// ======================================================================
// 4) STORE SPIDERFOOT RESULTS INTO MONGODB
// ======================================================================
async function storeResults() {
    const scanId = document.getElementById("scanIdInput").value;
    const caseId = document.getElementById("caseStoreInput").value;

    if (!scanId || !caseId) {
        alert("Enter both Case ID and Scan ID");
        return;
    }

    const data = {
        scan_id: scanId,
        case_id: caseId,
        target: "" // optional
    };

    try {
        const res = await fetch(`${API_BASE}/osint/store`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const json = await res.json();
        document.getElementById("storeBox").innerText =
            JSON.stringify(json, null, 2);

    } catch (err) {
        document.getElementById("storeBox").innerText =
            "Error: " + err.message;
    }
}


// ======================================================================
// 5) EXPORT FUNCTIONS FOR HTML BUTTONS
// ======================================================================
window.fetchResults = fetchResults;
window.checkStatus = checkStatus;
window.storeResults = storeResults;

// ======================================================================
// 6) Load All Cases
// ======================================================================
async function loadCases() {
    try {
        const res = await fetch(`${API_BASE}/osint/cases`);
        const data = await res.json();

        const tbody = document.getElementById("caseTableBody");
        tbody.innerHTML = ""; // clear old rows

        data.cases.forEach(c => {
            const row = `
                <tr>
                    <td>${c.case_id}</td>
                    <td>${c.scan_id}</td>
                    <td>${c.entity_count}</td>
                    <td><button onclick="viewCase('${c.case_id}')">View</button></td>
                </tr>
            `;
            tbody.innerHTML += row;
        });

    } catch (err) {
        alert("Failed to load cases: " + err.message);
    }
}


// ======================================================================
// 7) Load Case Details
// ======================================================================
async function viewCase(caseId) {
    try {
        const res = await fetch(`${API_BASE}/osint/cases/${caseId}`);
        const data = await res.json();

        document.getElementById("caseDetails").innerText =
            JSON.stringify(data, null, 2);

    } catch (err) {
        alert("Error loading case: " + err.message);
    }
}


// Export functions
window.loadCases = loadCases;
window.viewCase = viewCase;

// ======================================================================
// 8) Load Entities from Case
// ======================================================================
async function loadEntities() {
    const caseId = document.getElementById("entityCaseId").value;

    if (!caseId) {
        alert("Enter a Case ID");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/osint/entities/${caseId}`);
        const data = await res.json();

        const div = document.getElementById("entityOutput");
        div.innerHTML = "";

        for (const [type, items] of Object.entries(data)) {
            div.innerHTML += `
                <h3>${type.toUpperCase()}</h3>
                <ul>
                    ${items.map(item => `<li>${item}</li>`).join("")}
                </ul>
                <hr>
            `;
        }

    } catch (err) {
        document.getElementById("entityOutput").innerText =
            "Error: " + err.message;
    }
}

window.loadEntities = loadEntities;
