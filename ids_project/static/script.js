function getSeverity(alert) {
    if (alert.confidence === "HIGH") return "high";
    if (alert.type.includes("Privilege") || alert.type.includes("Malware")) return "medium";
    return "low";
}

function loadAlerts() {
    fetch("/api/alerts")
        .then(res => res.json())
        .then(data => {
            const alertsDiv = document.getElementById("alerts");
            const filter = document.getElementById("typeFilter").value;
            alertsDiv.innerHTML = "";

            let high = 0, medium = 0;

            data.reverse().forEach(alert => {
                if (filter !== "ALL" && alert.type !== filter) return;

                const severity = getSeverity(alert);
                if (severity === "high") high++;
                if (severity === "medium") medium++;

                const div = document.createElement("div");
                div.className = `alert ${severity}`;

                div.innerHTML = `
                    <div class="alert-header">
                        <h3>${alert.type}</h3>
                        <time>${alert.timestamp || ""}</time>
                    </div>
                    <div class="alert-details">${JSON.stringify(alert, null, 2)}</div>
                `;

                div.querySelector(".alert-header").onclick = () => {
                    const details = div.querySelector(".alert-details");
                    details.style.display = details.style.display === "block" ? "none" : "block";
                };

                alertsDiv.appendChild(div);
            });

            document.getElementById("totalAlerts").innerText = data.length;
            document.getElementById("highAlerts").innerText = high;
            document.getElementById("mediumAlerts").innerText = medium;
            document.getElementById("lastUpdated").innerText =
                "Last update: " + new Date().toLocaleTimeString();
        });
}

loadAlerts();
setInterval(loadAlerts, 5000);

