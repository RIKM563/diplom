let lastTrainResult = null;
let lastAssessResult = null;
let lastOptimizeResult = null;
let lastLatestResult = null;

const trainSample = {
    events: [
        {
            event_id: "e1",
            node_id: "n1",
            asset_id: "a1",
            threat_type: "phishing",
            source: "mail_gateway",
            timestamp: "2026-04-01T10:15:00",
            severity: 0.8,
            frequency: 15,
            anomaly_score: 0.7,
            has_vulnerability: true,
            privilege_level: 4,
            has_controls: false,
            metadata: {
                failed_logins: 3,
                external_ip: true
            }
        },
        {
            event_id: "e2",
            node_id: "n2",
            asset_id: "a1",
            threat_type: "malware",
            source: "edr",
            timestamp: "2026-04-01T12:30:00",
            severity: 0.7,
            frequency: 20,
            anomaly_score: 0.9,
            has_vulnerability: true,
            privilege_level: 5,
            has_controls: false,
            metadata: {
                suspicious_processes: 4
            }
        },
        {
            event_id: "e3",
            node_id: "n3",
            asset_id: "a2",
            threat_type: "data_leak",
            source: "dlp",
            timestamp: "2026-04-01T14:20:00",
            severity: 0.95,
            frequency: 8,
            anomaly_score: 0.85,
            has_vulnerability: false,
            privilege_level: 8,
            has_controls: false,
            metadata: {
                large_transfer_mb: 950
            }
        },
        {
            event_id: "e4",
            node_id: "n4",
            asset_id: "a3",
            threat_type: "ddos",
            source: "ids",
            timestamp: "2026-04-01T16:10:00",
            severity: 0.6,
            frequency: 30,
            anomaly_score: 0.6,
            has_vulnerability: false,
            privilege_level: 1,
            has_controls: true,
            metadata: {
                requests_per_sec: 12000
            }
        }
    ],
    nodes: [
        {
            node_id: "n1",
            asset_id: "a1",
            node_type: "gateway",
            segment: "dmz",
            business_service: "remote_access",
            criticality: 0.9,
            exposure: 0.9,
            trust_level: 0.4,
            metadata: {
                internet_facing: true
            }
        },
        {
            node_id: "n2",
            asset_id: "a1",
            node_type: "server",
            segment: "internal",
            business_service: "auth_service",
            criticality: 0.8,
            exposure: 0.6,
            trust_level: 0.6,
            metadata: {
                domain_joined: true
            }
        },
        {
            node_id: "n3",
            asset_id: "a2",
            node_type: "database",
            segment: "data",
            business_service: "customer_db",
            criticality: 1.0,
            exposure: 0.5,
            trust_level: 0.8,
            metadata: {
                contains_personal_data: true
            }
        },
        {
            node_id: "n4",
            asset_id: "a3",
            node_type: "application",
            segment: "web",
            business_service: "online_banking",
            criticality: 0.85,
            exposure: 0.8,
            trust_level: 0.5,
            metadata: {
                customer_facing: true
            }
        }
    ],
    assets: [
        {
            asset_id: "a1",
            name: "Access Control Platform",
            owner: "IT Security",
            business_process: "authentication",
            criticality: 0.9,
            cost: 5000000,
            metadata: {
                tier: 1
            }
        },
        {
            asset_id: "a2",
            name: "Customer Database",
            owner: "Data Office",
            business_process: "customer_service",
            criticality: 1.0,
            cost: 12000000,
            metadata: {
                tier: 1
            }
        },
        {
            asset_id: "a3",
            name: "Online Banking Frontend",
            owner: "Digital Banking",
            business_process: "online_banking",
            criticality: 0.85,
            cost: 8000000,
            metadata: {
                tier: 1
            }
        }
    ],
    labels: {
        e1: 1,
        e2: 1,
        e3: 1,
        e4: 0
    },
    model_type: "random_forest",
    model_params: {},
    use_calibration: true
};

const assessSample = {
    events: [
        {
            event_id: "e10",
            node_id: "n1",
            asset_id: "a1",
            threat_type: "phishing",
            source: "mail_gateway",
            timestamp: "2026-04-02T09:10:00",
            severity: 0.85,
            frequency: 18,
            anomaly_score: 0.75,
            has_vulnerability: true,
            privilege_level: 5,
            has_controls: false,
            metadata: {
                failed_logins: 5,
                external_ip: true
            }
        },
        {
            event_id: "e11",
            node_id: "n3",
            asset_id: "a2",
            threat_type: "data_leak",
            source: "dlp",
            timestamp: "2026-04-02T11:45:00",
            severity: 0.92,
            frequency: 9,
            anomaly_score: 0.88,
            has_vulnerability: false,
            privilege_level: 9,
            has_controls: false,
            metadata: {
                large_transfer_mb: 1100
            }
        }
    ],
    nodes: trainSample.nodes,
    assets: trainSample.assets,
    edges: [
        {
            source_node_id: "n1",
            target_node_id: "n2",
            weight: 0.7,
            relation_type: "network",
            bidirectional: false
        },
        {
            source_node_id: "n2",
            target_node_id: "n3",
            weight: 0.6,
            relation_type: "service",
            bidirectional: false
        }
    ]
};

const optimizeSample = {
    current_risks: [
        {
            event_id: "e10",
            node_id: "n1",
            asset_id: "a1",
            threat_type: "phishing",
            probability: 0.83,
            impact: 0.79,
            criticality: 0.9,
            base_risk: 0.59,
            propagated_risk: 0.62,
            final_risk: 0.61,
            risk_class: "high"
        },
        {
            event_id: "e11",
            node_id: "n3",
            asset_id: "a2",
            threat_type: "data_leak",
            probability: 0.90,
            impact: 0.93,
            criticality: 1.00,
            base_risk: 0.84,
            propagated_risk: 0.86,
            final_risk: 0.85,
            risk_class: "critical"
        }
    ],
    measures: [
        {
            measure_id: "m1",
            name: "Advanced Email Filtering",
            measure_type: "software",
            cost: 300000,
            labor: 40,
            implementation_time: 10,
            effectiveness: {
                phishing: 0.5,
                malware: 0.2
            },
            applicable_node_types: ["gateway", "server"],
            incompatible_with: [],
            requires: [],
            metadata: {}
        },
        {
            measure_id: "m2",
            name: "Database Activity Monitoring",
            measure_type: "software",
            cost: 500000,
            labor: 60,
            implementation_time: 20,
            effectiveness: {
                data_leak: 0.45,
                insider: 0.3
            },
            applicable_node_types: ["database"],
            incompatible_with: [],
            requires: [],
            metadata: {}
        }
    ],
    constraints: {
        max_budget: 700000,
        max_labor: 100,
        max_time: 30,
        max_measures: 2
    },
    nodes: trainSample.nodes
};

function pretty(obj) {
    return JSON.stringify(obj, null, 2);
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = typeof value === "string" ? value : pretty(value);
    }
}

function getTextareaValue(id) {
    return document.getElementById(id).value.trim();
}

function saveLocal(key, value) {
    localStorage.setItem(key, value);
}

function loadLocal(key) {
    return localStorage.getItem(key) || "";
}

function clearLocal(key) {
    localStorage.removeItem(key);
}

function parseJsonFromTextarea(id, label) {
    const raw = getTextareaValue(id);
    if (!raw) {
        throw new Error(`Поле ${label} пустое.`);
    }
    return JSON.parse(raw);
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(pretty(data));
    }

    return data;
}

async function getJson(url) {
    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(pretty(data));
    }

    return data;
}

function formatJsonTextarea(id) {
    const raw = getTextareaValue(id);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    document.getElementById(id).value = pretty(parsed);
}

function validateJsonTextarea(id, resultId) {
    try {
        const raw = getTextareaValue(id);
        if (!raw) {
            setText(resultId, "Поле пустое.");
            return;
        }
        JSON.parse(raw);
        setText(resultId, "JSON корректен.");
    } catch (error) {
        setText(resultId, `Ошибка JSON: ${error.message}`);
    }
}

function readJsonFileIntoTextarea(fileInputId, textareaId) {
    const input = document.getElementById(fileInputId);
    const file = input.files[0];
    if (!file) {
        alert("Выбери JSON-файл.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function (event) {
        const content = event.target.result;
        document.getElementById(textareaId).value = content;
    };
    reader.readAsText(file, "utf-8");
}

function setupDropzone(dropzoneId, textareaId) {
    const dropzone = document.getElementById(dropzoneId);
    if (!dropzone) return;

    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            event.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", (event) => {
        const file = event.dataTransfer.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function (e) {
            document.getElementById(textareaId).value = e.target.result;
        };
        reader.readAsText(file, "utf-8");
    });
}

function renderSummary(containerId, items) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!items || items.length === 0) {
        container.innerHTML = "";
        return;
    }

    container.innerHTML = items.map(item => `
        <div class="summary-card">
            <span class="label">${item.label}</span>
            <span class="value">${item.value}</span>
        </div>
    `).join("");
}

function riskBadge(value) {
    const cls = String(value || "").toLowerCase();
    return `<span class="risk-badge risk-${cls}">${cls || "n/a"}</span>`;
}

function buildTable(columns, rows) {
    if (!rows || rows.length === 0) {
        return "<div class='result-box'>Нет данных для отображения.</div>";
    }

    const thead = columns.map(col => `<th>${col.label}</th>`).join("");
    const tbody = rows.map(row => {
        return `<tr>${columns.map(col => {
            let value = row[col.key];

            if (col.key === "risk_class") {
                return `<td>${riskBadge(value)}</td>`;
            }

            if (typeof value === "number") {
                value = Number.isInteger(value) ? value : value.toFixed(4);
            }

            if (Array.isArray(value)) {
                value = value.join(", ");
            }

            if (value === undefined || value === null) {
                value = "";
            }

            return `<td>${value}</td>`;
        }).join("")}</tr>`;
    }).join("");

    return `
        <table class="result-table">
            <thead><tr>${thead}</tr></thead>
            <tbody>${tbody}</tbody>
        </table>
    `;
}

function renderAssessViews(data) {
    const events = data.event_risks || [];
    const nodes = data.node_risks || [];
    const assets = data.asset_risks || [];

    renderSummary("assessSummary", [
        { label: "Событий", value: events.length },
        { label: "Узлов", value: nodes.length },
        { label: "Активов", value: assets.length },
        {
            label: "Макс. риск актива",
            value: assets.length ? Math.max(...assets.map(x => x.final_risk || 0)).toFixed(4) : "0.0000"
        }
    ]);

    document.getElementById("eventsTableContainer").innerHTML = buildTable(
        [
            { key: "event_id", label: "Event ID" },
            { key: "node_id", label: "Node ID" },
            { key: "asset_id", label: "Asset ID" },
            { key: "threat_type", label: "Threat" },
            { key: "probability", label: "Probability" },
            { key: "base_risk", label: "Base Risk" },
            { key: "final_risk", label: "Final Risk" },
            { key: "risk_class", label: "Risk Class" }
        ],
        events
    );

    document.getElementById("nodesTableContainer").innerHTML = buildTable(
        [
            { key: "node_id", label: "Node ID" },
            { key: "asset_id", label: "Asset ID" },
            { key: "final_risk", label: "Final Risk" },
            { key: "risk_class", label: "Risk Class" }
        ],
        nodes
    );

    document.getElementById("assetsTableContainer").innerHTML = buildTable(
        [
            { key: "asset_id", label: "Asset ID" },
            { key: "final_risk", label: "Final Risk" },
            { key: "risk_class", label: "Risk Class" }
        ],
        assets
    );

    renderAssessExplanations(nodes);
}

function renderAssessExplanations(nodes) {
    const container = document.getElementById("assessExplanationsContainer");
    if (!container) return;

    if (!nodes || nodes.length === 0) {
        container.innerHTML = "<div class='result-box'>Объяснения пока отсутствуют.</div>";
        return;
    }

    container.innerHTML = nodes.map(node => {
        const explanations = node.explanations || [];
        const drivers = explanations.length
            ? explanations.map(item => {
                const contribution = typeof item.contribution === "number"
                    ? item.contribution.toFixed(4)
                    : item.contribution;
                return `<span class="driver-chip">${item.feature_name}: ${contribution}</span>`;
            }).join("")
            : "<span class='driver-chip'>Подробные драйверы не переданы backend</span>";

        return `
            <div class="explanation-card">
                <h4>Узел ${node.node_id}</h4>
                <p>
                    Для узла <strong>${node.node_id}</strong> в составе актива <strong>${node.asset_id}</strong>
                    рассчитан итоговый риск <strong>${Number(node.final_risk || 0).toFixed(4)}</strong>
                    с классом ${riskBadge(node.risk_class)}.
                </p>
                <p>
                    Интерпретация результата основана на наиболее значимых признаках, повлиявших на оценку модели.
                    Эти признаки помогают понять, почему узел был отнесен к данному классу риска.
                </p>
                <div class="explanation-drivers">${drivers}</div>
            </div>
        `;
    }).join("");
}

function renderOptimizeViews(data) {
    const selected = data.selected_measures || [];

    renderSummary("optimizeSummary", [
        { label: "Выбрано мер", value: selected.length },
        { label: "Стоимость", value: (data.total_cost || 0).toFixed(2) },
        { label: "Снижение риска", value: (data.expected_total_risk_reduction || 0).toFixed(4) },
        { label: "Остаточный риск", value: (data.expected_total_residual_risk || 0).toFixed(4) }
    ]);

    document.getElementById("optimizeTableContainer").innerHTML = buildTable(
        [
            { key: "measure_id", label: "ID" },
            { key: "name", label: "Название" },
            { key: "cost", label: "Стоимость" },
            { key: "labor", label: "Трудозатраты" },
            { key: "implementation_time", label: "Время" },
            { key: "expected_risk_reduction", label: "Risk Reduction" },
            { key: "expected_weighted_risk_reduction", label: "Weighted Reduction" },
            { key: "covered_node_ids", label: "Покрытие узлов" }
        ],
        selected
    );

    const explanationContainer = document.getElementById("optimizeExplanationContainer");
    if (explanationContainer) {
        const names = selected.map(item => item.name).join(", ") || "меры не выбраны";
        explanationContainer.innerHTML = `
            <h4>Пояснение по результату оптимизации</h4>
            <p>
                Система выбрала набор мер защиты: <strong>${names}</strong>.
                Решение сформировано с учетом ограничений по бюджету, трудозатратам, времени и числу мер,
                а также с учетом ожидаемого взвешенного снижения риска.
            </p>
            <p>
                Итоговая ожидаемая стоимость составляет <strong>${Number(data.total_cost || 0).toFixed(2)}</strong>,
                а ожидаемый остаточный риск — <strong>${Number(data.expected_total_residual_risk || 0).toFixed(4)}</strong>.
            </p>
        `;
    }
}

function renderLatestSummary(data) {
    const events = data.event_risks || [];
    const nodes = data.node_risks || [];
    const assets = data.asset_risks || [];

    renderSummary("latestSummary", [
        { label: "Последних событий", value: events.length },
        { label: "Последних узлов", value: nodes.length },
        { label: "Последних активов", value: assets.length }
    ]);
}

function setApiStatus(ok) {
    const badge = document.getElementById("apiStatusBadge");
    if (!badge) return;

    badge.className = "status-badge " + (ok ? "ok" : "error");
    badge.textContent = ok ? "API доступен" : "Ошибка API";
}

function downloadJson(filename, data) {
    if (!data) {
        alert("Нет данных для скачивания.");
        return;
    }

    const blob = new Blob([pretty(data)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();

    URL.revokeObjectURL(url);
}

document.getElementById("checkHealthBtn").addEventListener("click", async () => {
    try {
        const data = await getJson("/health");
        setText("healthResult", data);
        setApiStatus(true);
    } catch (error) {
        setText("healthResult", String(error));
        setApiStatus(false);
    }
});

document.getElementById("trainBtn").addEventListener("click", async () => {
    try {
        const payload = parseJsonFromTextarea("trainPayload", "/train");
        saveLocal("trainPayload", pretty(payload));
        setText("trainResult", "Запрос отправлен...");
        const data = await postJson("/train", payload);
        lastTrainResult = data;

        renderSummary("trainSummary", [
            { label: "Статус", value: data.status || "-" },
            { label: "Сэмплов", value: data.samples || 0 },
            { label: "Accuracy", value: data.metrics?.accuracy?.toFixed?.(4) ?? data.metrics?.accuracy ?? "-" },
            { label: "F1", value: data.metrics?.f1?.toFixed?.(4) ?? data.metrics?.f1 ?? "-" }
        ]);

        setText("trainResult", data);
    } catch (error) {
        setText("trainResult", String(error));
    }
});

document.getElementById("assessBtn").addEventListener("click", async () => {
    try {
        const payload = parseJsonFromTextarea("assessPayload", "/assess");
        saveLocal("assessPayload", pretty(payload));
        setText("assessResult", "Запрос отправлен...");
        const data = await postJson("/assess", payload);
        lastAssessResult = data;
        renderAssessViews(data);
        setText("assessResult", data);
    } catch (error) {
        setText("assessResult", String(error));
    }
});

document.getElementById("optimizeBtn").addEventListener("click", async () => {
    try {
        const payload = parseJsonFromTextarea("optimizePayload", "/optimize");
        saveLocal("optimizePayload", pretty(payload));
        setText("optimizeResult", "Запрос отправлен...");
        const data = await postJson("/optimize", payload);
        lastOptimizeResult = data;
        renderOptimizeViews(data);
        setText("optimizeResult", data);
    } catch (error) {
        setText("optimizeResult", String(error));
    }
});

async function loadLatest() {
    try {
        const data = await getJson("/latest");
        lastLatestResult = data;
        renderLatestSummary(data);
        setText("latestResult", data);
    } catch (error) {
        setText("latestResult", String(error));
    }
}

document.getElementById("latestBtn").addEventListener("click", loadLatest);
document.getElementById("latestBtnHero").addEventListener("click", loadLatest);

document.getElementById("loadTrainFileBtn").addEventListener("click", () => readJsonFileIntoTextarea("trainFileInput", "trainPayload"));
document.getElementById("loadAssessFileBtn").addEventListener("click", () => readJsonFileIntoTextarea("assessFileInput", "assessPayload"));
document.getElementById("loadOptimizeFileBtn").addEventListener("click", () => readJsonFileIntoTextarea("optimizeFileInput", "optimizePayload"));

document.getElementById("trainSampleBtn").addEventListener("click", () => {
    document.getElementById("trainPayload").value = pretty(trainSample);
});
document.getElementById("assessSampleBtn").addEventListener("click", () => {
    document.getElementById("assessPayload").value = pretty(assessSample);
});
document.getElementById("optimizeSampleBtn").addEventListener("click", () => {
    document.getElementById("optimizePayload").value = pretty(optimizeSample);
});

document.getElementById("formatTrainBtn").addEventListener("click", () => formatJsonTextarea("trainPayload"));
document.getElementById("formatAssessBtn").addEventListener("click", () => formatJsonTextarea("assessPayload"));
document.getElementById("formatOptimizeBtn").addEventListener("click", () => formatJsonTextarea("optimizePayload"));

document.getElementById("validateTrainBtn").addEventListener("click", () => validateJsonTextarea("trainPayload", "trainResult"));
document.getElementById("validateAssessBtn").addEventListener("click", () => validateJsonTextarea("assessPayload", "assessResult"));
document.getElementById("validateOptimizeBtn").addEventListener("click", () => validateJsonTextarea("optimizePayload", "optimizeResult"));

document.getElementById("saveTrainBtn").addEventListener("click", () => saveLocal("trainPayload", getTextareaValue("trainPayload")));
document.getElementById("saveAssessBtn").addEventListener("click", () => saveLocal("assessPayload", getTextareaValue("assessPayload")));
document.getElementById("saveOptimizeBtn").addEventListener("click", () => saveLocal("optimizePayload", getTextareaValue("optimizePayload")));

document.getElementById("clearTrainBtn").addEventListener("click", () => {
    document.getElementById("trainPayload").value = "";
    clearLocal("trainPayload");
});
document.getElementById("clearAssessBtn").addEventListener("click", () => {
    document.getElementById("assessPayload").value = "";
    clearLocal("assessPayload");
});
document.getElementById("clearOptimizeBtn").addEventListener("click", () => {
    document.getElementById("optimizePayload").value = "";
    clearLocal("optimizePayload");
});

document.getElementById("exportTrainResultBtn").addEventListener("click", () => {
    downloadJson("train_result.json", lastTrainResult);
});
document.getElementById("exportAssessResultBtn").addEventListener("click", () => {
    downloadJson("assess_result.json", lastAssessResult);
});
document.getElementById("exportOptimizeResultBtn").addEventListener("click", () => {
    downloadJson("optimize_result.json", lastOptimizeResult);
});
document.getElementById("exportLatestResultBtn").addEventListener("click", () => {
    downloadJson("latest_result.json", lastLatestResult);
});

document.querySelectorAll(".tab-button").forEach(button => {
    button.addEventListener("click", () => {
        const target = button.dataset.target;

        document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

        button.classList.add("active");
        document.getElementById(target).classList.add("active");
    });
});

setupDropzone("trainDropzone", "trainPayload");
setupDropzone("assessDropzone", "assessPayload");
setupDropzone("optimizeDropzone", "optimizePayload");

window.addEventListener("load", () => {
    document.getElementById("trainPayload").value = loadLocal("trainPayload");
    document.getElementById("assessPayload").value = loadLocal("assessPayload");
    document.getElementById("optimizePayload").value = loadLocal("optimizePayload");
});