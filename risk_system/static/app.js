let lastPipelineResult = null;

const pipelineSample = {
  logs: [
    {
      log_id: "log_001",
      timestamp: "2026-05-09T10:15:00",
      source_system: "SIEM",
      source_type: "siem",
      raw_message: "Software update completed successfully",
      event_code: "UPDATE_OK",
      host: "app-server-01",
      node_id: "node_app_01",
      asset_id: "asset_payments",
      action: "software_update",
      result: "success",
      severity_from_source: 0.1,
      metadata: {
        update_type: "security_patch",
        critical_asset: true,
        node_type: "application_server",
        asset_type: "payment_system",
        network_segment: "payment_processing",
        process_criticality: "critical",
        availability_impact: "high",
        integrity_impact: "high"
      }
    },
    {
      log_id: "log_002",
      timestamp: "2026-05-09T10:20:00",
      source_system: "SIEM",
      source_type: "siem",
      raw_message: "Security update failed. EDR agent disabled after update error",
      event_code: "UPDATE_FAILED",
      host: "app-server-01",
      node_id: "node_app_01",
      asset_id: "asset_payments",
      action: "software_update",
      result: "error",
      severity_from_source: 0.8,
      metadata: {
        update_type: "security_patch",
        edr_disabled: true,
        critical_asset: true,
        affected_process: "payment_processing",
        potential_loss: 750000,
        node_type: "application_server",
        asset_type: "payment_system",
        network_segment: "payment_processing",
        process_criticality: "critical",
        availability_impact: "high",
        integrity_impact: "high"
      }
    },
    {
      log_id: "log_003",
      timestamp: "2026-05-09T10:25:00",
      source_system: "EDR",
      source_type: "edr",
      raw_message: "Malware detected on database server",
      event_code: "MALWARE_DETECTED",
      host: "db-server-01",
      node_id: "node_db_01",
      asset_id: "asset_clients_db",
      action: "malware_detection",
      result: "blocked",
      severity_from_source: 0.95,
      metadata: {
        malware_detected: true,
        critical_asset: true,
        affected_process: "client_data_processing",
        potential_loss: 1500000,
        node_type: "database_server",
        asset_type: "client_database",
        network_segment: "data_processing",
        process_criticality: "critical",
        confidentiality_impact: "critical",
        integrity_impact: "high"
      }
    }
  ],
  incident_threshold: 0.5,
  risk_event_threshold: 0.5,
  infrastructure_links: [
    {
      source_node_id: "node_db_01",
      target_node_id: "node_app_01",
      influence_weight: 0.2,
      relation_type: "service_dependency",
      description: "Сервер приложения использует базу данных клиентов"
    }
  ],
  optimization_constraints: {
    max_budget: 800000,
    max_labor: 120,
    max_implementation_time: 45,
    max_measures: 3,
    min_effectiveness: 0.03
  }
};

function toggleMenu() {
  document.getElementById("topnav")?.classList.toggle("open");
}

function closeMenu() {
  document.getElementById("topnav")?.classList.remove("open");
}

function scrollToSection(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function getText(id) {
  const element = document.getElementById(id);
  if (!element) return "";
  return element.value ?? element.textContent ?? "";
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = typeof value === "string" ? value : pretty(value);
}

function setValue(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  element.value = typeof value === "string" ? value : pretty(value);
}

function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;

  toast.textContent = message;
  toast.hidden = false;

  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
  }, 3000);
}

async function getJson(url) {
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok) throw new Error(pretty(data));
  return data;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const data = await response.json();
  if (!response.ok) throw new Error(pretty(data));
  return data;
}

function parseTextareaJson(id) {
  const raw = document.getElementById(id).value.trim();
  if (!raw) throw new Error("JSON-поле пустое.");
  return JSON.parse(raw);
}

function insertPipelineSample() {
  setValue("pipelineInput", pipelineSample);
  setText("pipelineStatus", "Демонстрационный пример загружен.");
  showToast("Пример вставлен");
}

function formatJson(id) {
  try {
    const payload = parseTextareaJson(id);
    setValue(id, payload);
    showToast("JSON отформатирован");
  } catch (error) {
    showToast(`Ошибка: ${error.message}`);
  }
}

function validateJson(id, statusId) {
  try {
    parseTextareaJson(id);
    setText(statusId, "JSON корректен.");
    showToast("JSON корректен");
  } catch (error) {
    setText(statusId, `Ошибка JSON: ${error.message}`);
    showToast("В JSON есть ошибка");
  }
}

function clearPipeline() {
  setValue("pipelineInput", "");
  setText("pipelineResult", "Результат пока отсутствует.");
  setText("pipelineStatus", "Готово к запуску.");
  resetPipelineMetrics();
  clearTables();
  showToast("Данные очищены");
}

function loadJsonFile(inputId, textareaId) {
  const input = document.getElementById(inputId);
  const file = input?.files?.[0];

  if (!file) {
    showToast("Файл не выбран");
    return;
  }

  const reader = new FileReader();
  reader.onload = event => {
    setValue(textareaId, event.target.result);
    showToast(`Файл ${file.name} загружен`);
  };
  reader.readAsText(file, "utf-8");
}

function downloadText(filename, text) {
  if (!text || text.includes("Результат пока отсутствует")) {
    showToast("Нечего скачивать");
    return;
  }

  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  link.click();

  URL.revokeObjectURL(url);
}

async function checkHealth() {
  const dot = document.getElementById("apiStatusDot");
  const text = document.getElementById("apiStatusText");

  try {
    await getJson("/health");
    dot.className = "status-dot ok";
    text.textContent = "Backend доступен";
    showToast("Backend отвечает");
  } catch (error) {
    dot.className = "status-dot error";
    text.textContent = "Backend недоступен";
    showToast("Backend недоступен");
  }
}

async function runFullPipeline() {
  try {
    setText("pipelineStatus", "Выполняется полный конвейер...");
    const payload = parseTextareaJson("pipelineInput");
    const result = await postJson("/pipeline/full", payload);

    lastPipelineResult = result;
    setText("pipelineResult", result);
    renderPipelineResult(result);
    setText("pipelineStatus", "Обработка завершена успешно.");
    showToast("Полный конвейер выполнен");
  } catch (error) {
    setText("pipelineStatus", `Ошибка: ${error.message}`);
    setText("pipelineResult", error.message);
    showToast("Ошибка обработки");
  }
}

function renderPipelineResult(result) {
  const pipeline = result.pipeline || {};
  const summary = pipeline.summary || {};
  const assessments = result.risk_assessments || [];
  const controls = result.control_optimization?.selected_measures || [];

  renderPipelineMetrics(summary, assessments.length, controls.length);
  renderStages(summary.pipeline_stages || {});
  renderRiskAssessments(assessments);
  renderControlRecommendations(controls);
  renderRiskEvents(pipeline.risk_events || []);
  renderIncidents(pipeline.incidents || []);
}

function resetPipelineMetrics() {
  const metrics = document.getElementById("pipelineMetrics");
  if (!metrics) return;

  metrics.innerHTML = [
    metricCard("Логи", "—"),
    metricCard("События ЗИ", "—"),
    metricCard("Инциденты", "—"),
    metricCard("События риска", "—"),
    metricCard("Оценки риска", "—"),
    metricCard("Меры", "—")
  ].join("");
}

function renderPipelineMetrics(summary, assessmentsCount, controlsCount) {
  const metrics = document.getElementById("pipelineMetrics");
  if (!metrics) return;

  metrics.innerHTML = [
    metricCard("Логи", summary.logs_received ?? 0),
    metricCard("События ЗИ", summary.normalized_events_count ?? 0),
    metricCard("Инциденты", summary.incident_candidates_count ?? 0),
    metricCard("События риска", summary.risk_events_count ?? 0),
    metricCard("Оценки риска", assessmentsCount ?? 0),
    metricCard("Меры", controlsCount ?? 0)
  ].join("");
}

function metricCard(label, value) {
  return `
    <div class="metric">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value))}</strong>
    </div>
  `;
}

function renderStages(stages) {
  const container = document.getElementById("stageList");
  if (!container) return;

  const entries = Object.entries(stages);

  if (!entries.length) {
    container.innerHTML = `<div class="empty-note">Этапы появятся после запуска.</div>`;
    return;
  }

  container.innerHTML = entries
    .map(([key, value]) => {
      const num = key.replace("stage_", "");
      return `<div class="stage-item"><strong>Этап ${escapeHtml(num)}.</strong> ${escapeHtml(value)}</div>`;
    })
    .join("");
}

function clearTables() {
  setEmpty("riskAssessmentsTable", "Нет данных. Запустите обработку.");
  setEmpty("controlsTable", "Рекомендации по мерам защиты пока не сформированы.");
  setEmpty("riskEventsTable", "События риска пока не загружены.");
  setEmpty("incidentsTable", "Инциденты пока не загружены.");
}

function setEmpty(id, message) {
  const container = document.getElementById(id);
  if (!container) return;
  container.className = "table-shell empty-state";
  container.textContent = message;
}

function renderRiskAssessments(items) {
  const container = document.getElementById("riskAssessmentsTable");
  if (!container) return;

  container.className = "table-shell";

  container.innerHTML = buildTable(
    [
      ["risk_event_id", "Событие риска"],
      ["node_id", "Объект"],
      ["asset_id", "Актив"],
      ["threat_scenario", "Сценарий"],
      ["probability_estimate", "p"],
      ["impact_estimate", "I"],
      ["initial_risk_estimate", "r⁰"],
      ["graph_adjusted_risk_estimate", "Граф"],
      ["final_risk_estimate", "Итог"],
      ["risk_class", "Класс"],
      ["priority", "Приоритет"]
    ],
    items
  );
}

function renderControlRecommendations(items) {
  const container = document.getElementById("controlsTable");
  if (!container) return;

  container.className = "table-shell";

  container.innerHTML = buildTable(
    [
      ["measure_id", "ID"],
      ["name", "Мера"],
      ["measure_type", "Тип"],
      ["cost", "Стоимость"],
      ["labor", "Трудоемкость"],
      ["implementation_time", "Срок"],
      ["expected_risk_reduction", "Снижение"],
      ["expected_residual_risk", "Остаток"]
    ],
    items
  );
}

function renderRiskEvents(items) {
  const container = document.getElementById("riskEventsTable");
  if (!container) return;

  container.className = "table-shell";

  container.innerHTML = buildTable(
    [
      ["risk_event_id", "ID"],
      ["incident_id", "Инцидент"],
      ["event_type", "Тип"],
      ["threat_scenario", "Сценарий"],
      ["node_id", "Объект"],
      ["asset_id", "Актив"],
      ["probability_estimate", "Вероятность"],
      ["impact_estimate", "Последствия"],
      ["classifier_confidence", "ML"]
    ],
    items
  );
}

function renderIncidents(items) {
  const container = document.getElementById("incidentsTable");
  if (!container) return;

  container.className = "table-shell";

  container.innerHTML = buildTable(
    [
      ["incident_id", "ID"],
      ["incident_type", "Тип"],
      ["severity", "Уровень"],
      ["status", "Статус"],
      ["node_id", "Объект"],
      ["asset_id", "Актив"],
      ["affected_process", "Процесс"],
      ["classifier_confidence", "Уверенность"]
    ],
    items
  );
}

function buildTable(columns, rows) {
  if (!rows || rows.length === 0) {
    return `<div class="empty-state">Нет данных для отображения.</div>`;
  }

  const head = columns.map(([, label]) => `<th>${escapeHtml(label)}</th>`).join("");

  const body = rows
    .map(row => {
      const cells = columns
        .map(([key]) => `<td>${formatCell(key, row[key])}</td>`)
        .join("");
      return `<tr>${cells}</tr>`;
    })
    .join("");

  return `
    <table class="data-table">
      <thead><tr>${head}</tr></thead>
      <tbody>${body}</tbody>
    </table>
  `;
}

function formatCell(key, value) {
  if (value === null || value === undefined || value === "") return "—";

  if (key === "risk_class" || key === "severity") {
    return pill(value);
  }

  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(4);
  }

  if (Array.isArray(value)) {
    return escapeHtml(value.join(", "));
  }

  if (typeof value === "object") {
    return `<code>${escapeHtml(JSON.stringify(value))}</code>`;
  }

  return escapeHtml(String(value));
}

function pill(value) {
  const text = String(value).toLowerCase();
  return `<span class="pill ${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

async function refreshStorageSummary() {
  try {
    const summary = await getJson("/event-storage-summary");
    setText("storageSummary", summary);
    renderStorageMetrics(summary);
    showToast("Сводка базы обновлена");
  } catch (error) {
    setText("storageSummary", error.message);
    showToast("Ошибка загрузки сводки базы");
  }
}

function renderStorageMetrics(summary) {
  const container = document.getElementById("storageMetrics");
  if (!container) return;

  container.innerHTML = [
    metricCard("События ЗИ", summary.security_events_count ?? 0),
    metricCard("Инциденты", summary.incidents_count ?? 0),
    metricCard("События риска", summary.risk_events_count ?? 0),
    metricCard("Оценки риска", summary.risk_assessments_count ?? 0),
    metricCard("Меры", summary.control_recommendations_count ?? 0)
  ].join("");
}

async function loadStoredResults() {
  try {
    const assessments = await getJson("/risk-assessments");
    const controls = await getJson("/control-recommendations");
    const riskEvents = await getJson("/risk-events");
    const incidents = await getJson("/incidents");

    renderRiskAssessments(assessments);
    renderControlRecommendations(controls);
    renderRiskEvents(riskEvents);
    renderIncidents(incidents);

    setText("pipelineResult", {
      risk_assessments: assessments,
      control_recommendations: controls,
      risk_events: riskEvents,
      incidents: incidents
    });

    renderPipelineMetrics(
      {
        logs_received: "БД",
        normalized_events_count: "БД",
        incident_candidates_count: incidents.length,
        risk_events_count: riskEvents.length
      },
      assessments.length,
      controls.length
    );

    showToast("Результаты загружены из базы");
  } catch (error) {
    showToast(`Ошибка загрузки: ${error.message}`);
  }
}

async function trainClassifierFromFile() {
  const input = document.getElementById("trainingFileInput");
  const file = input?.files?.[0];

  if (!file) {
    showToast("Выберите CSV или JSON-файл");
    return;
  }

  const modelType = document.getElementById("modelType").value;
  const saveModel = document.getElementById("saveModel").checked;

  const formData = new FormData();
  formData.append("file", file);
  formData.append("model_type", modelType);
  formData.append("save_model", String(saveModel));

  try {
    setText("trainingResult", "Модель обучается...");
    const response = await fetch("/risk-event-classifier/train-file", {
      method: "POST",
      body: formData
    });

    const data = await response.json();
    if (!response.ok) throw new Error(pretty(data));

    setText("trainingResult", data);
    showToast("ML-классификатор обучен");
  } catch (error) {
    setText("trainingResult", error.message);
    showToast("Ошибка обучения модели");
  }
}

function openTab(tabId, button) {
  document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(tab => tab.classList.remove("active"));

  document.getElementById(tabId)?.classList.add("active");
  button?.classList.add("active");
}

function setupDropzone(dropzoneId, textareaId) {
  const dropzone = document.getElementById(dropzoneId);
  if (!dropzone) return;

  ["dragenter", "dragover"].forEach(name => {
    dropzone.addEventListener(name, event => {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(name => {
    dropzone.addEventListener(name, event => {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", event => {
    const file = event.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = e => {
      setValue(textareaId, e.target.result);
      showToast(`Файл ${file.name} загружен`);
    };
    reader.readAsText(file, "utf-8");
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  setupDropzone("pipelineDropzone", "pipelineInput");
  insertPipelineSample();
  checkHealth();
});