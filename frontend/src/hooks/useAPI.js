// hooks/useAPI.js
// 백엔드 실제 연동 훅 — 연결 실패 시 데모 데이터 자동 폴백

import API_BASE from "./apiConfig.js";

// ── 공통 fetch 래퍼 ──────────────────────────────────────────────
export async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(8000),
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── 대시보드 ─────────────────────────────────────────────────────
export async function fetchDashboard() {
  return apiFetch("/api/dashboard");
}

// ── 자산 ─────────────────────────────────────────────────────────
export async function fetchAssets() {
  return apiFetch("/api/assets");
}

export async function fetchAssetDetail(id) {
  return apiFetch(`/api/assets/${id}`);
}

export async function createAsset(data) {
  return apiFetch("/api/assets", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function deleteAsset(id) {
  return apiFetch(`/api/assets/${id}`, { method: "DELETE" });
}

export async function updateAsset(id, data) {
  return apiFetch(`/api/assets/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

// ── 점검 ─────────────────────────────────────────────────────────
export async function startScan(assetIds, scanTypes = "port,web,ssl") {
  return apiFetch("/api/scan/start", {
    method: "POST",
    body: JSON.stringify({ asset_ids: assetIds, scan_types: scanTypes }),
  });
}

export async function fetchScanStatus(jobId) {
  return apiFetch(`/api/scan/status/${jobId}`);
}

export async function fetchScanHistory() {
  return apiFetch("/api/scan/history");
}

// ── 취약점 ───────────────────────────────────────────────────────
export async function fetchFindings(params = {}) {
  const qs = new URLSearchParams();
  if (params.severity)    qs.set("severity",    params.severity);
  if (params.status)      qs.set("status",      params.status);
  if (params.scan_type)   qs.set("scan_type",   params.scan_type);
  if (params.repeat_only) qs.set("repeat_only", "true");
  const q = qs.toString();
  return apiFetch(`/api/findings${q ? "?" + q : ""}`);
}

export async function fetchFindingStats() {
  return apiFetch("/api/findings/stats");
}

export async function fetchRepeatFindings() {
  return apiFetch("/api/findings/repeat");
}

export async function resolveFindings(findingId, resolvedBy, note = "") {
  return apiFetch(`/api/findings/${findingId}/resolve`, {
    method: "POST",
    body: JSON.stringify({ resolved_by: resolvedBy, note }),
  });
}

export async function deleteFinding(findingId) {
  return apiFetch(`/api/findings/${findingId}`, { method: "DELETE" });
}

export async function deleteFindings(ids) {
  // 일괄 삭제 — 병렬 처리
  return Promise.all(ids.map(id => apiFetch(`/api/findings/${id}`, { method: "DELETE" })));
}

// ── 알람 ─────────────────────────────────────────────────────────
export async function fetchAlerts(unreadOnly = false) {
  return apiFetch(`/api/alerts${unreadOnly ? "?unread_only=true" : ""}`);
}

export async function fetchAlertCount() {
  return apiFetch("/api/alerts/count");
}

export async function markAlertsRead(alertIds) {
  return apiFetch("/api/alerts/read", {
    method: "POST",
    body: JSON.stringify(alertIds),
  });
}

export async function fetchAlertConfigs() {
  return apiFetch("/api/alerts/config");
}

export async function updateAlertConfig(alertType, data) {
  return apiFetch(`/api/alerts/config/${alertType}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

// ── CVE ──────────────────────────────────────────────────────────
export async function fetchCVE(days = 30) {
  return apiFetch(`/api/cve?days=${days}`);
}

// ── 뉴스 ─────────────────────────────────────────────────────────
export async function fetchNews(source = "") {
  return apiFetch(`/api/news${source ? "?source=" + source : ""}`);
}

export async function triggerNewsFetch() {
  return apiFetch("/api/news/fetch", { method: "POST" });
}

// ── 컴플라이언스 ──────────────────────────────────────────────────
export async function fetchCompliance() {
  return apiFetch("/api/compliance");
}

// ── 리포트 ───────────────────────────────────────────────────────
export async function generateReport(reportType = "executive") {
  // 보고서 생성은 시간이 걸릴 수 있으므로 타임아웃 60초
  const res = await fetch(`${API_BASE}/api/report/generate?report_type=${reportType}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── 업로드 ───────────────────────────────────────────────────────
export async function uploadAssets(file, uploadedBy = "admin") {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("uploaded_by", uploadedBy);
  const res = await fetch(`${API_BASE}/api/assets/upload`, {
    method: "POST",
    body: fd,
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "업로드 실패");
  }
  return res.json();
}

export async function fetchUploadHistory() {
  return apiFetch("/api/assets/upload/history");
}
