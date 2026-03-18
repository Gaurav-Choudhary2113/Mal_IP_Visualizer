const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

function toFiniteNumber(value) {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
}

function toApiUrl(path) {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  if (API_BASE_URL) {
    return `${API_BASE_URL}${path}`;
  }

  return path;
}

function clampScore(value) {
  const numericValue = toFiniteNumber(value) ?? 0;
  return Math.max(0, Math.min(100, numericValue));
}

function humanizeSummaryLabel(label) {
  return String(label)
    .split("_")
    .filter(Boolean)
    .map((segment) => {
      if (segment.length <= 3 || /^[0-9./-]+$/.test(segment)) {
        return segment;
      }

      return segment.charAt(0) + segment.slice(1).toLowerCase();
    })
    .join(" ");
}

async function requestJson(path, options = {}) {
  const requestUrl = toApiUrl(path);
  const response = await fetch(requestUrl, {
    headers: {
      Accept: "application/json"
    },
    ...options
  });

  const rawBody = await response.text();
  let payload = null;

  if (rawBody) {
    try {
      payload = JSON.parse(rawBody);
    } catch {
      throw new Error(`Received an invalid JSON payload from ${requestUrl}.`);
    }
  }

  if (!response.ok) {
    throw new Error(
      payload?.error ?? `Request to ${requestUrl} failed with status ${response.status}.`
    );
  }

  return payload;
}

function normalizeMaliciousIps(payload) {
  const ips = Array.isArray(payload?.ips) ? payload.ips : [];

  const normalizedIps = ips
    .map((ip) => {
      const lat = toFiniteNumber(ip?.lat);
      const lng = toFiniteNumber(ip?.lon);

      if (lat === null || lng === null) {
        return null;
      }

      return {
        lat,
        lng,
        score: clampScore(ip?.score),
        ip: String(ip?.ip ?? "Unknown"),
        lastReportedAt: ip?.lastReportedAt ?? null,
        sourceSnapshotGeneratedAt:
          ip?.sourceSnapshotGeneratedAt ?? payload?.generatedAt ?? null
      };
    })
    .filter(Boolean);

  return {
    generatedAt: payload?.generatedAt ?? null,
    count: toFiniteNumber(payload?.count) ?? normalizedIps.length,
    ips: normalizedIps
  };
}

function normalizeCountryRows(payload) {
  const rows = Array.isArray(payload?.data) ? payload.data : [];

  return rows
    .map((row) => {
      const value = toFiniteNumber(row?.value);

      if (value === null) {
        return null;
      }

      return {
        code: String(row?.country ?? "--"),
        label: String(row?.name ?? row?.country ?? "Unknown"),
        value,
        rank: toFiniteNumber(row?.rank) ?? null
      };
    })
    .filter(Boolean)
    .sort((left, right) => right.value - left.value);
}

function normalizeSummaryRows(payload) {
  const summary = payload?.data && typeof payload.data === "object" ? payload.data : {};

  return Object.entries(summary)
    .map(([label, value]) => {
      const numericValue = toFiniteNumber(value);

      if (numericValue === null) {
        return null;
      }

      return {
        label: humanizeSummaryLabel(label),
        value: numericValue
      };
    })
    .filter(Boolean)
    .sort((left, right) => right.value - left.value);
}

export async function getMaliciousIps(options = {}) {
  const payload = await requestJson("/api/malicious-ips", options);
  return normalizeMaliciousIps(payload);
}

export async function getRadarOrigins(dateRange, options = {}) {
  const payload = await requestJson(`/api/radar/origins?dateRange=${dateRange}`, options);
  return normalizeCountryRows(payload);
}

export async function getRadarTargets(dateRange, options = {}) {
  const payload = await requestJson(`/api/radar/targets?dateRange=${dateRange}`, options);
  return normalizeCountryRows(payload);
}

export async function getRadarSummary(dimension, dateRange, options = {}) {
  const payload = await requestJson(
    `/api/radar/summary/${dimension}?dateRange=${dateRange}`,
    options
  );

  return normalizeSummaryRows(payload);
}
