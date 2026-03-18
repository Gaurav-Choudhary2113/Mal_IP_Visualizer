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

function parseJsonText(text) {
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
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

function normalizeHoneypotAttack(attack) {
  const sourceLat = toFiniteNumber(attack?.source?.lat);
  const sourceLng = toFiniteNumber(attack?.source?.lng);
  const targetLat = toFiniteNumber(attack?.target?.lat);
  const targetLng = toFiniteNumber(attack?.target?.lng);

  return {
    id: String(attack?.id ?? `${attack?.eventId ?? "attack"}-${attack?.timestamp ?? Date.now()}`),
    eventId: String(attack?.eventId ?? "unknown"),
    session: attack?.session ?? null,
    timestamp: attack?.timestamp ?? null,
    ingestedAt: attack?.ingestedAt ?? null,
    source: {
      ip: String(attack?.source?.ip ?? "Unknown IP"),
      port: toFiniteNumber(attack?.source?.port),
      lat: sourceLat,
      lng: sourceLng,
      country: attack?.source?.country ?? null,
      countryCode: attack?.source?.countryCode ?? null,
      region: attack?.source?.region ?? null,
      city: attack?.source?.city ?? null,
      org: attack?.source?.org ?? null,
      asn: attack?.source?.asn ?? null
    },
    target: {
      label: attack?.target?.label ?? "India Honeypot",
      lat: targetLat,
      lng: targetLng,
      country: attack?.target?.country ?? "India",
      countryCode: attack?.target?.countryCode ?? "IN"
    },
    username: attack?.username ?? null,
    password: attack?.password ?? null,
    command: attack?.command ?? null,
    wasSuccessful:
      typeof attack?.wasSuccessful === "boolean" ? attack.wasSuccessful : attack?.wasSuccessful ?? null,
    clientVersion: attack?.clientVersion ?? null,
    hassh: attack?.hassh ?? null,
    protocol: attack?.protocol ?? "ssh"
  };
}

function normalizeHoneypotTarget(target) {
  if (!target) {
    return null;
  }

  return {
    label: target.label ?? "India Honeypot",
    lat: toFiniteNumber(target.lat),
    lng: toFiniteNumber(target.lng),
    country: target.country ?? "India",
    countryCode: target.countryCode ?? "IN"
  };
}

function normalizeHoneypotMetadata(payload) {
  return {
    generatedAt: payload?.generatedAt ?? null,
    target: normalizeHoneypotTarget(payload?.target),
    startedAt: payload?.startedAt ?? null,
    totalSinceStartup: toFiniteNumber(payload?.totalSinceStartup) ?? 0,
    mapWindowMinutes: toFiniteNumber(payload?.mapWindowMinutes) ?? 120
  };
}

function normalizeHoneypotFeed(payload) {
  const attacks = Array.isArray(payload?.attacks) ? payload.attacks : [];
  const mapAttacks = Array.isArray(payload?.mapAttacks) ? payload.mapAttacks : [];
  const normalizedAttacks = attacks
    .map(normalizeHoneypotAttack)
    .sort((left, right) => Date.parse(right.timestamp ?? 0) - Date.parse(left.timestamp ?? 0));
  const normalizedMapAttacks = mapAttacks
    .map(normalizeHoneypotAttack)
    .sort((left, right) => Date.parse(right.timestamp ?? 0) - Date.parse(left.timestamp ?? 0));

  const latestTarget =
    normalizedAttacks[0]?.target ??
    normalizedMapAttacks[0]?.target ??
    normalizeHoneypotTarget(payload?.target);

  const metadata = normalizeHoneypotMetadata(payload);

  return {
    generatedAt: metadata.generatedAt,
    count: toFiniteNumber(payload?.count) ?? normalizedAttacks.length,
    startedAt: metadata.startedAt,
    totalSinceStartup: metadata.totalSinceStartup,
    mapWindowMinutes: metadata.mapWindowMinutes,
    mapAttackCount: toFiniteNumber(payload?.mapAttackCount) ?? normalizedMapAttacks.length,
    target: latestTarget,
    attacks: normalizedAttacks,
    mapAttacks: normalizedMapAttacks
  };
}

function normalizeHoneypotStreamAttack(payload) {
  if (!payload?.attack) {
    return null;
  }

  return {
    attack: normalizeHoneypotAttack(payload.attack),
    totalSinceStartup: toFiniteNumber(payload?.totalSinceStartup)
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

export async function getHoneypotAttacks(limit = 40, options = {}) {
  const payload = await requestJson(`/api/honeypot/attacks?limit=${limit}`, options);
  return normalizeHoneypotFeed(payload);
}

export function createHoneypotStream({ onReady, onAttack, onError }) {
  if (typeof EventSource === "undefined") {
    return null;
  }

  const eventSource = new EventSource(toApiUrl("/api/honeypot/stream"));

  eventSource.addEventListener("ready", (event) => {
    onReady?.(normalizeHoneypotMetadata(parseJsonText(event.data)));
  });

  eventSource.addEventListener("attack", (event) => {
    const payload = normalizeHoneypotStreamAttack(parseJsonText(event.data));
    if (!payload?.attack) {
      return;
    }

    onAttack?.(payload);
  });

  eventSource.onerror = (event) => {
    onError?.(event);
  };

  return eventSource;
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
