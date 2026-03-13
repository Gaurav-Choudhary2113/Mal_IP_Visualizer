import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import geoip from "geoip-lite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.join(__dirname, "../data/malicious_ips.json");
const HISTORY_PATH = path.join(__dirname, "../data/malicious_ips_history.json");
const HISTORY_RETENTION_DAYS = 7;
const DATE_RANGE_TO_MS = {
  "1d": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000
};

function ensureDataDir() {
  fs.mkdirSync(path.dirname(DATA_PATH), { recursive: true });
}

function readJson(filePath, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return fallback;
  }
}

function snapshotGeneratedAt(snapshot) {
  return Date.parse(snapshot?.generatedAt ?? "");
}

function ipEventTime(ip, snapshot) {
  const ipTimestamp = Date.parse(ip?.lastReportedAt ?? "");
  if (Number.isFinite(ipTimestamp)) {
    return ipTimestamp;
  }

  const snapshotTimestamp = snapshotGeneratedAt(snapshot);
  return Number.isFinite(snapshotTimestamp) ? snapshotTimestamp : 0;
}

function normalizeHistory(historyPayload) {
  if (!historyPayload || !Array.isArray(historyPayload.snapshots)) {
    return [];
  }

  return historyPayload.snapshots.filter(
    (snapshot) => snapshot && typeof snapshot === "object" && Array.isArray(snapshot.ips)
  );
}

function persistSnapshot(snapshot) {
  ensureDataDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(snapshot, null, 2));

  const retentionCutoff = Date.now() - HISTORY_RETENTION_DAYS * DATE_RANGE_TO_MS["1d"];
  const historySnapshots = normalizeHistory(readJson(HISTORY_PATH, { snapshots: [] }))
    .filter((entry) => {
      const generatedAt = snapshotGeneratedAt(entry);
      return Number.isFinite(generatedAt) && generatedAt >= retentionCutoff;
    })
    .filter((entry) => entry.generatedAt !== snapshot.generatedAt);

  historySnapshots.push(snapshot);
  historySnapshots.sort((left, right) => snapshotGeneratedAt(left) - snapshotGeneratedAt(right));

  fs.writeFileSync(
    HISTORY_PATH,
    JSON.stringify(
      {
        updatedAt: snapshot.generatedAt,
        retentionDays: HISTORY_RETENTION_DAYS,
        snapshots: historySnapshots
      },
      null,
      2
    )
  );
}

function compareIpRecords(left, right) {
  const rightEventTime = ipEventTime(right, right.__snapshot);
  const leftEventTime = ipEventTime(left, left.__snapshot);

  if (rightEventTime !== leftEventTime) {
    return rightEventTime - leftEventTime;
  }

  if (right.score !== left.score) {
    return right.score - left.score;
  }

  return String(left.ip).localeCompare(String(right.ip));
}

export function readLatestBlacklistSnapshot() {
  return readJson(DATA_PATH, null);
}

export function readBlacklistHistory() {
  const latestSnapshot = readLatestBlacklistSnapshot();
  const historySnapshots = normalizeHistory(readJson(HISTORY_PATH, { snapshots: [] }));

  if (!latestSnapshot) {
    return historySnapshots;
  }

  const hasLatestSnapshot = historySnapshots.some(
    (snapshot) => snapshot.generatedAt === latestSnapshot.generatedAt
  );

  return hasLatestSnapshot ? historySnapshots : [...historySnapshots, latestSnapshot];
}

export function isSupportedMaliciousDateRange(dateRange) {
  return Object.hasOwn(DATE_RANGE_TO_MS, dateRange);
}

export function buildMaliciousRangeSnapshot(dateRange) {
  const rangeMs = DATE_RANGE_TO_MS[dateRange];
  if (!rangeMs) {
    throw new Error(`Unsupported dateRange '${dateRange}'.`);
  }

  const latestSnapshot = readLatestBlacklistSnapshot();
  const historySnapshots = readBlacklistHistory();
  if (!historySnapshots.length) {
    return null;
  }

  const cutoff = Date.now() - rangeMs;
  const latestByIp = new Map();

  for (const snapshot of historySnapshots) {
    const ips = Array.isArray(snapshot?.ips) ? snapshot.ips : [];

    for (const ip of ips) {
      const eventTimestamp = ipEventTime(ip, snapshot);
      if (!Number.isFinite(eventTimestamp) || eventTimestamp < cutoff) {
        continue;
      }

      const nextRecord = {
        ...ip,
        sourceSnapshotGeneratedAt: snapshot.generatedAt ?? null,
        __snapshot: snapshot
      };
      const existingRecord = latestByIp.get(ip.ip);

      if (!existingRecord || compareIpRecords(nextRecord, existingRecord) < 0) {
        latestByIp.set(ip.ip, nextRecord);
      }
    }
  }

  const ips = Array.from(latestByIp.values())
    .sort(compareIpRecords)
    .map(({ __snapshot, ...ip }) => ip);

  const snapshotsCovered = historySnapshots.filter((snapshot) => {
    const generatedAt = snapshotGeneratedAt(snapshot);
    return Number.isFinite(generatedAt) && generatedAt >= cutoff;
  }).length;

  const historyStartAt =
    historySnapshots.length > 0
      ? historySnapshots.reduce((earliest, snapshot) => {
          const generatedAt = snapshotGeneratedAt(snapshot);
          if (!Number.isFinite(generatedAt)) {
            return earliest;
          }

          if (earliest === null || generatedAt < earliest) {
            return generatedAt;
          }

          return earliest;
        }, null)
      : null;

  return {
    generatedAt: latestSnapshot?.generatedAt ?? new Date().toISOString(),
    historyStartAt: historyStartAt ? new Date(historyStartAt).toISOString() : null,
    dateRange,
    snapshotsCovered,
    count: ips.length,
    ips
  };
}

export async function refreshBlacklist() {
  const generatedAt = new Date().toISOString();
  const response = await fetch(
    "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=3000",
    {
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: "application/json"
      }
    }
  );

  const data = await response.json();
  const processed = [];

  for (const entry of data.data) {
    const geo = geoip.lookup(entry.ipAddress);
    if (!geo || !geo.ll) continue;

    processed.push({
      ip: entry.ipAddress,
      lat: geo.ll[0],
      lon: geo.ll[1],
      score: entry.abuseConfidenceScore,
      lastReportedAt: entry.lastReportedAt,
      sourceSnapshotGeneratedAt: generatedAt
    });
  }

  const output = {
    generatedAt,
    count: processed.length,
    ips: processed
  };

  persistSnapshot(output);
  console.log(`[AbuseIPDB] Saved ${processed.length} malicious IPs`);
}
