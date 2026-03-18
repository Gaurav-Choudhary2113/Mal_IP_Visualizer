import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import geoip from "geoip-lite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.join(__dirname, "../data/malicious_ips.json");
const DEFAULT_CONFIDENCE_MINIMUM = 70;
const DEFAULT_BLACKLIST_LIMIT = 10000;

function parsePositiveIntegerEnv(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

const CONFIDENCE_MINIMUM = parsePositiveIntegerEnv(
  process.env.ABUSEIPDB_CONFIDENCE_MINIMUM,
  DEFAULT_CONFIDENCE_MINIMUM
);
const BLACKLIST_LIMIT = parsePositiveIntegerEnv(
  process.env.ABUSEIPDB_BLACKLIST_LIMIT,
  DEFAULT_BLACKLIST_LIMIT
);

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

function persistSnapshot(snapshot) {
  ensureDataDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(snapshot, null, 2));
}

export function readLatestBlacklistSnapshot() {
  return readJson(DATA_PATH, null);
}

export async function refreshBlacklist() {
  const generatedAt = new Date().toISOString();
  const blacklistUrl = new URL("https://api.abuseipdb.com/api/v2/blacklist");
  blacklistUrl.searchParams.set("confidenceMinimum", String(CONFIDENCE_MINIMUM));
  blacklistUrl.searchParams.set("limit", String(BLACKLIST_LIMIT));

  const response = await fetch(blacklistUrl, {
    headers: {
      Key: process.env.ABUSEIPDB_API_KEY,
      Accept: "application/json"
    }
  });

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
  console.log(
    `[AbuseIPDB] Saved ${processed.length} geolocated malicious IPs ` +
      `(confidence >= ${CONFIDENCE_MINIMUM}, requested limit ${BLACKLIST_LIMIT})`
  );
}
