import { Router } from "express";
import { readLatestBlacklistSnapshot, refreshBlacklist } from "../services/abuseipdb.js";

const router = Router();
let refreshInFlight = null;
let lastRefreshError = null;
let refreshBlockedUntil = 0;
const ON_DEMAND_REFRESH_ENABLED =
  String(process.env.ABUSEIPDB_ON_DEMAND_REFRESH ?? "false").toLowerCase() === "true";

function isRateLimitError(errorMessage) {
  return /\(429\)|rate limit/i.test(String(errorMessage ?? ""));
}

router.get("/api/malicious-ips", async (req, res) => {
  try {
    let latestSnapshot = readLatestBlacklistSnapshot();
    const now = Date.now();
    const isRefreshBlocked = refreshBlockedUntil > now;

    if (
      !latestSnapshot &&
      process.env.ABUSEIPDB_API_KEY &&
      ON_DEMAND_REFRESH_ENABLED &&
      !isRefreshBlocked
    ) {
      if (!refreshInFlight) {
        refreshInFlight = refreshBlacklist()
          .then(() => {
            lastRefreshError = null;
            refreshBlockedUntil = 0;
          })
          .catch((error) => {
            lastRefreshError = error?.message ?? "Unknown refresh error";

            if (isRateLimitError(lastRefreshError)) {
              // Back off until daily quota is likely reset.
              refreshBlockedUntil = Date.now() + 24 * 60 * 60 * 1000;
            }

            throw error;
          })
          .finally(() => {
            refreshInFlight = null;
          });
      }

      await refreshInFlight.catch((error) => {
        console.error("[AbuseIPDB] On-demand refresh failed:", error);
      });

      latestSnapshot = readLatestBlacklistSnapshot();
    }

    if (latestSnapshot) {
      return res.json(latestSnapshot);
    }

    return res.json({
      generatedAt: null,
      count: 0,
      ips: [],
      warning: "Malicious IP data unavailable.",
      reason:
        !process.env.ABUSEIPDB_API_KEY
          ? "ABUSEIPDB_API_KEY is missing."
          : isRefreshBlocked
            ? "AbuseIPDB refresh temporarily blocked after rate limit. Try again after cooldown."
            : !ON_DEMAND_REFRESH_ENABLED
              ? "On-demand AbuseIPDB refresh is disabled. Enable ABUSEIPDB_ON_DEMAND_REFRESH=true if needed."
          : lastRefreshError ?? "Refresh has not succeeded yet. Check backend logs."
    });
  } catch {
    res.json({
      generatedAt: null,
      count: 0,
      ips: [],
      warning: "Malicious IP data unavailable.",
      reason: lastRefreshError ?? "Unexpected backend error. Check backend logs."
    });
  }
});

export default router;
