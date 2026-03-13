import { Router } from "express";
import {
  buildMaliciousRangeSnapshot,
  isSupportedMaliciousDateRange,
  readLatestBlacklistSnapshot
} from "../services/abuseipdb.js";

const router = Router();

router.get("/api/malicious-ips", (req, res) => {
  try {
    const { dateRange } = req.query;

    if (dateRange) {
      if (!isSupportedMaliciousDateRange(dateRange)) {
        return res.status(400).json({
          error: `Invalid dateRange '${dateRange}'. Must be one of: 1d, 7d`
        });
      }

      const rangedSnapshot = buildMaliciousRangeSnapshot(dateRange);
      if (!rangedSnapshot) {
        return res
          .status(503)
          .json({ error: "Malicious IP history is not yet available. Try again shortly." });
      }

      return res.json(rangedSnapshot);
    }

    const latestSnapshot = readLatestBlacklistSnapshot();
    if (!latestSnapshot) {
      return res
        .status(503)
        .json({ error: "Malicious IP data not yet available. Try again shortly." });
    }

    res.json(latestSnapshot);
  } catch {
    res.status(503).json({ error: "Malicious IP data not yet available. Try again shortly." });
  }
});

export default router;
