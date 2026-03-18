import { Router } from "express";
import { readLatestBlacklistSnapshot } from "../services/abuseipdb.js";

const router = Router();

router.get("/api/malicious-ips", (req, res) => {
  try {
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
