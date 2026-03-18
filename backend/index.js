import "dotenv/config";
import express from "express";
import maliciousRouter from "./routes/malicious.js";
import radarRouter from "./routes/radar.js";
import { refreshBlacklist } from "./services/abuseipdb.js";

const app = express();
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10) || 3000;
const REFRESH_INTERVAL_MS =
  (Number.parseFloat(process.env.ABUSEIPDB_REFRESH_INTERVAL_HOURS ?? "24") || 24) *
  60 *
  60 *
  1000;
const allowedOrigins = (process.env.CORS_ORIGIN ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (allowedOrigins.includes("*") || allowedOrigins.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.get("/healthz", (req, res) => {
  res.status(200).json({ ok: true, uptimeSeconds: Math.round(process.uptime()) });
});

app.use(maliciousRouter);
app.use(radarRouter);

// Refresh malicious IP list on startup, then every 4 hours
if (process.env.ABUSEIPDB_API_KEY) {
  refreshBlacklist().catch((err) => console.error("[AbuseIPDB] Initial refresh failed:", err));

  const refreshTimer = setInterval(() => {
    refreshBlacklist().catch((err) => console.error("[AbuseIPDB] Refresh failed:", err));
  }, REFRESH_INTERVAL_MS);

  refreshTimer.unref?.();
} else {
  console.warn("[AbuseIPDB] API key missing. Blacklist refresh is disabled.");
}

app.listen(PORT, () => console.log(`[Server] Listening on port ${PORT}`));