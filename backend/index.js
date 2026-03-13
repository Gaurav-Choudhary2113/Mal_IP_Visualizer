import "dotenv/config";
import express from "express";
import maliciousRouter from "./routes/malicious.js";
import radarRouter from "./routes/radar.js";
import { refreshBlacklist } from "./services/abuseipdb.js";

const app = express();

app.use(maliciousRouter);
app.use(radarRouter);

// Refresh malicious IP list on startup, then every 4 hours
refreshBlacklist().catch((err) => console.error("[AbuseIPDB] Initial refresh failed:", err));
setInterval(() => {
  refreshBlacklist().catch((err) => console.error("[AbuseIPDB] Refresh failed:", err));
}, 4 * 60 * 60 * 1000);

app.listen(3000, () => console.log("Server running on http://localhost:3000"));