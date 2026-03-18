import crypto from "crypto";
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { isDatabaseConfigured } from "../services/database.js";
import {
  getHoneypotFeedMetadata,
  ingestCowrieEvents,
  listRecentHoneypotAttacks,
  subscribeToHoneypotAttacks
} from "../services/honeypot.js";

const router = Router();

const ingestionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number.parseInt(process.env.HONEYPOT_INGEST_MAX_REQUESTS_PER_MINUTE ?? "600", 10) || 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many honeypot ingestion requests. Slow the forwarder down or batch events."
  }
});

function safeCompare(expectedValue, actualValue) {
  const expected = Buffer.from(expectedValue ?? "");
  const actual = Buffer.from(actualValue ?? "");

  if (expected.length === 0 || expected.length !== actual.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, actual);
}

function resolveIngestKey(request) {
  const authHeader = request.get("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice("Bearer ".length).trim();
  }

  return request.get("x-ingest-key")?.trim() ?? "";
}

function requireHoneypotAuth(request, response, next) {
  const expectedKey = process.env.HONEYPOT_INGEST_API_KEY?.trim();
  if (!expectedKey) {
    return response.status(503).json({
      error: "HONEYPOT_INGEST_API_KEY is not configured on the backend."
    });
  }

  const providedKey = resolveIngestKey(request);
  if (!safeCompare(expectedKey, providedKey)) {
    return response.status(401).json({ error: "Invalid honeypot ingest key." });
  }

  next();
}

router.post("/api/honeypot/events", ingestionLimiter, requireHoneypotAuth, async (req, res) => {
  try {
    if (!isDatabaseConfigured()) {
      return res.status(503).json({ error: "MONGODB_URI is not configured on the backend." });
    }

    const body = req.body;
    const events = Array.isArray(body?.events) ? body.events : Array.isArray(body) ? body : [body];

    if (!events.length || events.every((event) => !event || typeof event !== "object")) {
      return res.status(400).json({
        error: "Expected a JSON object or an { events: [...] } payload."
      });
    }

    const result = await ingestCowrieEvents(events);
    return res.status(202).json({
      ok: true,
      ...result
    });
  } catch (error) {
    console.error("[Honeypot] Event ingest failed:", error);
    return res.status(500).json({ error: "Failed to ingest honeypot events." });
  }
});

router.get("/api/honeypot/attacks", async (req, res) => {
  try {
    if (!isDatabaseConfigured()) {
      return res.status(503).json({ error: "MONGODB_URI is not configured on the backend." });
    }

    const attacks = await listRecentHoneypotAttacks(req.query.limit);
    return res.json({
      ...getHoneypotFeedMetadata(),
      count: attacks.length,
      attacks
    });
  } catch (error) {
    console.error("[Honeypot] Failed to list attacks:", error);
    return res.status(500).json({ error: "Unable to load recent honeypot attacks." });
  }
});

router.get("/api/honeypot/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const writeEvent = (eventName, payload) => {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };

  writeEvent("ready", getHoneypotFeedMetadata());

  const unsubscribe = subscribeToHoneypotAttacks((attack) => {
    writeEvent("attack", { attack });
  });

  const heartbeat = setInterval(() => {
    res.write(": keep-alive\n\n");
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
});

export default router;
