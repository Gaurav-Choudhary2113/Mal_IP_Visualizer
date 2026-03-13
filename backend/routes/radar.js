import { Router } from "express";
import { fetchRadar } from "../services/radar.js";

const router = Router();

const VALID_DIMENSIONS = new Set([
  "HTTP_METHOD",
  "HTTP_VERSION",
  "IP_VERSION",
  "MANAGED_RULES",
  "MITIGATION_PRODUCT",
  "VERTICAL",
  "INDUSTRY"
]);

function parseTopLocations(data) {
  const rows = data?.result?.top_0 ?? [];
  return rows.map((r) => ({
    country: r.originCountryAlpha2 ?? r.targetCountryAlpha2 ?? r.clientCountryAlpha2,
    name: r.originCountryName ?? r.targetCountryName ?? r.clientCountryName,
    value: parseFloat(r.value),
    rank: r.rank
  }));
}

router.get("/api/radar/origins", async (req, res) => {
  try {
    const dateRange = req.query.dateRange ?? "1d";
    const data = await fetchRadar("/radar/attacks/layer7/top/locations/origin", { dateRange });
    res.json({ data: parseTopLocations(data) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/api/radar/targets", async (req, res) => {
  try {
    const dateRange = req.query.dateRange ?? "1d";
    const data = await fetchRadar("/radar/attacks/layer7/top/locations/target", { dateRange });
    res.json({ data: parseTopLocations(data) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// /api/radar/summary/INDUSTRY
// /api/radar/summary/HTTP_METHOD
// /api/radar/summary/IP_VERSION
// /api/radar/summary/MANAGED_RULES
// /api/radar/summary/MITIGATION_PRODUCT
// /api/radar/summary/VERTICAL
// /api/radar/summary/HTTP_VERSION
router.get("/api/radar/summary/:dimension", async (req, res) => {
  const { dimension } = req.params;

  if (!VALID_DIMENSIONS.has(dimension)) {
    return res.status(400).json({
      error: `Invalid dimension '${dimension}'. Must be one of: ${[...VALID_DIMENSIONS].join(", ")}`
    });
  }

  try {
    const dateRange = req.query.dateRange ?? "1d";
    const data = await fetchRadar(`/radar/attacks/layer7/summary/${dimension}`, { dateRange });
    res.json({ data: data?.result?.summary_0 ?? {} });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
