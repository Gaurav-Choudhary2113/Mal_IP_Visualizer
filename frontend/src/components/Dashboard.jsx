import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import {
  getMaliciousIps,
  getRadarOrigins,
  getRadarSummary,
  getRadarTargets
} from "../api/dashboardApi";
import {
  formatAxisPercentage,
  formatCompactNumber,
  formatPercentage,
  formatTimestamp,
  truncateLabel
} from "../lib/formatters";
import ChartCard from "./ChartCard";
import DateRangeToggle from "./DateRangeToggle";
import GlobeCard from "./GlobeCard";

const RANGE_LABELS = {
  "1d": "Last 24 hours",
  "7d": "Last 7 days"
};

const ORIGIN_COLORS = [
  "#ff5f77",
  "#ff7567",
  "#ff8d5d",
  "#ffaa63",
  "#ffca7a",
  "#ffd98d",
  "#ffe7a5",
  "#fff3c8"
];

const TARGET_COLORS = [
  "#33d9ff",
  "#2bc5ff",
  "#28b1ff",
  "#289dfb",
  "#3f8ff4",
  "#597fd8",
  "#6f75c7",
  "#8770b4"
];

const METHOD_COLORS = ["#ffe073", "#ffab57", "#ff6d69", "#ff4d6d", "#7b8bff", "#41d9ff"];

const INDUSTRY_COLORS = [
  "#71f5c8",
  "#53dfd1",
  "#3cc8d7",
  "#35b2d9",
  "#3d9bdd",
  "#4687dd",
  "#506fda",
  "#5d5ed1"
];

function createSectionState(data = []) {
  return {
    data,
    loading: true,
    error: null
  };
}

function CustomChartTooltip({ active, payload }) {
  if (!active || !payload?.length) {
    return null;
  }

  const point = payload[0].payload;

  return (
    <div className="dashboard-tooltip">
      <span className="dashboard-tooltip__eyebrow">Radar share</span>
      <strong>{point.label}</strong>
      <span>{formatPercentage(point.value)}</span>
      {point.code && point.code !== "--" ? <span>Country code {point.code}</span> : null}
    </div>
  );
}

export default function Dashboard() {
  const [dateRange, setDateRange] = useState("1d");
  const [maliciousFeed, setMaliciousFeed] = useState({
    data: null,
    loading: true,
    error: null
  });
  const [radarFeeds, setRadarFeeds] = useState({
    origins: createSectionState(),
    targets: createSectionState(),
    methods: createSectionState(),
    industries: createSectionState()
  });

  useEffect(() => {
    const abortController = new AbortController();
    let isActive = true;

    setMaliciousFeed((current) => ({
      ...current,
      loading: true,
      error: null
    }));

    getMaliciousIps(dateRange, { signal: abortController.signal })
      .then((data) => {
        if (!isActive) {
          return;
        }

        setMaliciousFeed({
          data,
          loading: false,
          error: null
        });
      })
      .catch((error) => {
        if (!isActive || error.name === "AbortError") {
          return;
        }

        setMaliciousFeed((current) => ({
          data: current.data,
          loading: false,
          error: error.message
        }));
      });

    return () => {
      isActive = false;
      abortController.abort();
    };
  }, [dateRange]);

  useEffect(() => {
    const abortController = new AbortController();
    let isActive = true;

    setRadarFeeds((current) => ({
      origins: { ...current.origins, loading: true, error: null },
      targets: { ...current.targets, loading: true, error: null },
      methods: { ...current.methods, loading: true, error: null },
      industries: { ...current.industries, loading: true, error: null }
    }));

    const requests = [
      ["origins", getRadarOrigins(dateRange, { signal: abortController.signal })],
      ["targets", getRadarTargets(dateRange, { signal: abortController.signal })],
      ["methods", getRadarSummary("HTTP_METHOD", dateRange, { signal: abortController.signal })],
      ["industries", getRadarSummary("INDUSTRY", dateRange, { signal: abortController.signal })]
    ];

    Promise.allSettled(requests.map(([, promise]) => promise)).then((results) => {
      if (!isActive) {
        return;
      }

      setRadarFeeds((current) => {
        const nextState = { ...current };

        results.forEach((result, index) => {
          const [key] = requests[index];

          if (result.status === "fulfilled") {
            nextState[key] = {
              data: result.value,
              loading: false,
              error: null
            };
            return;
          }

          if (result.reason?.name === "AbortError") {
            return;
          }

          nextState[key] = {
            data: current[key].data,
            loading: false,
            error: result.reason?.message ?? "Unable to load this feed."
          };
        });

        return nextState;
      });
    });

    return () => {
      isActive = false;
      abortController.abort();
    };
  }, [dateRange]);

  const maliciousSnapshot = maliciousFeed.data ?? {
    generatedAt: null,
    count: 0,
    ips: []
  };

  const origins = radarFeeds.origins.data.slice(0, 8);
  const targets = radarFeeds.targets.data.slice(0, 8);
  const methods = radarFeeds.methods.data;
  const industries = radarFeeds.industries.data.slice(0, 8);
  const onlineFeedCount = [radarFeeds.origins, radarFeeds.targets, radarFeeds.methods, radarFeeds.industries]
    .filter((feed) => feed.data.length > 0 && !feed.error)
    .length;

  return (
    <main className="app-shell">
      <div className="dashboard">
        <header className="dashboard__header panel" style={{ "--delay": "0ms" }}>
          <div className="dashboard__title-block">
            <span className="dashboard__eyebrow">Cyber attack monitoring</span>
            <h1 className="dashboard__title">Cyber Attack Dashboard</h1>
            <p className="dashboard__subtitle">
              Track hostile IP hotspots from AbuseIPDB alongside Cloudflare Radar attack
              distribution across origins, targets, HTTP methods, and industries.
            </p>
          </div>

          <div className="dashboard__controls">
            <span className="dashboard__control-label">Radar range</span>
            <DateRangeToggle value={dateRange} onChange={setDateRange} />
          </div>
        </header>

        <section className="panel dashboard__status-strip" style={{ "--delay": "80ms" }}>
          <div className="status-pill">
            <span className="status-pill__label">Blacklist nodes</span>
            <strong className="status-pill__value">
              {formatCompactNumber(maliciousSnapshot.count)}
            </strong>
          </div>
          <div className="status-pill">
            <span className="status-pill__label">Snapshot</span>
            <strong className="status-pill__value">
              {formatTimestamp(maliciousSnapshot.generatedAt)}
            </strong>
          </div>
          <div className="status-pill">
            <span className="status-pill__label">Radar window</span>
            <strong className="status-pill__value">{RANGE_LABELS[dateRange]}</strong>
          </div>
          <div className="status-pill">
            <span className="status-pill__label">Chart feeds online</span>
            <strong className="status-pill__value">{onlineFeedCount}/4</strong>
          </div>
        </section>

        <GlobeCard
          style={{ "--delay": "140ms" }}
          loading={maliciousFeed.loading}
          error={maliciousFeed.error}
          points={maliciousSnapshot.ips}
          count={maliciousSnapshot.count}
          generatedAt={maliciousSnapshot.generatedAt}
        />

        <section className="dashboard__grid">
          <ChartCard
            title="Attack Origins"
            subtitle="Countries generating the highest share of observed L7 attack traffic."
            status={radarFeeds.origins}
            meta={`${RANGE_LABELS[dateRange]} | Top 8`}
            accent="rose"
            style={{ "--delay": "220ms" }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={origins}
                layout="vertical"
                margin={{ top: 10, right: 8, left: 0, bottom: 8 }}
              >
                <CartesianGrid
                  stroke="rgba(184, 197, 224, 0.08)"
                  strokeDasharray="3 3"
                  horizontal
                  vertical={false}
                />
                <XAxis
                  type="number"
                  tickFormatter={formatAxisPercentage}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#9aabc6", fontSize: 12 }}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={110}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#eef3ff", fontSize: 12 }}
                  tickFormatter={(value) => truncateLabel(value, 14)}
                />
                <Tooltip
                  cursor={{ fill: "rgba(255, 255, 255, 0.04)" }}
                  content={<CustomChartTooltip />}
                />
                <Bar dataKey="value" radius={[0, 10, 10, 0]} barSize={16}>
                  {origins.map((entry, index) => (
                    <Cell
                      key={`${entry.code}-${entry.label}`}
                      fill={ORIGIN_COLORS[index % ORIGIN_COLORS.length]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard
            title="Attack Targets"
            subtitle="Countries receiving the largest share of layer 7 attack traffic."
            status={radarFeeds.targets}
            meta={`${RANGE_LABELS[dateRange]} | Top 8`}
            accent="cyan"
            style={{ "--delay": "280ms" }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={targets}
                layout="vertical"
                margin={{ top: 10, right: 8, left: 0, bottom: 8 }}
              >
                <CartesianGrid
                  stroke="rgba(184, 197, 224, 0.08)"
                  strokeDasharray="3 3"
                  horizontal
                  vertical={false}
                />
                <XAxis
                  type="number"
                  tickFormatter={formatAxisPercentage}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#9aabc6", fontSize: 12 }}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={110}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#eef3ff", fontSize: 12 }}
                  tickFormatter={(value) => truncateLabel(value, 14)}
                />
                <Tooltip
                  cursor={{ fill: "rgba(255, 255, 255, 0.04)" }}
                  content={<CustomChartTooltip />}
                />
                <Bar dataKey="value" radius={[0, 10, 10, 0]} barSize={16}>
                  {targets.map((entry, index) => (
                    <Cell
                      key={`${entry.code}-${entry.label}`}
                      fill={TARGET_COLORS[index % TARGET_COLORS.length]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard
            title="HTTP Methods"
            subtitle="Method distribution associated with attack traffic across the selected range."
            status={radarFeeds.methods}
            meta={RANGE_LABELS[dateRange]}
            accent="amber"
            style={{ "--delay": "340ms" }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={methods} margin={{ top: 10, right: 8, left: -12, bottom: 8 }}>
                <CartesianGrid
                  stroke="rgba(184, 197, 224, 0.08)"
                  strokeDasharray="3 3"
                  horizontal
                  vertical={false}
                />
                <XAxis
                  dataKey="label"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#eef3ff", fontSize: 12 }}
                />
                <YAxis
                  tickFormatter={formatAxisPercentage}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#9aabc6", fontSize: 12 }}
                />
                <Tooltip
                  cursor={{ fill: "rgba(255, 255, 255, 0.04)" }}
                  content={<CustomChartTooltip />}
                />
                <Bar dataKey="value" radius={[12, 12, 0, 0]} barSize={32}>
                  {methods.map((entry, index) => (
                    <Cell key={entry.label} fill={METHOD_COLORS[index % METHOD_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard
            title="Attack Industries"
            subtitle="Industry sectors receiving the highest share of attack activity."
            status={radarFeeds.industries}
            meta={`${RANGE_LABELS[dateRange]} | Top 8`}
            accent="mint"
            style={{ "--delay": "400ms" }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={industries}
                layout="vertical"
                margin={{ top: 10, right: 8, left: 0, bottom: 8 }}
              >
                <CartesianGrid
                  stroke="rgba(184, 197, 224, 0.08)"
                  strokeDasharray="3 3"
                  horizontal
                  vertical={false}
                />
                <XAxis
                  type="number"
                  tickFormatter={formatAxisPercentage}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#9aabc6", fontSize: 12 }}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={132}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "#eef3ff", fontSize: 12 }}
                  tickFormatter={(value) => truncateLabel(value, 18)}
                />
                <Tooltip
                  cursor={{ fill: "rgba(255, 255, 255, 0.04)" }}
                  content={<CustomChartTooltip />}
                />
                <Bar dataKey="value" radius={[0, 10, 10, 0]} barSize={16}>
                  {industries.map((entry, index) => (
                    <Cell key={entry.label} fill={INDUSTRY_COLORS[index % INDUSTRY_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
        </section>
      </div>
    </main>
  );
}
