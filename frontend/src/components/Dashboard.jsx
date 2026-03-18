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
  createHoneypotStream,
  getHoneypotAttacks,
  getMaliciousIps,
  getRadarOrigins,
  getRadarSummary,
  getRadarTargets
} from "../api/dashboardApi";
import {
  formatAxisPercentage,
  formatCompactNumber,
  formatFullNumber,
  formatPercentage,
  formatPreciseTimestamp,
  formatTimeWindowLabel,
  truncateLabel
} from "../lib/formatters";
import ChartCard from "./ChartCard";
import GlobeCard from "./GlobeCard";
import LiveAttackFeedCard from "./LiveAttackFeedCard";

const RADAR_DATE_RANGE = "1d";
const RADAR_RANGE_LABEL = "Last 24 hours";
const HONEYPOT_FEED_LIMIT = 40;
const DEFAULT_HONEYPOT_MAP_WINDOW_MINUTES = 120;

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

function createHoneypotFeedData() {
  return {
    generatedAt: null,
    count: 0,
    target: null,
    startedAt: null,
    totalSinceStartup: 0,
    mapWindowMinutes: DEFAULT_HONEYPOT_MAP_WINDOW_MINUTES,
    mapAttackCount: 0,
    attacks: [],
    mapAttacks: []
  };
}

function sortAttacksByTimestamp(left, right) {
  return Date.parse(right?.timestamp ?? 0) - Date.parse(left?.timestamp ?? 0);
}

function mergeAttacksById(
  incomingAttacks,
  existingAttacks,
  { limit = Number.POSITIVE_INFINITY, maxAgeMinutes } = {}
) {
  const mergedById = new Map();

  for (const attack of incomingAttacks) {
    if (attack?.id) {
      mergedById.set(attack.id, attack);
    }
  }

  for (const attack of existingAttacks) {
    if (attack?.id && !mergedById.has(attack.id)) {
      mergedById.set(attack.id, attack);
    }
  }

  let mergedAttacks = Array.from(mergedById.values()).sort(sortAttacksByTimestamp);

  if (Number.isFinite(maxAgeMinutes)) {
    const cutoff = Date.now() - maxAgeMinutes * 60 * 1000;
    mergedAttacks = mergedAttacks.filter((attack) => Date.parse(attack?.timestamp ?? 0) >= cutoff);
  }

  if (Number.isFinite(limit)) {
    mergedAttacks = mergedAttacks.slice(0, limit);
  }

  return mergedAttacks;
}

function streamStatusLabel(status) {
  switch (status) {
    case "live":
      return "Live stream connected";
    case "polling":
      return "Polling fallback active";
    case "reconnecting":
      return "Stream reconnecting";
    default:
      return "Connecting to stream";
  }
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
  const [honeypotFeed, setHoneypotFeed] = useState({
    data: createHoneypotFeedData(),
    loading: true,
    error: null,
    streamStatus: "connecting"
  });
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

    getMaliciousIps({ signal: abortController.signal })
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
  }, []);

  useEffect(() => {
    const abortController = new AbortController();
    let isActive = true;
    let reconnectTimer = null;
    let eventSource = null;
    let pollingTimer = null;

    const mergeIncomingAttack = ({ attack, totalSinceStartup = null }) => {
      if (!attack?.id) {
        return;
      }

      setHoneypotFeed((current) => {
        const alreadyKnown =
          current.data.attacks.some((existingAttack) => existingAttack.id === attack.id) ||
          current.data.mapAttacks.some((existingAttack) => existingAttack.id === attack.id);
        const mapWindowMinutes =
          current.data.mapWindowMinutes ?? DEFAULT_HONEYPOT_MAP_WINDOW_MINUTES;
        const attacks = mergeAttacksById([attack], current.data.attacks, {
          limit: HONEYPOT_FEED_LIMIT
        });
        const mapAttacks = mergeAttacksById([attack], current.data.mapAttacks, {
          maxAgeMinutes: mapWindowMinutes
        });
        const isWithinMapWindow =
          Date.parse(attack.timestamp ?? 0) >= Date.now() - mapWindowMinutes * 60 * 1000;

        return {
          data: {
            ...current.data,
            generatedAt: new Date().toISOString(),
            count: attacks.length,
            totalSinceStartup:
              totalSinceStartup ?? current.data.totalSinceStartup + (alreadyKnown ? 0 : 1),
            mapAttackCount:
              current.data.mapAttackCount + (alreadyKnown || !isWithinMapWindow ? 0 : 1),
            target: attack.target ?? current.data.target ?? null,
            attacks,
            mapAttacks
          },
          loading: false,
          error: null,
          streamStatus: current.streamStatus
        };
      });
    };

    const loadRecentAttacks = async ({ preserveStreamStatus = true } = {}) => {
      try {
        const data = await getHoneypotAttacks(HONEYPOT_FEED_LIMIT, {
          signal: abortController.signal
        });
        if (!isActive) {
          return;
        }

        setHoneypotFeed((current) => ({
          data,
          loading: false,
          error: null,
          streamStatus: preserveStreamStatus ? current.streamStatus : "connecting"
        }));
      } catch (error) {
        if (!isActive || error.name === "AbortError") {
          return;
        }

        setHoneypotFeed((current) => ({
          data: current.data,
          loading: false,
          error: error.message,
          streamStatus: current.streamStatus === "live" ? "reconnecting" : current.streamStatus
        }));
      }
    };

    const scheduleReconnect = () => {
      if (!isActive || reconnectTimer !== null) {
        return;
      }

      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        loadRecentAttacks();
        connectStream();
      }, 5000);
    };

    const connectStream = () => {
      if (!isActive) {
        return;
      }

      if (typeof EventSource === "undefined") {
        setHoneypotFeed((current) => ({
          ...current,
          streamStatus: "polling"
        }));

        pollingTimer = window.setInterval(() => {
          loadRecentAttacks();
        }, 15000);
        return;
      }

      setHoneypotFeed((current) => ({
        ...current,
        streamStatus: current.data.attacks.length > 0 ? current.streamStatus : "connecting"
      }));

      eventSource = createHoneypotStream({
        onReady: (payload) => {
          if (!isActive) {
            return;
          }

          setHoneypotFeed((current) => ({
            ...current,
            data: {
              ...current.data,
              target: payload?.target ?? current.data.target,
              generatedAt: payload?.generatedAt ?? current.data.generatedAt,
              startedAt: payload?.startedAt ?? current.data.startedAt,
              totalSinceStartup: payload?.totalSinceStartup ?? current.data.totalSinceStartup,
              mapWindowMinutes: payload?.mapWindowMinutes ?? current.data.mapWindowMinutes
            },
            streamStatus: "live"
          }));
        },
        onAttack: (payload) => {
          if (!isActive) {
            return;
          }

          mergeIncomingAttack(payload);
          setHoneypotFeed((current) => ({
            ...current,
            streamStatus: "live"
          }));
        },
        onError: () => {
          if (!isActive) {
            return;
          }

          eventSource?.close();
          eventSource = null;
          setHoneypotFeed((current) => ({
            ...current,
            streamStatus: "reconnecting"
          }));
          scheduleReconnect();
        }
      });

      if (!eventSource) {
        setHoneypotFeed((current) => ({
          ...current,
          streamStatus: "polling"
        }));
      }
    };

    loadRecentAttacks({ preserveStreamStatus: false }).finally(() => {
      connectStream();
    });

    return () => {
      isActive = false;
      abortController.abort();
      if (eventSource) {
        eventSource.close();
      }
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      if (pollingTimer !== null) {
        window.clearInterval(pollingTimer);
      }
    };
  }, []);

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
      ["origins", getRadarOrigins(RADAR_DATE_RANGE, { signal: abortController.signal })],
      ["targets", getRadarTargets(RADAR_DATE_RANGE, { signal: abortController.signal })],
      [
        "methods",
        getRadarSummary("HTTP_METHOD", RADAR_DATE_RANGE, { signal: abortController.signal })
      ],
      [
        "industries",
        getRadarSummary("INDUSTRY", RADAR_DATE_RANGE, { signal: abortController.signal })
      ]
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
  }, []);

  const maliciousSnapshot = maliciousFeed.data ?? {
    generatedAt: null,
    count: 0,
    ips: []
  };

  const origins = radarFeeds.origins.data.slice(0, 8);
  const targets = radarFeeds.targets.data.slice(0, 8);
  const methods = radarFeeds.methods.data;
  const industries = radarFeeds.industries.data.slice(0, 8);

  return (
    <main className="app-shell">
      <div className="dashboard">
        <header className="dashboard__header panel" style={{ "--delay": "0ms" }}>
          <div className="dashboard__title-block">
            <span className="dashboard__eyebrow">Cyber attack monitoring</span>
            <h1 className="dashboard__title">Cyber Attack Dashboard</h1>
            <p className="dashboard__subtitle">
              Track hostile IP hotspots from AbuseIPDB alongside Cloudflare Radar attack
              distribution across origins, targets, HTTP methods, and industries, plus live
              Cowrie hits flowing into your India honeypot.
            </p>
          </div>
          <div className="dashboard__status-strip">
            <div className="status-pill status-pill--accent">
              <span className="status-pill__label">Attacks since backend start</span>
              <strong className="status-pill__value status-pill__value--primary">
                {formatFullNumber(honeypotFeed.data.totalSinceStartup)}
              </strong>
            </div>
            <div className="status-pill">
              <span className="status-pill__label">Backend started</span>
              <strong className="status-pill__value">
                {formatPreciseTimestamp(honeypotFeed.data.startedAt)}
              </strong>
            </div>
            <div className="status-pill">
              <span className="status-pill__label">Globe window</span>
              <strong className="status-pill__value">
                {formatTimeWindowLabel(honeypotFeed.data.mapWindowMinutes)}
              </strong>
            </div>
            <div className="status-pill">
              <span className="status-pill__label">Feed status</span>
              <strong className="status-pill__value">
                {streamStatusLabel(honeypotFeed.streamStatus)}
              </strong>
            </div>
          </div>
        </header>

        <GlobeCard
          style={{ "--delay": "140ms" }}
          loading={maliciousFeed.loading}
          error={maliciousFeed.error}
          points={maliciousSnapshot.ips}
          count={maliciousSnapshot.count}
          generatedAt={maliciousSnapshot.generatedAt}
          totalSinceStartup={honeypotFeed.data.totalSinceStartup}
          mapAttacks={honeypotFeed.data.mapAttacks}
          mapWindowMinutes={honeypotFeed.data.mapWindowMinutes}
          liveStatus={honeypotFeed.streamStatus}
        />

        <LiveAttackFeedCard
          style={{ "--delay": "180ms" }}
          status={honeypotFeed}
          meta={
            honeypotFeed.data.target?.label
              ? `${honeypotFeed.data.target.label} | ${formatCompactNumber(
                  honeypotFeed.data.count
                )} latest feed rows`
              : `${formatCompactNumber(honeypotFeed.data.count)} latest feed rows`
          }
        />

        <section className="dashboard__grid">
          <ChartCard
            title="Attack Origins"
            subtitle="Countries generating the highest share of observed L7 attack traffic."
            status={radarFeeds.origins}
            meta={`${RADAR_RANGE_LABEL} | Top 8`}
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
            meta={`${RADAR_RANGE_LABEL} | Top 8`}
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
            meta={RADAR_RANGE_LABEL}
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
            meta={`${RADAR_RANGE_LABEL} | Top 8`}
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
