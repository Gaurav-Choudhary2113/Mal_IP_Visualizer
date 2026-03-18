import { useEffect, useState } from "react";
import PanelState from "./PanelState";
import { formatPreciseTimestamp, truncateLabel } from "../lib/formatters";

const DEFAULT_VISIBLE_ATTACKS = 5;

function eventLabel(attack) {
  switch (attack?.eventId) {
    case "cowrie.login.success":
      return "Login Success";
    case "cowrie.login.failed":
      return "Login Failed";
    case "cowrie.command.input":
      return "Command Input";
    default:
      return "Attack Event";
  }
}

function eventDetail(attack) {
  if (attack?.command) {
    return attack.command;
  }

  if (attack?.username || attack?.password) {
    return `${attack.username ?? "unknown"} / ${attack.password ?? "unknown"}`;
  }

  return attack?.source?.ip ?? "Unknown source";
}

function streamLabel(status) {
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

export default function LiveAttackFeedCard({ status, meta, style }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const hasData = Array.isArray(status?.data?.attacks) && status.data.attacks.length > 0;
  const attacks = hasData ? status.data.attacks : [];
  const visibleAttacks = isExpanded ? attacks : attacks.slice(0, DEFAULT_VISIBLE_ATTACKS);
  const hiddenCount = Math.max(0, attacks.length - DEFAULT_VISIBLE_ATTACKS);

  useEffect(() => {
    if (attacks.length <= DEFAULT_VISIBLE_ATTACKS && isExpanded) {
      setIsExpanded(false);
    }
  }, [attacks.length, isExpanded]);

  let content;
  if (status?.loading && !hasData) {
    content = <PanelState variant="loading" message="Connecting to the live Cowrie attack feed." />;
  } else if (status?.error && !hasData) {
    content = <PanelState variant="error" message={status.error} />;
  } else if (!hasData) {
    content = (
      <PanelState
        variant="empty"
        message="No honeypot events have arrived yet. The stream is ready for new attacks."
      />
    );
  } else {
    content = (
      <div className="live-attack-card__content">
        <div className="live-attack-card__toolbar">
          <div className="chart-card__banner-row">
            <span className="panel-banner">{streamLabel(status.streamStatus)}</span>
            <span className="live-attack-card__count">
              Showing {visibleAttacks.length} of {attacks.length} latest feed rows
            </span>
          </div>
          {status.error ? <span className="panel-banner panel-banner--error">{status.error}</span> : null}
        </div>

        <div className="live-attack-table" role="table" aria-label="Recent honeypot attacks">
          <div className="live-attack-table__header" role="row">
            <span>Time</span>
            <span>Source</span>
            <span>Signal</span>
            <span>Details</span>
          </div>

          {visibleAttacks.map((attack) => {
            const sourceLocation = [attack?.source?.city, attack?.source?.country]
              .filter(Boolean)
              .join(", ");

            return (
              <div key={attack.id} className="live-attack-table__row" role="row">
                <span className="live-attack-table__time">
                  {formatPreciseTimestamp(attack.timestamp)}
                </span>
                <span className="live-attack-table__source">
                  <strong>{attack?.source?.ip ?? "Unknown IP"}</strong>
                  <small>{sourceLocation || "Location unavailable"}</small>
                </span>
                <span
                  className={`live-attack-table__event${
                    attack?.wasSuccessful === true
                      ? " is-success"
                      : attack?.wasSuccessful === false
                        ? " is-failure"
                        : " is-command"
                  }`}
                >
                  {eventLabel(attack)}
                </span>
                <span className="live-attack-table__detail" title={eventDetail(attack)}>
                  {truncateLabel(eventDetail(attack), 72)}
                </span>
              </div>
            );
          })}
        </div>

        {hiddenCount > 0 ? (
          <button
            type="button"
            className="live-attack-card__toggle"
            onClick={() => setIsExpanded((current) => !current)}
          >
            {isExpanded ? "Show fewer" : `View ${hiddenCount} more`}
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <section className="panel live-attack-card" style={style}>
      <header className="chart-card__header">
        <div>
          <span className="panel-kicker">Cowrie honeypot telemetry</span>
          <h2 className="chart-card__title">Live Attack Feed</h2>
          <p className="chart-card__subtitle">
            Real-time SSH login attempts and command activity forwarded from your honeypot.
          </p>
        </div>
        {meta ? <span className="panel-chip">{meta}</span> : null}
      </header>
      {content}
    </section>
  );
}
