import PanelState from "./PanelState";

export default function ChartCard({
  title,
  subtitle,
  status,
  meta,
  accent = "rose",
  style,
  children
}) {
  const hasData = Array.isArray(status?.data) && status.data.length > 0;

  let content;
  if (status?.loading && !hasData) {
    content = <PanelState variant="loading" message="Querying Cloudflare Radar." />;
  } else if (status?.error && !hasData) {
    content = <PanelState variant="error" message={status.error} />;
  } else if (!hasData) {
    content = <PanelState variant="empty" message="This feed returned no chartable rows." />;
  } else {
    content = (
      <div className="chart-card__content">
        <div className="chart-card__banner-row">
          {status.loading ? <span className="panel-banner">Refreshing feed...</span> : null}
          {status.error ? (
            <span className="panel-banner panel-banner--error">
              Showing last good snapshot: {status.error}
            </span>
          ) : null}
        </div>
        <div className="chart-card__visual">{children}</div>
      </div>
    );
  }

  return (
    <section className={`panel chart-card chart-card--${accent}`} style={style}>
      <header className="chart-card__header">
        <div>
          <span className="panel-kicker">Cloudflare Radar</span>
          <h2 className="chart-card__title">{title}</h2>
          <p className="chart-card__subtitle">{subtitle}</p>
        </div>
        {meta ? <span className="panel-chip">{meta}</span> : null}
      </header>
      {content}
    </section>
  );
}
