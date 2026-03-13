const DEFAULT_COPY = {
  loading: {
    code: "SYNC",
    title: "Loading feed",
    message: "Pulling telemetry from the backend."
  },
  error: {
    code: "WARN",
    title: "Feed unavailable",
    message: "This panel could not load its current dataset."
  },
  empty: {
    code: "NULL",
    title: "No data returned",
    message: "The API responded successfully, but there was nothing to visualize."
  }
};

export default function PanelState({ variant = "loading", title, message }) {
  const copy = DEFAULT_COPY[variant] ?? DEFAULT_COPY.loading;

  return (
    <div
      className={`panel-state panel-state--${variant}`}
      role={variant === "error" ? "alert" : "status"}
    >
      <span className="panel-state__code">{copy.code}</span>
      <h3 className="panel-state__title">{title ?? copy.title}</h3>
      <p className="panel-state__message">{message ?? copy.message}</p>
    </div>
  );
}
