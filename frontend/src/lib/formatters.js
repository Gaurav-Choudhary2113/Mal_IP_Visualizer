const percentageFormatter = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 0,
  maximumFractionDigits: 1
});

const axisPercentageFormatter = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 0,
  maximumFractionDigits: 0
});

const compactNumberFormatter = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1
});

const timestampFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short"
});

const preciseTimestampFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "medium"
});

export function formatPercentage(value) {
  if (!Number.isFinite(value)) {
    return "--";
  }

  return `${percentageFormatter.format(value)}%`;
}

export function formatAxisPercentage(value) {
  if (!Number.isFinite(value)) {
    return "--";
  }

  return `${axisPercentageFormatter.format(value)}%`;
}

export function formatCompactNumber(value) {
  if (!Number.isFinite(value)) {
    return "--";
  }

  return compactNumberFormatter.format(value);
}

export function formatTimestamp(value) {
  if (!value) {
    return "Awaiting feed";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }

  return timestampFormatter.format(date);
}

export function formatPreciseTimestamp(value) {
  if (!value) {
    return "Awaiting feed";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }

  return preciseTimestampFormatter.format(date);
}

export function formatScore(value) {
  if (!Number.isFinite(value)) {
    return "--";
  }

  return `${Math.round(value)}/100`;
}

export function truncateLabel(value, maxLength = 18) {
  const text = String(value ?? "");

  if (text.length <= maxLength) {
    return text;
  }

  return `${text.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}
