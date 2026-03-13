const OPTIONS = [
  { value: "1d", label: "1D", hint: "Last 24 hours" },
  { value: "7d", label: "7D", hint: "Last 7 days" }
];

export default function DateRangeToggle({ value, onChange }) {
  return (
    <div className="range-toggle" role="group" aria-label="Radar date range">
      {OPTIONS.map((option) => {
        const isActive = option.value === value;

        return (
          <button
            key={option.value}
            type="button"
            className={`range-toggle__button${isActive ? " is-active" : ""}`}
            aria-pressed={isActive}
            onClick={() => onChange(option.value)}
          >
            <span className="range-toggle__label">{option.label}</span>
            <span className="range-toggle__hint">{option.hint}</span>
          </button>
        );
      })}
    </div>
  );
}
