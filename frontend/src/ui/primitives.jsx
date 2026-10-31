// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Small shared UI primitives for the SOC design system.

export function Panel({ title, right, children, className = "", bodyClass = "", style }) {
  return (
    <section style={style} className={`panel flex flex-col min-h-0 ${className}`}>
      {(title || right) && (
        <header className="panel-head">
          <h2 className="panel-title">{title}</h2>
          {right}
        </header>
      )}
      <div className={`min-h-0 ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function SeverityTag({ level }) {
  const l = (level || "info").toLowerCase();
  return <span className={`sev sev-${l}`}>{l}</span>;
}

export function StatusDot({ state = "ok", label }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`dot dot-${state}`} />
      {label && <span className="text-xs text-muted">{label}</span>}
    </span>
  );
}

export function Chip({ children, className = "" }) {
  return <span className={`chip ${className}`}>{children}</span>;
}
