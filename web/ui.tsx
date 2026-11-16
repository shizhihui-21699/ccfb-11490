import type { ReactNode } from 'react';

export function Chip({ tone, children }: { tone?: 'critical' | 'high' | 'medium' | 'info' | 'accent'; children: ReactNode }) {
  return <span className={`chip${tone ? ` ${tone}` : ''}`}>{children}</span>;
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export function Panel({
  title,
  actions,
  children,
  bodyClass,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  bodyClass?: string;
}) {
  return (
    <section className="panel">
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2 className="grow">{title}</h2>}
          {actions && <div className="row-wrap">{actions}</div>}
        </header>
      )}
      <div className={`panel-body${bodyClass ? ` ${bodyClass}` : ''}`}>{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="mono">{children}</span>;
}

export function Stat({ n, k }: { n: ReactNode; k: string }) {
  return (
    <div className="stat">
      <span className="n">{n}</span>
      <span className="k">{k}</span>
    </div>
  );
}
