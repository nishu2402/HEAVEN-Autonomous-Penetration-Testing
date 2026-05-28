// HEAVEN — Loading skeletons + empty-state component
//
// Replaces the "Loading..." text scattered across pages with proper
// shimmer placeholders, and the bare "no entries" text with a richer
// empty-state component (icon + headline + body + optional CTA).

import React from "react";
import { Link } from "react-router-dom";

// ── Skeleton primitives ──────────────────────────────────────────

export function SkeletonLine({ width = "100%", size = "md", ...rest }) {
  const cls = "skeleton skeleton-line" + (size === "lg" ? " lg" : size === "sm" ? " sm" : "");
  return <span className={cls} style={{ width }} {...rest} />;
}

export function SkeletonBlock({ height = 80, ...rest }) {
  return <span className="skeleton skeleton-block" style={{ height }} {...rest} />;
}

// ── Higher-level skeletons for common page layouts ───────────────

export function SkeletonStatGrid({ count = 4 }) {
  return (
    <div className="stat-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="stat-card">
          <SkeletonLine size="sm" width="40%" />
          <SkeletonLine size="lg" width="60%" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 8, cols = 5 }) {
  return (
    <table style={{ width: "100%" }}>
      <tbody>
        {Array.from({ length: rows }).map((_, r) => (
          <tr key={r}>
            {Array.from({ length: cols }).map((_, c) => (
              <td key={c} style={{ padding: "8px 4px" }}>
                <SkeletonLine width={c === 0 ? "60%" : "90%"} />
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function SkeletonCard({ lines = 4 }) {
  return (
    <div className="card">
      <SkeletonLine size="lg" width="35%" />
      <div style={{ height: 12 }} />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonLine
          key={i}
          width={`${[100, 92, 78, 88][i % 4]}%`}
        />
      ))}
    </div>
  );
}

// ── Empty state ──────────────────────────────────────────────────

export function EmptyState({
  icon = "📭",
  headline,
  body,
  cta,
  ctaTo,
  ctaOnClick,
}) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon">{icon}</div>
      {headline && <div className="empty-state-headline">{headline}</div>}
      {body && <div className="empty-state-body">{body}</div>}
      {cta && (
        ctaTo ? (
          <Link className="empty-state-cta" to={ctaTo}>{cta}</Link>
        ) : (
          <button className="empty-state-cta" onClick={ctaOnClick} type="button">
            {cta}
          </button>
        )
      )}
    </div>
  );
}
