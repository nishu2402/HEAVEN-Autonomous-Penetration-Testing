// HEAVEN — first-run guide
//
// A dismissible getting-started checklist on the Dashboard. Steps auto-check
// from real engagement state (scope targets / scans / findings), so a new
// operator always knows the next action and sees progress as they go. Hides
// itself once every step is done, or when dismissed (persisted in localStorage).

import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Engagement } from "../api";

const DISMISS_KEY = "heaven.firstrun.dismissed";

export default function FirstRunGuide() {
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem(DISMISS_KEY) === "1"; } catch { return false; }
  });
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (dismissed) return;
    Engagement.summary()
      .then((d) => setStats(d?.stats || {}))
      .catch(() => setStats({}));
  }, [dismissed]);

  if (dismissed || !stats) return null;

  const steps = [
    { done: (stats.scope_targets ?? 0) > 0, to: "/engagement",
      label: "Add an in-scope target", hint: "heaven scope add <target>" },
    { done: (stats.scans_run ?? 0) > 0, to: "/scans",
      label: "Run your first scan", hint: "Scans → Launch (or heaven scan -u …)" },
    { done: (stats.total_findings ?? 0) > 0, to: "/findings",
      label: "Review findings", hint: "Triage what HEAVEN found" },
    { done: (stats.total_findings ?? 0) > 0, to: "/reports",
      label: "Download a report", hint: "PDF / HTML / SARIF deliverable" },
  ];
  // Auto-hide once the core flow (scope → scan → findings) is complete.
  if (steps[0].done && steps[1].done && steps[2].done) return null;

  const completed = steps.filter((s) => s.done).length;

  function dismiss() {
    try { localStorage.setItem(DISMISS_KEY, "1"); } catch { /* ignore */ }
    setDismissed(true);
  }

  return (
    <div className="card" style={{ gridColumn: "1 / -1", padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div className="card-title" style={{ margin: 0 }}>
          🚀 Get started <span className="dim" style={{ fontWeight: 400 }}>· {completed}/{steps.length}</span>
        </div>
        <button className="btn-small" onClick={dismiss} title="Don't show this again">Dismiss</button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                    gap: 10, marginTop: 12 }}>
        {steps.map((s, i) => (
          <Link
            key={i}
            to={s.to}
            style={{
              display: "block", padding: "10px 12px", textDecoration: "none",
              borderRadius: "var(--radius-md)",
              border: `1px solid ${s.done ? "rgba(34,197,94,0.4)" : "var(--border)"}`,
              background: s.done ? "rgba(34,197,94,0.08)" : "rgba(255,255,255,0.02)",
            }}
          >
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-0)" }}>
              <span style={{ marginRight: 6 }}>{s.done ? "✅" : `${i + 1}.`}</span>{s.label}
            </div>
            <div className="dim" style={{ fontSize: 11, marginTop: 2 }}>{s.hint}</div>
          </Link>
        ))}
      </div>
    </div>
  );
}
