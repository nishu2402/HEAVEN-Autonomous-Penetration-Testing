// HEAVEN — Reports page
//
// A first-class home for the deliverable export under the "Reporting" nav group.
// Previously the download menu was buried on the Findings page, so navigating to
// "Reporting" surfaced only Tickets/Benchmark/Methodology and operators couldn't
// find where to generate the actual report.
//
// The report is generated dynamically from the ACTIVE engagement's findings via
// GET /api/report/export (every standard format). The page shows a live summary
// of what will be in the report so it's clear the output reflects current data.

import React, { useEffect, useState } from "react";
import { Engagement, downloadReport } from "../api";
import { useToast } from "../components/Toast.jsx";
import { SkeletonCard, EmptyState } from "../components/Skeleton.jsx";

const FORMATS = [
  { id: "pdf", label: "PDF report", hint: "Client deliverable" },
  { id: "html", label: "HTML report", hint: "Compliance-mapped, shareable" },
  { id: "markdown", label: "Markdown", hint: "Wiki / Git" },
  { id: "csv", label: "CSV", hint: "Spreadsheet / triage" },
  { id: "json", label: "JSON", hint: "Automation / re-import" },
  { id: "sarif", label: "SARIF", hint: "GitHub code scanning" },
  { id: "burp", label: "Burp XML", hint: "Burp Suite import" },
  { id: "proxy-jsonl", label: "Proxy JSONL", hint: "Replay / pipelines" },
];

const SEV_COLORS = {
  critical: "var(--crit)",
  high: "#ff8a3d",
  medium: "#ffd24d",
  low: "var(--cyan)",
  info: "var(--text-2)",
};

export default function Reports() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState("");
  const toast = useToast();

  useEffect(() => {
    Engagement.summary()
      .then(setSummary)
      .catch((e) => setError(e.message));
  }, []);

  async function pick(fmt) {
    setBusy(fmt);
    try {
      const eng = summary?.engagement?.name;
      const name = await downloadReport(fmt, eng ? { engagement: eng } : {});
      toast.success(`Downloaded ${name}`);
    } catch (e) {
      toast.error(e.message || "Export failed");
    } finally {
      setBusy("");
    }
  }

  if (error) {
    return (
      <div className="page">
        <div className="card error">Failed to load engagement: {error}</div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="page">
        <SkeletonCard lines={6} />
      </div>
    );
  }

  const stats = summary.stats || {};
  const eng = summary.engagement;
  const total = stats.total_findings ?? 0;
  const bySev = stats.by_severity || {};

  // No engagement / nothing to report yet → actionable empty state.
  if (summary.no_engagement || total === 0) {
    return (
      <div className="page">
        <EmptyState
          icon="📄"
          headline="No findings to report yet"
          body="Reports are generated from the active engagement's findings. Run a scan first, then come back to export a deliverable in any format."
          cta="Launch a scan →"
          ctaTo="/scans"
        />
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>📄 Reports</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Generate a deliverable from the active engagement
          {eng?.name ? <> — <strong style={{ color: "var(--text-0)" }}>{eng.name}</strong></> : null}.
          Output is built live from the findings below, so it always reflects the
          current state of the engagement.
        </p>

        {/* Live snapshot of what the report will contain */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 18, margin: "14px 0 6px" }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-0)" }}>{total}</div>
            <div className="dim" style={{ fontSize: 11 }}>total findings</div>
          </div>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-0)" }}>
              {stats.scope_targets ?? 0}
            </div>
            <div className="dim" style={{ fontSize: 11 }}>targets in scope</div>
          </div>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <div key={s}>
              <div style={{ fontSize: 22, fontWeight: 700, color: SEV_COLORS[s] }}>
                {bySev[s] ?? 0}
              </div>
              <div className="dim" style={{ fontSize: 11, textTransform: "capitalize" }}>{s}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
                      color: "var(--text-2)", fontWeight: 600, marginBottom: 10 }}>
          Choose a format to download
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                      gap: 10 }}>
          {FORMATS.map((f) => (
            <button
              key={f.id}
              onClick={() => pick(f.id)}
              disabled={!!busy}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                textAlign: "left", gap: 10, padding: "12px 14px",
                background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)", color: "var(--text-0)",
                cursor: busy ? "wait" : "pointer", fontFamily: "var(--font-ui)",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--brand)")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            >
              <span>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>{f.label}</div>
                <div style={{ fontSize: 11, color: "var(--text-2)" }}>{f.hint}</div>
              </span>
              <span style={{ fontSize: 12, color: "var(--text-2)" }}>
                {busy === f.id ? "…" : "↓"}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
