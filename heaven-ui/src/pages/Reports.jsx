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
import { Engagement, Engagements, downloadReport, previewReport, downloadSbom } from "../api";
import { useToast } from "../components/Toast.jsx";
import { SkeletonCard, EmptyState } from "../components/Skeleton.jsx";

// Secondary data exports (the headline professional report lives in the hero).
const FORMATS = [
  { id: "pdf", label: "PDF report", hint: "Needs reportlab" },
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
  // Engagement picker: when more than one engagement exists the operator must
  // be able to choose WHICH one to export, not just the active one.
  const [engList, setEngList] = useState([]);      // [{name, display_name, findings, scans, active}]
  const [selected, setSelected] = useState("");    // DB-stem name — the export selector
  const toast = useToast();

  useEffect(() => {
    Engagement.summary().then(setSummary).catch((e) => setError(e.message));
    Engagements.list()
      .then((r) => {
        const list = r?.engagements || [];
        setEngList(list);
        // Default the picker to the active engagement (or the richest one).
        const active = list.find((e) => e.active) || list[0];
        if (active) setSelected(active.name);
      })
      .catch(() => { /* picker is optional; active export still works */ });
  }, []);

  // Export the SELECTED engagement. We pass the engagement's DB-stem `name`
  // (from /api/engagements) — never a display name — because the server
  // resolves a name to a DB file, and the stem is the authoritative key.
  function engOpts() {
    return selected ? { engagement: selected } : {};
  }

  const selectedEntry = engList.find((e) => e.name === selected) || null;
  const isActiveSelected = !selectedEntry || selectedEntry.active;

  async function pick(fmt) {
    setBusy(fmt);
    try {
      const name = await downloadReport(fmt, engOpts());
      toast.success(`Downloaded ${name}`);
    } catch (e) {
      toast.error(e.message || "Export failed");
    } finally {
      setBusy("");
    }
  }

  async function preview() {
    setBusy("preview");
    try {
      await previewReport(engOpts());
      toast.info("Report opened in a new tab — use Print → Save as PDF for a PDF copy");
    } catch (e) {
      toast.error(e.message || "Preview failed");
    } finally {
      setBusy("");
    }
  }

  async function sbom() {
    setBusy("sbom");
    try {
      const name = await downloadSbom(engOpts());
      toast.success(`Downloaded ${name}`);
    } catch (e) {
      toast.error(e.message || "SBOM export failed");
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
  // Totals reflect the SELECTED engagement: the active one has a live severity
  // breakdown from the summary; any other engagement uses its list counts.
  const total = isActiveSelected ? (stats.total_findings ?? 0) : (selectedEntry?.findings ?? 0);
  const bySev = isActiveSelected ? (stats.by_severity || {}) : {};

  // Only show the "nothing to report" empty state when NO engagement anywhere
  // has findings — otherwise the operator can pick a populated one below.
  const anyFindings = total > 0 || engList.some((e) => (e.findings || 0) > 0);
  if (!anyFindings) {
    return (
      <div className="page">
        <EmptyState
          icon="📄"
          headline="No findings to report yet"
          body="Reports are generated from an engagement's findings. Run a scan first, then come back to export a deliverable in any format."
          cta="Launch a scan →"
          ctaTo="/scans"
        />
      </div>
    );
  }

  const selName = selectedEntry?.display_name || selectedEntry?.name || eng?.name || "engagement";

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>📄 Reports</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Generate a deliverable from the engagement selected below. Output is built
          live from that engagement's findings, so it always reflects current data.
        </p>

        {/* Engagement picker — surfaces only when there's more than one to choose. */}
        {engList.length > 1 && (
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
                        margin: "6px 0 4px" }}>
            <label htmlFor="report-eng" className="form-label" style={{ margin: 0 }}>
              Engagement to export
            </label>
            <select
              id="report-eng"
              className="form-select"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              style={{ maxWidth: 360, minWidth: 0 }}
            >
              {engList.map((e) => (
                <option key={e.name} value={e.name}>
                  {(e.display_name || e.name)}{e.active ? "  (active)" : ""} — {e.findings} finding{e.findings === 1 ? "" : "s"}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Live snapshot of what the report will contain */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 18, margin: "14px 0 6px" }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-0)" }}>{total}</div>
            <div className="dim" style={{ fontSize: 11 }}>total findings</div>
          </div>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-0)" }}>
              {isActiveSelected ? (stats.scope_targets ?? 0) : (selectedEntry?.scans ?? 0)}
            </div>
            <div className="dim" style={{ fontSize: 11 }}>
              {isActiveSelected ? "targets in scope" : "scans"}
            </div>
          </div>
          {isActiveSelected && ["critical", "high", "medium", "low", "info"].map((s) => (
            <div key={s}>
              <div style={{ fontSize: 22, fontWeight: 700, color: SEV_COLORS[s] }}>
                {bySev[s] ?? 0}
              </div>
              <div className="dim" style={{ fontSize: 11, textTransform: "capitalize" }}>{s}</div>
            </div>
          ))}
        </div>
        {!isActiveSelected && (
          <div className="dim" style={{ fontSize: 11 }}>
            Exporting <strong style={{ color: "var(--text-0)" }}>{selName}</strong> — switch it to
            active on the dashboard to see its full severity breakdown here.
          </div>
        )}
      </div>

      {/* Hero: the professional deliverable, one click */}
      <div className="card" style={{
        marginTop: 12, border: "1px solid var(--brand)",
        background: "linear-gradient(180deg, rgba(31,111,235,0.08), transparent)",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-0)" }}>
              📄 Professional penetration test report
            </div>
            <p className="dim" style={{ fontSize: 12, margin: "6px 0 0", lineHeight: 1.6 }}>
              A complete, client-ready deliverable: cover page, executive summary, scope &amp;
              methodology, risk ratings, detailed findings with evidence &amp; remediation, OWASP
              mapping and a prioritised roadmap. Print-ready — open it and use
              <strong style={{ color: "var(--text-0)" }}> Print → Save as PDF</strong>.
            </p>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <button
            onClick={() => pick("html")}
            disabled={!!busy}
            style={{
              flex: "1 1 220px", padding: "13px 18px", fontSize: 14, fontWeight: 700,
              background: "var(--brand)", color: "#fff", border: "none",
              borderRadius: "var(--radius-md)", cursor: busy ? "wait" : "pointer",
              fontFamily: "var(--font-ui)",
            }}
          >
            {busy === "html" ? "Preparing…" : "⬇  Download report (HTML)"}
          </button>
          <button
            onClick={preview}
            disabled={!!busy}
            style={{
              flex: "1 1 180px", padding: "13px 18px", fontSize: 14, fontWeight: 600,
              background: "rgba(255,255,255,0.04)", color: "var(--text-0)",
              border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
              cursor: busy ? "wait" : "pointer", fontFamily: "var(--font-ui)",
            }}
          >
            {busy === "preview" ? "Opening…" : "👁  Preview in browser"}
          </button>
          <button
            onClick={() => pick("pdf")}
            disabled={!!busy}
            style={{
              flex: "1 1 150px", padding: "13px 18px", fontSize: 14, fontWeight: 600,
              background: "rgba(255,255,255,0.04)", color: "var(--text-0)",
              border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
              cursor: busy ? "wait" : "pointer", fontFamily: "var(--font-ui)",
            }}
            title="Direct PDF export (requires the reportlab package on the server)"
          >
            {busy === "pdf" ? "Preparing…" : "⬇  Download PDF"}
          </button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
                      color: "var(--text-2)", fontWeight: 600, marginBottom: 10 }}>
          Other formats &amp; data exports
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
          <button
            onClick={sbom}
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
            title="CycloneDX SBOM — discovered services + CVE findings"
          >
            <span>
              <div style={{ fontSize: 13.5, fontWeight: 600 }}>SBOM (CycloneDX)</div>
              <div style={{ fontSize: 11, color: "var(--text-2)" }}>Services + CVEs, JSON</div>
            </span>
            <span style={{ fontSize: 12, color: "var(--text-2)" }}>
              {busy === "sbom" ? "…" : "↓"}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}
