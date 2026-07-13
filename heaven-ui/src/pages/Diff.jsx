// HEAVEN — Scan Diff page
// Mirrors `heaven diff <baseline> <current>` from the CLI.

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Diff, Scans } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { EmptyState, SkeletonCard } from "../components/Skeleton.jsx";
import { sevColor } from "../theme";

export default function DiffPage() {
  const [scans, setScans] = useState([]);
  const [baseline, setBaseline] = useState("");
  const [current, setCurrent] = useState("");
  // Tracked globally so the diff result survives page navigation.
  const { loading, result: report, error: jobError, start } = useJob("diff");
  const [error, setError] = useState(null);   // scan-list load + pre-flight validation
  const navigate = useNavigate();

  useEffect(() => {
    Scans.list(50).then((d) => setScans(d.scans || [])).catch((e) => setError(e.message));
  }, []);

  function run() {
    setError(null);
    if (!baseline || !current) {
      setError("Pick both a baseline and a current scan.");
      return;
    }
    if (baseline === current) {
      setError("Baseline and current must be different scans.");
      return;
    }
    start({ label: "Scan diff", kind: "diff", path: "/diff" }, () => Diff.compute(current, baseline));
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--cyan)", marginTop: 0 }}>↹ Scan Diff</h2>
        <p className="page-lead">
          Compare two scans of the same engagement. Bucketed output: NEW · RESOLVED ·
          REGRESSED · UNCHANGED. <strong>Regressed</strong> = a finding that was marked
          <code> fixed</code> / <code>false_positive</code> / <code>accepted_risk</code>
          but was observed again in the current scan.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 10, marginBottom: 10, alignItems: "center" }}>
          <select className="form-select" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
            <option value="">— Baseline scan —</option>
            {scans.map((s) => {
              const id = s.scan_id || s.id;
              return (
                <option key={id} value={id}>
                  {id?.slice(0, 8)} · {s.mode || "?"} · {s.findings_count ?? 0} findings · {(s.started_at || "").slice(0, 16)}
                </option>
              );
            })}
          </select>
          <select className="form-select" value={current} onChange={(e) => setCurrent(e.target.value)}>
            <option value="">— Current scan —</option>
            {scans.map((s) => {
              const id = s.scan_id || s.id;
              return (
                <option key={id} value={id}>
                  {id?.slice(0, 8)} · {s.mode || "?"} · {s.findings_count ?? 0} findings · {(s.started_at || "").slice(0, 16)}
                </option>
              );
            })}
          </select>
          <button className="btn btn-primary" disabled={loading} onClick={run}>
            {loading ? "Diffing…" : "Compute diff"}
          </button>
        </div>

        {(error || jobError) && <div className="error">{error || jobError}</div>}
      </div>

      {scans.length < 2 && !report && !loading && (
        <EmptyState
          icon="↹"
          headline="Need at least two scans to compare"
          body="Scan diff buckets findings into new / resolved / regressed between two runs of the same engagement. Run a couple of scans first."
          cta="Launch a scan →"
          ctaTo="/scans"
        />
      )}

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>
      )}

      {report && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">Summary</div>
            <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
              <Stat label="🆕 New" value={report.summary.new}
                    color="var(--text-0)" sub={`${report.summary.critical_new} critical`} />
              <Stat label="✅ Resolved" value={report.summary.resolved} color="var(--cyan)" />
              <Stat label="⚠ Regressed" value={report.summary.regressed}
                    color="var(--crit)"
                    sub={`${report.summary.regressed_critical_or_high} crit/high`}
                    highlight={report.summary.regressed_critical_or_high > 0} />
              <Stat label="= Unchanged" value={report.summary.unchanged} color="var(--text-2)" />
            </div>
            {report.summary.regressed_critical_or_high > 0 && (
              <div style={{
                marginTop: 12, padding: 12, borderRadius: "var(--radius-md)",
                background: "rgba(255,77,106,0.08)",
                border: "1px solid rgba(255,77,106,0.32)",
                color: "var(--crit)", fontWeight: 600,
              }}>
                🚨 {report.summary.regressed_critical_or_high} previously-fixed critical/high finding(s) came back. Treat as P0.
              </div>
            )}
          </div>

          <FindingBucket title="🆕 New findings" rows={report.new} onOpen={navigate} />
          <FindingBucket title="⚠️ Regressed (closed → reopened)" rows={report.regressed} onOpen={navigate} />
          <FindingBucket title="✅ Resolved" rows={report.resolved} dim onOpen={navigate} />
        </>
      )}
    </div>
  );
}

function Stat({ label, value, color, sub, highlight }) {
  return (
    <div className={"mini-stat" + (highlight ? " is-alert" : "")}>
      <div className="mini-stat-label">{label}</div>
      <div className="mini-stat-value" style={{ color }}>{value}</div>
      {sub && <div className="mini-stat-sub">{sub}</div>}
    </div>
  );
}

function FindingBucket({ title, rows, dim, onOpen }) {
  if (!rows || rows.length === 0) return null;
  return (
    <div className="card" style={{ marginTop: 12, opacity: dim ? 0.85 : 1 }}>
      <div className="card-title">{title} ({rows.length})</div>
      <table className="data-table">
        <thead><tr>
          <th style={{ width: 60 }}>Sev</th>
          <th>Type</th>
          <th>Target</th>
          <th className="num" style={{ width: 60 }}>Conf</th>
        </tr></thead>
        <tbody>
          {rows.slice(0, 50).map((r) => (
            <tr key={r.id}
                className={r.id ? "is-clickable" : ""}
                onClick={r.id ? () => onOpen(`/findings/${r.id}`) : undefined}
                title={r.id ? "Open finding detail" : undefined}>
              <td style={{ color: sevColor(r.severity), fontWeight: 600 }}>{r.severity}</td>
              <td><code>{r.vuln_type}</code></td>
              <td style={{ wordBreak: "break-all" }}>{r.target}</td>
              <td className="num">{r.confidence?.toFixed?.(2) ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 50 && (
        <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
          … and {rows.length - 50} more
        </div>
      )}
    </div>
  );
}
