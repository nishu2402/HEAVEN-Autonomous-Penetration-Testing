// HEAVEN — Scan Diff page
// Mirrors `heaven diff <baseline> <current>` from the CLI.

import React, { useEffect, useState } from "react";
import { Diff, Scans } from "../api";

const SEV_COLOR = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--cyan)", info: "#888",
};

export default function DiffPage() {
  const [scans, setScans] = useState([]);
  const [baseline, setBaseline] = useState("");
  const [current, setCurrent] = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    Scans.list(50).then((d) => setScans(d.scans || [])).catch((e) => setError(e.message));
  }, []);

  async function run() {
    setError(null);
    setReport(null);
    if (!baseline || !current) {
      setError("Pick both a baseline and a current scan.");
      return;
    }
    if (baseline === current) {
      setError("Baseline and current must be different scans.");
      return;
    }
    setLoading(true);
    try {
      const r = await Diff.compute(current, baseline);
      setReport(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--cyan)", marginTop: 0 }}>↹ Scan Diff</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Compare two scans of the same engagement. Bucketed output: NEW · RESOLVED ·
          REGRESSED · UNCHANGED. <strong>Regressed</strong> = a finding that was marked
          <code> fixed</code> / <code>false_positive</code> / <code>accepted_risk</code>
          but was observed again in the current scan.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 8, marginBottom: 10 }}>
          <select value={baseline} onChange={(e) => setBaseline(e.target.value)}
                  style={{ fontSize: 12, padding: "6px 8px" }}>
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
          <select value={current} onChange={(e) => setCurrent(e.target.value)}
                  style={{ fontSize: 12, padding: "6px 8px" }}>
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
          <button className="btn" disabled={loading} onClick={run}>
            {loading ? "Diffing…" : "Compute diff"}
          </button>
        </div>

        {error && <div className="error">{error}</div>}
      </div>

      {report && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">Summary</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
              <Stat label="🆕 New" value={report.summary.new}
                    color="var(--text-0)" sub={`${report.summary.critical_new} critical`} />
              <Stat label="✅ Resolved" value={report.summary.resolved} color="var(--cyan)" />
              <Stat label="⚠ Regressed" value={report.summary.regressed}
                    color="var(--crit)"
                    sub={`${report.summary.regressed_critical_or_high} crit/high`}
                    highlight={report.summary.regressed_critical_or_high > 0} />
              <Stat label="= Unchanged" value={report.summary.unchanged} color="#888" />
            </div>
            {report.summary.regressed_critical_or_high > 0 && (
              <div style={{
                marginTop: 12, padding: 12,
                background: "rgba(255,7,58,0.07)",
                border: "1px solid rgba(255,7,58,0.3)",
                color: "var(--crit)", fontWeight: 600,
              }}>
                🚨 {report.summary.regressed_critical_or_high} previously-fixed critical/high finding(s) came back. Treat as P0.
              </div>
            )}
          </div>

          <FindingBucket title="🆕 New findings" rows={report.new} />
          <FindingBucket title="⚠️ Regressed (closed → reopened)" rows={report.regressed} />
          <FindingBucket title="✅ Resolved" rows={report.resolved} dim />
        </>
      )}
    </div>
  );
}

function Stat({ label, value, color, sub, highlight }) {
  return (
    <div style={{
      padding: 12,
      background: highlight ? "rgba(255,7,58,0.07)" : "rgba(0,0,0,0.3)",
      border: `1px solid ${color}33`,
    }}>
      <div className="dim" style={{ fontSize: 11 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
      {sub && <div className="dim" style={{ fontSize: 10, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function FindingBucket({ title, rows, dim }) {
  if (!rows || rows.length === 0) return null;
  return (
    <div className="card" style={{ marginTop: 12, opacity: dim ? 0.85 : 1 }}>
      <div className="card-title">{title} ({rows.length})</div>
      <table style={{ width: "100%", fontSize: 12 }}>
        <thead><tr style={{ color: "var(--cyan)" }}>
          <th align="left" style={{ width: 60 }}>Sev</th>
          <th align="left">Type</th>
          <th align="left">Target</th>
          <th align="right" style={{ width: 60 }}>Conf</th>
        </tr></thead>
        <tbody>
          {rows.slice(0, 50).map((r) => (
            <tr key={r.id}>
              <td><span style={{ color: SEV_COLOR[r.severity] || "#888" }}>
                {r.severity}
              </span></td>
              <td><code>{r.vuln_type}</code></td>
              <td style={{ wordBreak: "break-all" }}>{r.target}</td>
              <td align="right">{r.confidence?.toFixed?.(2) ?? "—"}</td>
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
