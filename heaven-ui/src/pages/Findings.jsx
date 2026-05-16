import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Engagement } from "../api";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES   = ["", "open", "verified", "false_positive", "accepted_risk", "fixed"];
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Findings() {
  const [filters, setFilters] = useState({
    severity: "", status: "open", target: "", min_confidence: "", limit: 500,
  });
  const [data, setData]     = useState(null);
  const [error, setError]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [sort, setSort]     = useState({ col: "severity", dir: 1 });

  const load = useCallback(() => {
    setLoading(true);
    Engagement.findings(filters)
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [filters]);

  useEffect(() => { load(); }, []);

  const toggleSort = (col) => {
    setSort(s => ({ col, dir: s.col === col ? -s.dir : 1 }));
  };

  const sortedFindings = data?.findings ? [...data.findings].sort((a, b) => {
    if (sort.col === "severity") {
      return sort.dir * ((SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
    }
    if (sort.col === "confidence") {
      return sort.dir * (Number(b.confidence) - Number(a.confidence));
    }
    return sort.dir * String(a[sort.col] || "").localeCompare(String(b[sort.col] || ""));
  }) : [];

  function SortTh({ col, children }) {
    const active = sort.col === col;
    return (
      <th onClick={() => toggleSort(col)} style={{ cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }}>
        {children}{active ? (sort.dir > 0 ? " ↑" : " ↓") : ""}
      </th>
    );
  }

  const noEng = data?.no_engagement;

  return (
    <div className="page">
      {/* Filters */}
      <div className="card filters">
        <FilterSelect label="Severity" options={SEVERITIES} value={filters.severity}
          onChange={(v) => setFilters(f => ({ ...f, severity: v }))} />
        <FilterSelect label="Status" options={STATUSES} value={filters.status}
          onChange={(v) => setFilters(f => ({ ...f, status: v }))} />
        <label className="form-group">
          <span className="form-label">Target contains</span>
          <input className="form-input" type="text" value={filters.target}
            placeholder="api.acme"
            onChange={(e) => setFilters(f => ({ ...f, target: e.target.value }))} />
        </label>
        <label className="form-group">
          <span className="form-label">Min confidence</span>
          <input className="form-input" type="number" min="0" max="1" step="0.05"
            value={filters.min_confidence}
            onChange={(e) => setFilters(f => ({ ...f, min_confidence: e.target.value }))} />
        </label>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? "..." : "Apply"}
        </button>
      </div>

      {error && <div className="card error">{error}</div>}

      {noEng && (
        <div className="onboarding-banner">
          <div className="onboarding-icon">⚠</div>
          <div>
            <div className="onboarding-title">No Active Engagement</div>
            <div className="onboarding-body">
              Set <code>HEAVEN_ENGAGEMENT</code> and restart the server to load findings.
              <br/>Run a scan first: <code>heaven scan -u https://target --i-have-authorization</code>
            </div>
          </div>
        </div>
      )}

      {data && !noEng && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {data.count} finding{data.count !== 1 ? "s" : ""}
            </div>
            <div style={{ fontSize: 11, color: "rgba(0,255,65,0.62)" }}>
              Click column headers to sort
            </div>
          </div>
          <table className="findings-table">
            <thead>
              <tr>
                <SortTh col="severity">Sev</SortTh>
                <SortTh col="vuln_type">Type</SortTh>
                <SortTh col="target">Target</SortTh>
                <SortTh col="confidence">Conf</SortTh>
                <SortTh col="status">Status</SortTh>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((f) => (
                <tr key={f.id} className="animate-in">
                  <td><span className={`sev-pill sev-${f.severity}`}>{f.severity}</span></td>
                  <td><code style={{ fontSize: 11 }}>{f.vuln_type}</code></td>
                  <td className="ellipsis" title={f.target}>{f.target}</td>
                  <td>
                    <span style={{
                      color: Number(f.confidence) >= 0.9 ? '#00FF41'
                           : Number(f.confidence) >= 0.7 ? '#FFB800' : '#FF6B00',
                    }}>
                      {Number(f.confidence).toFixed(2)}
                    </span>
                  </td>
                  <td><span className={`status-pill status-${f.status}`}>{f.status}</span></td>
                  <td className="dim">{(f.last_seen_at || "").slice(0, 10)}</td>
                  <td><Link to={`/findings/${f.id}`} className="btn-small">Detail</Link></td>
                </tr>
              ))}
              {sortedFindings.length === 0 && (
                <tr><td colSpan="7">
                  <div className="info-state">
                    <div>No findings match the current filters</div>
                  </div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FilterSelect({ label, options, value, onChange }) {
  return (
    <label className="form-group">
      <span className="form-label">{label}</span>
      <select className="form-select" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o} value={o}>{o || "any"}</option>
        ))}
      </select>
    </label>
  );
}
