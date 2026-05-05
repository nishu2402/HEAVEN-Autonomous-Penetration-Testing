import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Engagement } from "../api";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "open", "verified", "false_positive", "accepted_risk", "fixed"];

export default function Findings() {
  const [filters, setFilters] = useState({
    severity: "", status: "", target: "", min_confidence: "", limit: 200,
  });
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  function load() {
    setLoading(true);
    Engagement.findings(filters)
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  return (
    <div>
      <div className="card filters">
        <FilterSelect label="Severity" name="severity"
          options={SEVERITIES} value={filters.severity}
          onChange={(v) => setFilters({...filters, severity: v})} />
        <FilterSelect label="Status" name="status"
          options={STATUSES} value={filters.status}
          onChange={(v) => setFilters({...filters, status: v})} />
        <label>
          Target contains
          <input
            type="text"
            value={filters.target}
            onChange={(e) => setFilters({ ...filters, target: e.target.value })}
            placeholder="api.acme"
          />
        </label>
        <label>
          Min confidence
          <input
            type="number" min="0" max="1" step="0.05"
            value={filters.min_confidence}
            onChange={(e) => setFilters({ ...filters, min_confidence: e.target.value })}
          />
        </label>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? "Loading…" : "Apply"}
        </button>
      </div>

      {error && <div className="card error">{error}</div>}

      {data && (
        <div className="card">
          <h3>{data.count} finding(s)</h3>
          <table className="findings-table">
            <thead>
              <tr>
                <th>Sev</th>
                <th>Type</th>
                <th>Target</th>
                <th>Conf</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((f) => (
                <tr key={f.id}>
                  <td><span className={`sev-pill sev-${f.severity}`}>{f.severity}</span></td>
                  <td><code>{f.vuln_type}</code></td>
                  <td className="ellipsis" title={f.target}>{f.target}</td>
                  <td>{Number(f.confidence).toFixed(2)}</td>
                  <td><span className={`status-pill status-${f.status}`}>{f.status}</span></td>
                  <td className="dim">{(f.last_seen_at || "").slice(0, 10)}</td>
                  <td>
                    <Link to={`/findings/${f.id}`} className="btn-small">Open</Link>
                  </td>
                </tr>
              ))}
              {data.findings.length === 0 && (
                <tr><td colSpan="7" className="dim">No findings match filters.</td></tr>
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
    <label>
      {label}
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o} value={o}>{o || "any"}</option>
        ))}
      </select>
    </label>
  );
}
