import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Engagement } from "../api";
import ReportMenu from "../components/ReportMenu.jsx";
import { EmptyState, SkeletonTable } from "../components/Skeleton.jsx";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES   = ["", "open", "verified", "false_positive", "accepted_risk", "fixed"];
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_LIST   = ["critical", "high", "medium", "low", "info"];

// Reduce any target (URL, host:port, bare IP) to the bare host/IP so every
// finding on one machine groups under a single heading — mirrors the backend's
// inventory.host_key so the Findings grouping and the Assets inventory agree on
// what "one host" means.
function hostOf(target) {
  let t = String(target || "").trim();
  if (!t) return "(unspecified)";
  if (t.includes("://")) {
    try { t = new URL(t).hostname || t; }
    catch { t = t.split("://")[1] || t; }
  }
  t = t.split("/")[0];              // drop any path
  if (t.startsWith("[")) return t.toLowerCase();   // keep IPv6 literal intact
  if ((t.match(/:/g) || []).length === 1) t = t.split(":")[0];  // strip :port
  return t.toLowerCase();
}

// Per-severity counts for a host's findings, highest severity first.
function sevSummary(rows) {
  const c = {};
  for (const r of rows) c[r.severity] = (c[r.severity] || 0) + 1;
  return SEV_LIST.filter((s) => c[s]).map((s) => ({ sev: s, n: c[s] }));
}

export default function Findings() {
  const [filters, setFilters] = useState({
    severity: "", status: "open", target: "", min_confidence: "", limit: 500,
  });
  const [data, setData]     = useState(null);
  const [error, setError]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [sort, setSort]     = useState({ col: "severity", dir: 1 });
  const [groupByHost, setGroupByHost] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    Engagement.findings(filters)
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [filters]);

  // Auto-apply on filter change (debounced). Enter and the Apply button fire it
  // immediately. Also runs once on mount (load is stable until filters change).
  useEffect(() => {
    const t = setTimeout(load, 350);
    return () => clearTimeout(t);
  }, [load]);

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
    const ariaSort = active ? (sort.dir > 0 ? "ascending" : "descending") : "none";
    return (
      <th
        role="button"
        tabIndex={0}
        aria-sort={ariaSort}
        onClick={() => toggleSort(col)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleSort(col); }
        }}
        style={{ cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }}
      >
        {children}{active ? (sort.dir > 0 ? " ↑" : " ↓") : ""}
      </th>
    );
  }

  const noEng = data?.no_engagement;

  // Distinct hosts across the current result set — grouping only helps (and the
  // toggle only shows) when a scan spanned more than one machine, e.g. an IP
  // range. A single-target scan stays a plain table.
  const hosts = [...new Set(sortedFindings.map((f) => hostOf(f.target)))];
  const multiHost = hosts.length > 1;
  const grouped = groupByHost && multiHost;

  // Findings bucketed by host, host order = worst severity, then most findings,
  // then name — so the most exposed machine is first.
  const hostGroups = grouped ? (() => {
    const m = new Map();
    for (const f of sortedFindings) {
      const h = hostOf(f.target);
      if (!m.has(h)) m.set(h, []);
      m.get(h).push(f);
    }
    return [...m.entries()].map(([host, rows]) => ({ host, rows })).sort((a, b) => {
      const wa = Math.min(...a.rows.map((r) => SEV_ORDER[r.severity] ?? 5));
      const wb = Math.min(...b.rows.map((r) => SEV_ORDER[r.severity] ?? 5));
      if (wa !== wb) return wa - wb;
      if (a.rows.length !== b.rows.length) return b.rows.length - a.rows.length;
      return a.host.localeCompare(b.host);
    });
  })() : [];

  const renderRow = (f) => (
    <tr key={f.id} className="animate-in">
      <td><span className={`sev-pill sev-${f.severity}`}>{f.severity}</span></td>
      <td><code style={{ fontSize: 11 }}>{f.vuln_type}</code></td>
      <td className="ellipsis" title={f.target}>{f.target}</td>
      <td>
        <span style={{
          color: Number(f.confidence) >= 0.9 ? 'var(--text-0)'
               : Number(f.confidence) >= 0.7 ? 'var(--med)' : 'var(--high)',
        }}>
          {Number(f.confidence).toFixed(2)}
        </span>
      </td>
      <td><span className={`status-pill status-${f.status}`}>{f.status}</span></td>
      <td className="dim">{(f.last_seen_at || "").slice(0, 10)}</td>
      <td><Link to={`/findings/${f.id}`} className="btn-small">Detail</Link></td>
    </tr>
  );

  const findingsTable = (rows, sortable) => {
    const Head = sortable
      ? SortTh
      : ({ children }) => <th style={{ whiteSpace: "nowrap" }}>{children}</th>;
    return (
      <table className="findings-table">
        <thead>
          <tr>
            <Head col="severity">Sev</Head>
            <Head col="vuln_type">Type</Head>
            <Head col="target">Target</Head>
            <Head col="confidence">Conf</Head>
            <Head col="status">Status</Head>
            <th>Last seen</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map(renderRow)}
          {rows.length === 0 && (
            <tr><td colSpan="7">
              <div className="info-state"><div>No findings match the current filters</div></div>
            </td></tr>
          )}
        </tbody>
      </table>
    );
  };

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
            onKeyDown={(e) => { if (e.key === "Enter") load(); }}
            onChange={(e) => setFilters(f => ({ ...f, target: e.target.value }))} />
        </label>
        <label className="form-group">
          <span className="form-label">Min confidence</span>
          <input className="form-input" type="number" min="0" max="1" step="0.05"
            value={filters.min_confidence}
            onKeyDown={(e) => { if (e.key === "Enter") load(); }}
            onChange={(e) => setFilters(f => ({ ...f, min_confidence: e.target.value }))} />
        </label>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? "..." : "Apply"}
        </button>
        <div style={{ marginLeft: "auto" }}><ReportMenu /></div>
      </div>

      {error && <div className="card error">{error}</div>}

      {loading && !data && (
        <div className="card"><SkeletonTable rows={8} cols={7} /></div>
      )}

      {noEng && (
        <EmptyState
          icon="🛰"
          headline="No active engagement yet"
          body="Findings show up here after your first scan. Launch one from the Scans page — no terminal required."
          cta="Launch a scan →"
          ctaTo="/scans"
        />
      )}

      {data && !noEng && !grouped && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, gap: 12, flexWrap: "wrap" }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {data.count} finding{data.count !== 1 ? "s" : ""}
              {multiHost && <span className="dim" style={{ fontWeight: 400 }}> · {hosts.length} hosts</span>}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              {multiHost && (
                <label style={{ fontSize: 12, color: "var(--text-1)", display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
                  <input type="checkbox" checked={groupByHost} onChange={(e) => setGroupByHost(e.target.checked)} />
                  Group by host
                </label>
              )}
              <span style={{ fontSize: 11, color: "var(--text-1)" }}>Click column headers to sort</span>
            </div>
          </div>
          {findingsTable(sortedFindings, true)}
        </div>
      )}

      {data && !noEng && grouped && (
        <>
          <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {data.count} finding{data.count !== 1 ? "s" : ""} across {hosts.length} host{hosts.length !== 1 ? "s" : ""}
            </div>
            <label style={{ fontSize: 12, color: "var(--text-1)", display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}>
              <input type="checkbox" checked={groupByHost} onChange={(e) => setGroupByHost(e.target.checked)} />
              Group by host
            </label>
          </div>
          {hostGroups.map(({ host, rows }) => (
            <div key={host} className="card" style={{ marginTop: 12 }}>
              <div className="card-title" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
                <span className="mono">{host}</span>
                <span className="dim" style={{ fontSize: 12, fontWeight: 400 }}>
                  {rows.length} finding{rows.length !== 1 ? "s" : ""}
                </span>
                <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {sevSummary(rows).map(({ sev, n }) => (
                    <span key={sev} className={`sev-pill sev-${sev}`} style={{ fontSize: 10 }}>{n} {sev}</span>
                  ))}
                </span>
              </div>
              {findingsTable(rows, false)}
            </div>
          ))}
        </>
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
