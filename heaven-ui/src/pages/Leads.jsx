import React, { useEffect, useState, useCallback } from "react";
import { Engagement } from "../api";
import { EmptyState, SkeletonTable } from "../components/Skeleton.jsx";
import usePersistentState from "../hooks/usePersistentState.js";

// Leads are honest sub-confirmation observations: a real signal was seen but
// could not be confirmed to the finding bar. They are NOT findings and are
// never counted or scored as findings. This page exists so a weak-but-real
// signal is handed to a human rather than dropped silently.

const STATUSES = ["open", "promoted", "dismissed", "all"];

function pct(v) {
  const n = Number(v);
  return Number.isFinite(n) ? `${Math.round(n * 100)}%` : "—";
}

export default function Leads() {
  const [status, setStatus] = usePersistentState("heaven.leads.status", "open");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    Engagement.leads(status === "all" ? "" : status)
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [status]);

  useEffect(() => { load(); }, [load]);

  const adjudicate = async (id, newStatus) => {
    setBusy(id);
    try {
      await Engagement.setLeadStatus(id, newStatus);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const leads = data?.leads || [];

  return (
    <div className="page">
      <div className="card" style={{ borderLeft: "3px solid var(--med)" }}>
        <h2 style={{ marginTop: 0 }}>Leads for manual review</h2>
        <p className="dim" style={{ marginBottom: 0 }}>
          Unconfirmed observations that did <strong>not</strong> reach the finding
          bar. Each had a real signal the scanner could not safely confirm, kept
          here so it can be verified by hand instead of dropped. Leads are not
          findings and are never counted or scored as findings. Promoting a lead
          records your judgement; it does not create a finding on its own (that
          still needs evidence).
        </p>
      </div>

      <div className="card filters">
        <label className="filter-select">
          <span>Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s === "all" ? "All" : s}</option>
            ))}
          </select>
        </label>
        <button className="btn-small" onClick={load} disabled={loading}>Refresh</button>
      </div>

      {error && <div className="card error-state">{error}</div>}

      {loading && !data ? (
        <SkeletonTable rows={5} />
      ) : leads.length === 0 ? (
        <EmptyState
          title="No leads for review"
          hint="Every substantiated signal reached the finding bar, or none was seen this scan."
        />
      ) : (
        <div className="card">
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ whiteSpace: "nowrap" }}>Calib. p</th>
                <th>Type</th>
                <th>Target</th>
                <th>Why unconfirmed</th>
                <th>How to verify</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {leads.map((l) => (
                <tr key={l.id} className="animate-in">
                  <td>
                    <span className="conf-badge conf-potential" title="Calibrated probability">
                      {pct(l.calibrated_confidence)}
                    </span>
                  </td>
                  <td><code style={{ fontSize: 11 }}>{l.vuln_type}</code></td>
                  <td className="ellipsis" title={l.target}>{l.target}</td>
                  <td className="dim" style={{ maxWidth: 260 }}>{l.reason}</td>
                  <td className="dim" style={{ maxWidth: 260 }}>{l.next_step}</td>
                  <td><span className={`status-pill status-${l.status}`}>{l.status}</span></td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {l.status !== "promoted" && (
                      <button className="btn-small" disabled={busy === l.id}
                        title="A human confirmed this by hand"
                        onClick={() => adjudicate(l.id, "promoted")}>Promote</button>
                    )}
                    {l.status !== "dismissed" && (
                      <button className="btn-small" disabled={busy === l.id}
                        title="A human ruled this out"
                        onClick={() => adjudicate(l.id, "dismissed")}
                        style={{ marginLeft: 6 }}>Dismiss</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="dim" style={{ marginTop: 8, fontSize: 12 }}>
            {leads.length} lead(s). A promoted lead becomes a tracked finding only
            when you add it with your own evidence or a re-scan confirms it.
          </div>
        </div>
      )}
    </div>
  );
}
