import React, { useEffect, useState } from "react";
import { Engagement as Eng } from "../api";

export default function EngagementPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Eng.summary().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="card error">No active engagement: {error}</div>;
  if (!data) return <div className="card">Loading…</div>;

  const { engagement, stats } = data;

  return (
    <div className="card">
      <h2>{engagement?.name || "—"}</h2>
      <table className="kv-table">
        <tbody>
          <tr><td>Client</td><td>{engagement?.client || "—"}</td></tr>
          <tr><td>Statement of work</td><td>{engagement?.statement_of_work || "—"}</td></tr>
          <tr><td>Created</td><td>{engagement?.created_at || "—"}</td></tr>
          <tr><td>Targets in scope</td><td>{stats.scope_targets}</td></tr>
          <tr><td>Scans run</td><td>{stats.scans_run}</td></tr>
          <tr><td>Total findings</td><td>{stats.total_findings}</td></tr>
        </tbody>
      </table>
      <h3>Manage scope from the CLI</h3>
      <pre className="code">{`heaven scope add api.acme.example --kind host
heaven scope import scope.txt
heaven scope list`}</pre>
      <p className="dim">
        Scope changes require operator authorization and are intentionally
        CLI-only. The web UI is for triage, not for adding new attack surface.
      </p>
    </div>
  );
}
