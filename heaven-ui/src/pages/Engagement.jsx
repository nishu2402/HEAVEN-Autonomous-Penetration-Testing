import React, { useEffect, useState } from "react";
import { Engagement as Eng } from "../api";

export default function EngagementPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Eng.summary()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="page">
        <div className="card error">{error}</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="page">
        <div className="card"><span className="dim">Loading...</span></div>
      </div>
    );
  }

  const { engagement, stats } = data;
  const noEng = data.no_engagement || !engagement;

  if (noEng) {
    return (
      <div className="page">
        <div className="onboarding-banner">
          <div className="onboarding-icon">◈</div>
          <div>
            <div className="onboarding-title">No Active Engagement</div>
            <div className="onboarding-body">
              HEAVEN organizes findings per engagement — one SQLite file per engagement.
              Start one from the CLI, then set the environment variable so the UI can load it.
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title">Setup</div>
          <pre className="code">{`# 1. Create an engagement
heaven engage init acme-q2 --client "ACME Corp" --sow "SOW-2026-001"

# 2. Point the server at it
export HEAVEN_ENGAGEMENT=engagements/acme-q2.db

# 3. Restart the server
heaven serve

# 4. Add scope
heaven scope add 10.0.0.0/24 --kind cidr
heaven scope add https://app.acme.example --kind url`}</pre>
        </div>

        <div className="card">
          <div className="card-title">Why per-engagement SQLite?</div>
          <div style={{ color: 'rgba(0,255,65,0.80)', lineHeight: 1.8, fontSize: 13 }}>
            <p>Each engagement gets an isolated database file. No cross-contamination of findings,
            no shared state between clients. The file lives next to your notes — hand it to a
            colleague or archive it after the engagement ends.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">Engagement Details</div>
        <table className="kv-table">
          <tbody>
            <tr><td>Name</td><td style={{ color: '#00FF41', fontWeight: 700 }}>{engagement.name}</td></tr>
            <tr><td>Client</td><td>{engagement.client || "—"}</td></tr>
            <tr><td>Statement of work</td><td>{engagement.statement_of_work || "—"}</td></tr>
            <tr><td>Created</td><td className="dim">{engagement.created_at || "—"}</td></tr>
            <tr><td>Targets in scope</td><td>{stats.scope_targets}</td></tr>
            <tr><td>Scans run</td><td>{stats.scans_run}</td></tr>
            <tr><td>Total findings</td><td>{stats.total_findings}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Findings by severity</div>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {Object.entries(stats.by_severity || {}).map(([sev, count]) => (
            <div key={sev} style={{ textAlign: 'center', minWidth: 60 }}>
              <div style={{ fontSize: 24, fontWeight: 700 }} className={`sev-${sev}`}>{count}</div>
              <div style={{ fontSize: 10, color: 'rgba(0,255,65,0.68)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>{sev}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-title">Manage scope from CLI</div>
        <pre className="code">{`heaven scope add api.acme.example --kind host
heaven scope add 10.0.0.0/24 --kind cidr
heaven scope import scope.txt
heaven scope list`}</pre>
        <p className="dim" style={{ marginTop: 10, fontSize: 12 }}>
          Scope changes are CLI-only. The UI is for triage, not for expanding attack surface.
        </p>
      </div>
    </div>
  );
}
