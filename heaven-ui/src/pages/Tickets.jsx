// HEAVEN — Ticketing status + push viewer
// Mirrors `heaven tickets status` from the CLI.

import React, { useEffect, useState } from "react";
import { Tickets } from "../api";
import { SkeletonStatGrid } from "../components/Skeleton.jsx";

export default function TicketsPage() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Tickets.status().then(setStatus).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--med)", marginTop: 0 }}>🎫 Ticketing</h2>
        <p className="page-lead">
          Auto-create Jira / Linear issues from findings. Backends are
          env-configured — once set, the "Push to ticketing" button on
          FindingDetail and bulk push via CLI start working.
        </p>

        {error && <div className="error">{error}</div>}

        {!status && !error && <SkeletonStatGrid count={2} />}

        {status && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Backend
              name="Jira"
              configured={status.jira_configured}
              env={["HEAVEN_JIRA_URL", "HEAVEN_JIRA_USER",
                    "HEAVEN_JIRA_TOKEN", "HEAVEN_JIRA_PROJECT"]}
              color="#0052CC"
            />
            <Backend
              name="Linear"
              configured={status.linear_configured}
              env={["HEAVEN_LINEAR_TOKEN", "HEAVEN_LINEAR_TEAM_ID"]}
              color="#5E6AD2"
            />
          </div>
        )}

        {status && status.configured_backends?.length === 0 && (
          <div className="form-banner" style={{
            marginTop: 14, color: "var(--med)",
            background: "rgba(255,197,61,0.08)", border: "1px solid rgba(255,197,61,0.30)",
          }}>
            <span><strong style={{ color: "var(--text-0)" }}>No backends configured.</strong> Set the env vars above
            and restart the API server. Critical findings won't auto-create
            tickets until at least one backend is configured.</span>
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">CLI usage</div>
        <pre className="cli-block">{`# Check backend config
heaven tickets status

# Push one finding to every configured backend
heaven tickets push <finding-id> --engagement <name>

# Bulk-push every critical open finding
heaven tickets bulk --engagement <name> --severity critical

# Dry-run first
heaven tickets bulk --engagement <name> --severity high --dry-run`}</pre>
      </div>
    </div>
  );
}

function Backend({ name, configured, env, color }) {
  return (
    <div className={"status-tile " + (configured ? "is-active" : "is-inactive")}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontWeight: 700, color }}>{name}</div>
        <div style={{ color: configured ? "var(--brand)" : "var(--med)" }}>
          {configured ? "✓ configured" : "✗ not configured"}
        </div>
      </div>
      <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>
        Required env vars:
      </div>
      <ul style={{ paddingLeft: 18, fontSize: 11, marginTop: 4, lineHeight: 1.5 }}>
        {env.map((e) => (<li key={e}><code>{e}</code></li>))}
      </ul>
    </div>
  );
}
