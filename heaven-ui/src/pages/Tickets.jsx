// HEAVEN — Ticketing status + push viewer
// Mirrors `heaven tickets status` from the CLI.

import React, { useEffect, useState } from "react";
import { Tickets } from "../api";

export default function TicketsPage() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Tickets.status().then(setStatus).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#FFB800", marginTop: 0 }}>🎫 Ticketing</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Auto-create Jira / Linear issues from findings. Backends are
          env-configured — once set, the "Push to ticketing" button on
          FindingDetail and bulk push via CLI start working.
        </p>

        {error && <div className="error">{error}</div>}

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
          <div style={{ marginTop: 12, padding: 12, background: "rgba(255,184,0,0.05)",
                        border: "1px solid rgba(255,184,0,0.3)" }}>
            <strong>No backends configured.</strong> Set the env vars above
            and restart the API server. Critical findings won't auto-create
            tickets until at least one backend is configured.
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">CLI usage</div>
        <pre style={{
          fontSize: 12, fontFamily: "monospace", padding: 12,
          background: "rgba(0,0,0,0.4)",
          border: "1px solid rgba(0,255,65,0.2)",
          whiteSpace: "pre-wrap",
        }}>{`# Check backend config
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
    <div style={{
      padding: 12, background: "rgba(0,0,0,0.3)",
      border: `1px solid ${configured ? "#00FF41" : "#FFB800"}33`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontWeight: 700, color }}>{name}</div>
        <div style={{ color: configured ? "#00FF41" : "#FFB800" }}>
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
