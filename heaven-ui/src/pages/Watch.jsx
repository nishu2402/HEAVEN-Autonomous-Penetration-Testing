// HEAVEN — Watch mode (continuous monitoring) info + status
//
// The watch loop is a long-running CLI process (`heaven watch ...`) so this
// page is informational + a status check rather than a launcher button.
// The UI shows the most-recent watch-iteration scans by querying the
// engagement DB.

import React, { useEffect, useState } from "react";
import { Scans, Tickets, SIEM } from "../api";

export default function WatchPage() {
  const [scans, setScans] = useState([]);
  const [siem, setSiem] = useState(null);
  const [tickets, setTickets] = useState(null);

  useEffect(() => {
    Scans.list(30).then((d) => setScans(d.scans || [])).catch(() => {});
    SIEM.status().then(setSiem).catch(() => {});
    Tickets.status().then(setTickets).catch(() => {});
  }, []);

  const watchScans = (scans || []).filter(s =>
    (s.name || "").startsWith("watch-")
  );

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#00D4FF", marginTop: 0 }}>🔁 Watch Mode</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Continuous monitoring with auto-diff. Runs scans on an interval,
          diffs each against the previous, and alerts ONLY when something
          changes (new / regressed finding) — no Slack spam from boring
          re-scans.
        </p>

        <div className="card-title" style={{ marginTop: 16 }}>Start a watch loop (CLI)</div>
        <pre style={{
          fontSize: 12, fontFamily: "monospace", padding: 12,
          background: "rgba(0,0,0,0.4)",
          border: "1px solid rgba(0,212,255,0.2)",
          whiteSpace: "pre-wrap",
        }}>{`# Watch a SaaS app every 30 min, auto-create Jira tickets on new criticals:
heaven watch -u https://app.example.com \\
    --engagement prod-monitor \\
    --interval 30m \\
    --auto-tickets \\
    --i-have-authorization

# Quick demo — 3 iterations, 60s apart:
heaven watch -t 10.0.0.5 \\
    --engagement test \\
    --interval 60s \\
    --max-iterations 3 \\
    --i-have-authorization

# Send a heartbeat every run (default = change-only alerts):
heaven watch -u https://x --engagement prod \\
    --heartbeat --interval 1h --i-have-authorization`}</pre>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">Outgoing alert channels</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <Channel
            name="Webhook (Slack/Teams)"
            active={!!siem && true /* webhook is per-env via WEBHOOK_URL */}
            note="Set WEBHOOK_URL env var"
          />
          <Channel
            name="SIEM (Splunk HEC / Elastic)"
            active={siem?.siem_backends_active?.length > 0}
            note={siem?.siem_backends_active?.length
              ? `Active: ${siem.siem_backends_active.join(", ")}`
              : "Set HEAVEN_SPLUNK_HEC_* or HEAVEN_ELASTIC_* env vars"}
          />
          <Channel
            name="Ticketing (Jira / Linear)"
            active={tickets?.configured_backends?.length > 0}
            note={tickets?.configured_backends?.length
              ? `Active: ${tickets.configured_backends.join(", ")}`
              : "Set HEAVEN_JIRA_* or HEAVEN_LINEAR_* env vars"}
          />
        </div>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">
          Recent watch-iteration scans ({watchScans.length})
        </div>
        {watchScans.length === 0 ? (
          <div className="dim">No watch iterations yet. Start one from the CLI above.</div>
        ) : (
          <table style={{ width: "100%", fontSize: 12 }}>
            <thead><tr style={{ color: "#00D4FF" }}>
              <th align="left">Iteration</th>
              <th align="left">Scan ID</th>
              <th align="left">Status</th>
              <th align="right">Findings</th>
              <th align="left">Started</th>
            </tr></thead>
            <tbody>
              {watchScans.map((s) => {
                const id = s.scan_id || s.id;
                const iter = (s.name || "").replace("watch-", "");
                return (
                  <tr key={id}>
                    <td><code>{iter}</code></td>
                    <td><code>{(id || "").slice(0, 8)}</code></td>
                    <td>{s.status || "?"}</td>
                    <td align="right">{s.findings_count ?? 0}</td>
                    <td className="dim" style={{ fontSize: 11 }}>
                      {(s.started_at || "").slice(0, 16).replace("T", " ")}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Channel({ name, active, note }) {
  return (
    <div style={{
      padding: 12, background: "rgba(0,0,0,0.3)",
      border: `1px solid ${active ? "#00FF41" : "#FFB800"}33`,
    }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{name}</div>
      <div style={{ color: active ? "#00FF41" : "#FFB800", fontSize: 12 }}>
        {active ? "✓ active" : "✗ not configured"}
      </div>
      <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>{note}</div>
    </div>
  );
}
