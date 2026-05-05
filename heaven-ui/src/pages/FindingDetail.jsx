import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Engagement } from "../api";

const STATUSES = ["open", "verified", "false_positive", "accepted_risk", "fixed"];

export default function FindingDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [notes, setNotes] = useState("");
  const [updating, setUpdating] = useState(false);
  const [copied, setCopied] = useState(false);

  function load() {
    setError(null);
    Engagement.evidence(id)
      .then((d) => { setData(d); setNotes(d.finding?.operator_notes || ""); })
      .catch((e) => setError(e.message));
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  async function changeStatus(newStatus) {
    setUpdating(true);
    try {
      await Engagement.setStatus(id, newStatus, notes);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setUpdating(false);
    }
  }

  async function copyCurl() {
    if (!data?.evidence_package?.curl_command) return;
    try {
      await navigator.clipboard.writeText(data.evidence_package.curl_command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* no clipboard */ }
  }

  if (error) return <div className="card error">{error}</div>;
  if (!data) return <div className="card">Loading…</div>;

  const f = data.finding;
  const ev = data.evidence_package;

  return (
    <div className="finding-detail">
      <div className="card">
        <Link to="/findings" className="btn-small">← Back to findings</Link>
        <h2>
          <span className={`sev-pill sev-${f.severity}`}>{f.severity}</span>
          {" "}{f.vuln_type.toUpperCase()} — <span className="dim">{f.target}</span>
        </h2>
        <table className="kv-table">
          <tbody>
            <tr><td>ID</td><td><code>{f.id}</code></td></tr>
            <tr><td>Confidence</td><td>{Number(f.confidence).toFixed(2)} ({f.confidence_bucket || "—"})</td></tr>
            <tr><td>CVE</td><td>{f.cve_id || "—"}</td></tr>
            <tr><td>Risk score</td><td>{f.risk_score?.toFixed?.(1) || "—"}</td></tr>
            <tr><td>Title</td><td>{f.title}</td></tr>
            <tr><td>Current status</td><td><span className={`status-pill status-${f.status}`}>{f.status}</span></td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Operator workflow</h3>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Notes on this finding (saved with status change)"
          rows={3}
        />
        <div className="status-buttons">
          {STATUSES.map((s) => (
            <button
              key={s}
              disabled={updating || f.status === s}
              onClick={() => changeStatus(s)}
              className={`btn status-btn-${s}`}
            >
              {f.status === s ? `✓ ${s}` : s}
            </button>
          ))}
        </div>
      </div>

      {ev?.curl_command && (
        <div className="card">
          <h3>Reproduce in your shell</h3>
          <p className="dim">
            Paste this into a terminal or Burp's "Paste URL as request" to verify manually.
          </p>
          <pre className="code">{ev.curl_command}</pre>
          <button className="btn" onClick={copyCurl}>
            {copied ? "✓ Copied" : "Copy curl"}
          </button>
        </div>
      )}

      <div className="card">
        <h3>Proof of issue</h3>
        <h4>Request</h4>
        <pre className="code">
          {ev.request_method} {ev.request_url}{"\n"}
          {Object.entries(ev.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}
          {ev.request_body ? "\n\n" + ev.request_body.slice(0, 1500) : ""}
        </pre>
        <h4>Response — HTTP {ev.response_status} ({ev.response_size_bytes} bytes)</h4>
        <pre className="code">
          {ev.response_excerpt?.slice(0, 2000) || "(no response captured)"}
        </pre>
      </div>

      {ev.reasons?.length > 0 && (
        <div className="card">
          <h3>Why this is flagged</h3>
          <ul>
            {ev.reasons.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      {ev.remediation && (
        <div className="card">
          <h3>Remediation</h3>
          <pre className="code">{ev.remediation}</pre>
        </div>
      )}
    </div>
  );
}
