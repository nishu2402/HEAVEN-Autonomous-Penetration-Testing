import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Engagement } from "../api";

const STATUSES = ["open", "verified", "false_positive", "accepted_risk", "fixed"];
const STATUS_COLORS = {
  open: "#FFB800", verified: "#00FF41",
  false_positive: "#aaa", accepted_risk: "#00D4FF", fixed: "rgba(0,255,65,0.70)"
};

export default function FindingDetail() {
  const { id } = useParams();
  const [data, setData]       = useState(null);
  const [error, setError]     = useState(null);
  const [notes, setNotes]     = useState("");
  const [updating, setUpdating] = useState(false);
  const [copied, setCopied]   = useState(false);

  function load() {
    setError(null);
    Engagement.evidence(id)
      .then((d) => { setData(d); setNotes(d.finding?.operator_notes || ""); })
      .catch((e) => setError(e.message));
  }

  useEffect(() => { load(); }, [id]);

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
    const cmd = data?.evidence_package?.curl_command;
    if (!cmd) return;
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* no clipboard API */ }
  }

  if (error) return (
    <div className="page">
      <div className="card error">
        <div style={{ marginBottom: 8 }}>{error}</div>
        <Link to="/findings" className="btn-small">← Back</Link>
      </div>
    </div>
  );

  if (!data) return (
    <div className="page">
      <div className="card"><span className="dim blink">Loading evidence package...</span></div>
    </div>
  );

  const f  = data.finding || {};
  const ev = data.evidence_package || {};

  return (
    <div className="page">
      {/* Header */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
          <div>
            <Link to="/findings" className="btn-small" style={{ marginBottom: 10, display: "inline-block" }}>
              ← All findings
            </Link>
            <h2 style={{ fontSize: 16, marginTop: 8, color: "#00FF41", fontWeight: 700, letterSpacing: "0.05em" }}>
              <span className={`sev-pill sev-${f.severity}`} style={{ marginRight: 8 }}>{f.severity}</span>
              {(f.vuln_type || "").toUpperCase()}
            </h2>
            <div style={{ color: "rgba(0,255,65,0.72)", fontSize: 13, marginTop: 4 }}>{f.target}</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 11, color: "rgba(0,255,65,0.65)", marginBottom: 4 }}>FINDING ID</div>
            <code style={{ fontSize: 12 }}>{f.id}</code>
          </div>
        </div>

        <table className="kv-table" style={{ marginTop: 16 }}>
          <tbody>
            <tr><td>Title</td><td style={{ color: "#00FF41" }}>{f.title || "—"}</td></tr>
            <tr><td>Confidence</td><td>
              <span style={{ color: Number(f.confidence) >= 0.9 ? "#00FF41" : "#FFB800" }}>
                {Number(f.confidence).toFixed(2)}
              </span>
              {f.confidence_bucket && <span className="dim" style={{ marginLeft: 6 }}>({f.confidence_bucket})</span>}
            </td></tr>
            <tr><td>CVE</td><td>{f.cve_id || "—"}</td></tr>
            <tr><td>Predicted CVSS</td><td>{f.predicted_cvss_score?.toFixed?.(1) ?? "—"}</td></tr>
            <tr><td>Priority score</td><td>{f.priority_score?.toFixed?.(2) ?? "—"}</td></tr>
            <tr><td>MITRE Technique</td><td>{f.mitre_technique || "—"}</td></tr>
            <tr><td>Seen</td><td className="dim">{f.seen_count ?? 1}× (last: {(f.last_seen_at || "").slice(0, 10)})</td></tr>
            <tr><td>Status</td><td>
              <span className={`status-pill status-${f.status}`}>{f.status}</span>
            </td></tr>
          </tbody>
        </table>
      </div>

      {/* Operator workflow */}
      <div className="card">
        <div className="card-title">Triage</div>
        <div style={{ marginBottom: 10 }}>
          <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
            Operator notes (saved with status change)
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="e.g. confirmed via Burp Repeater — response includes admin hashes"
            rows={3}
            style={{
              width: "100%", background: "rgba(0,255,65,0.04)",
              border: "1px solid rgba(0,255,65,0.2)", color: "#00FF41",
              fontFamily: "inherit", fontSize: 12, padding: "8px 10px", outline: "none",
              resize: "vertical",
            }}
          />
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {STATUSES.map((s) => (
            <button
              key={s}
              disabled={updating || f.status === s}
              onClick={() => changeStatus(s)}
              className="btn"
              style={{
                borderColor: STATUS_COLORS[s],
                color: STATUS_COLORS[s],
                opacity: f.status === s ? 1 : 0.6,
                fontWeight: f.status === s ? 700 : 400,
              }}
            >
              {f.status === s ? `✓ ${s}` : s}
            </button>
          ))}
        </div>
      </div>

      {/* Curl repro */}
      {ev.curl_command && (
        <div className="card">
          <div className="card-title">Reproduce</div>
          <p className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
            Paste into terminal or Burp's "Paste as request" to verify manually.
          </p>
          <div className="evidence-block">{ev.curl_command}</div>
          <button className="btn" onClick={copyCurl} style={{ marginTop: 10 }}>
            {copied ? "✓ Copied to clipboard" : "Copy curl command"}
          </button>
        </div>
      )}

      {/* Request / Response */}
      {(ev.request_url || ev.request_method) && (
        <div className="card">
          <div className="card-title">Evidence</div>
          <div style={{ marginBottom: 8, fontSize: 11, color: "rgba(0,255,65,0.68)", letterSpacing: "0.08em" }}>
            REQUEST
          </div>
          <div className="evidence-block">
            {ev.request_method} {ev.request_url}{"\n"}
            {Object.entries(ev.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}
            {ev.request_body ? "\n\n" + ev.request_body.slice(0, 1000) : ""}
          </div>

          <div style={{ margin: "12px 0 8px", fontSize: 11, color: "rgba(0,255,65,0.68)", letterSpacing: "0.08em" }}>
            RESPONSE — HTTP {ev.response_status} ({ev.response_size_bytes ?? "?"} bytes)
          </div>
          <div className="evidence-block">
            {ev.response_excerpt?.slice(0, 2000) || "(no response captured)"}
          </div>
        </div>
      )}

      {/* Why flagged */}
      {ev.reasons?.length > 0 && (
        <div className="card">
          <div className="card-title">Detection Rationale</div>
          <ul style={{ paddingLeft: 16, lineHeight: 2 }}>
            {ev.reasons.map((r, i) => (
              <li key={i} style={{ color: "rgba(0,255,65,0.85)", fontSize: 13 }}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation */}
      {ev.remediation && (
        <div className="card">
          <div className="card-title">Remediation</div>
          <div className="evidence-block">{ev.remediation}</div>
        </div>
      )}
    </div>
  );
}
