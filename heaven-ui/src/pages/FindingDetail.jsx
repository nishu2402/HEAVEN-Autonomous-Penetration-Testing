import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Engagement, ExploitProof, AI, ExploitDB } from "../api";
import Markdown from "../components/Markdown";

const STATUSES = ["open", "verified", "false_positive", "accepted_risk", "fixed"];
const STATUS_COLORS = {
  open: "var(--med)", verified: "var(--brand)",
  false_positive: "var(--text-2)", accepted_risk: "var(--cyan)", fixed: "var(--text-1)"
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
            <h2 style={{ fontSize: 16, marginTop: 8, color: "var(--text-0)", fontWeight: 700, letterSpacing: "0.05em" }}>
              <span className={`sev-pill sev-${f.severity}`} style={{ marginRight: 8 }}>{f.severity}</span>
              {(f.vuln_type || "").toUpperCase()}
            </h2>
            <div style={{ color: "var(--text-1)", fontSize: 13, marginTop: 4 }}>{f.target}</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 11, color: "var(--text-1)", marginBottom: 4 }}>FINDING ID</div>
            <code style={{ fontSize: 12 }}>{f.id}</code>
          </div>
        </div>

        <table className="kv-table" style={{ marginTop: 16 }}>
          <tbody>
            <tr><td>Title</td><td style={{ color: "var(--text-0)" }}>{f.title || "—"}</td></tr>
            <tr><td>Confidence</td><td>
              <span style={{ color: Number(f.confidence) >= 0.9 ? "var(--text-0)" : "var(--med)" }}>
                {Number(f.confidence).toFixed(2)}
              </span>
              {f.confidence_bucket && <span className="dim" style={{ marginLeft: 6 }}>({f.confidence_bucket})</span>}
            </td></tr>
            <tr><td>CVE</td><td>{f.cve_id || "—"}</td></tr>
            <tr><td>CVSS</td><td>
              {f.predicted_cvss_score?.toFixed?.(1)
                ?? (f.typical_cvss ? Number(f.typical_cvss).toFixed(1) : "—")}
              {!f.predicted_cvss_score && f.typical_cvss
                ? <span className="dim" style={{ marginLeft: 6 }}>(typical for class)</span>
                : null}
            </td></tr>
            <tr><td>Priority score</td><td>{f.priority_score?.toFixed?.(2) ?? "—"}</td></tr>
            <tr><td>CWE</td><td>{f.cwe || ev.cwe || "—"}</td></tr>
            <tr><td>OWASP</td><td>{f.owasp || ev.owasp || "—"}</td></tr>
            <tr><td>MITRE ATT&CK</td><td>{f.mitre_technique || ev.mitre || "—"}</td></tr>
            <tr><td>CVSS vector</td><td className="mono" style={{ fontSize: 12 }}>{f.cvss_vector || ev.cvss_vector || "—"}</td></tr>
            <tr><td>Seen</td><td className="dim">
              {f.seen_count ?? 1}×{f.last_seen_at ? ` (last: ${f.last_seen_at.slice(0, 10)})` : ""}
            </td></tr>
            <tr><td>Status</td><td>
              <span className={`status-pill status-${f.status}`}>{f.status}</span>
            </td></tr>
          </tbody>
        </table>
      </div>

      {(ev.description || ev.impact) && (
        <div className="card">
          <div className="card-title">About this vulnerability</div>
          {ev.description && (
            <p style={{ color: "var(--text-0)", fontSize: 13.5, lineHeight: 1.7, marginBottom: ev.impact ? 14 : 0 }}>
              {ev.description}
            </p>
          )}
          {ev.impact && (
            <>
              <div style={{ fontSize: 11, color: "var(--text-2)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>Impact</div>
              <p style={{ color: "var(--text-1)", fontSize: 13, lineHeight: 1.7 }}>{ev.impact}</p>
            </>
          )}
          {(ev.cwe || ev.owasp || ev.mitre) && (
            <div style={{ marginTop: 14, display: "flex", gap: 8, flexWrap: "wrap" }}>
              {ev.cwe && <span className="badge-soft">{ev.cwe}</span>}
              {ev.owasp && <span className="badge-soft">{ev.owasp}</span>}
              {ev.mitre && <span className="badge-soft">{ev.mitre}</span>}
            </div>
          )}
        </div>
      )}

      {/* Active confirmation — Gap 4 + Gap 6 */}
      <ExploitAndReviewActions id={id} finding={f} onChange={load} />

      {/* Exploit-DB lookup (only when finding has a CVE) */}
      {f.cve_id && <ExploitDBLookup cve={f.cve_id} />}

      {/* Operator workflow */}
      <div className="card">
        <div className="card-title">Triage</div>
        <div style={{ marginBottom: 10 }}>
          <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
            Operator notes (saved with status change)
          </label>
          <textarea
            className="form-input"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="e.g. confirmed via Burp Repeater — response includes admin hashes"
            rows={3}
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
          <div style={{ marginBottom: 8, fontSize: 11, color: "var(--text-1)", letterSpacing: "0.08em" }}>
            REQUEST
          </div>
          <div className="evidence-block">
            {ev.request_method} {ev.request_url}{"\n"}
            {Object.entries(ev.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}
            {ev.request_body ? "\n\n" + ev.request_body.slice(0, 1000) : ""}
          </div>

          <div style={{ margin: "12px 0 8px", fontSize: 11, color: "var(--text-1)", letterSpacing: "0.08em" }}>
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
              <li key={i} style={{ color: "var(--text-0)", fontSize: 13 }}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation — static KB text + on-demand AI-tailored guidance */}
      <RemediationCard id={id} staticText={ev.remediation} />


      {/* References */}
      {ev.references?.length > 0 && (
        <div className="card">
          <div className="card-title">References</div>
          <ul style={{ paddingLeft: 18, lineHeight: 1.9 }}>
            {ev.references.map((r, i) => (
              <li key={i} style={{ fontSize: 13 }}>
                <a href={r} target="_blank" rel="noopener noreferrer"
                   style={{ color: "var(--cyan)", wordBreak: "break-all" }}>{r}</a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Sub-component: remediation (static KB text + on-demand AI guidance) ──

function RemediationCard({ id, staticText }) {
  const [loading, setLoading] = useState(false);
  const [ai, setAi]           = useState(null);   // { remediation, ai_generated }
  const [error, setError]     = useState(null);

  async function generate() {
    setLoading(true);
    setError(null);
    try {
      setAi(await Engagement.remediate(id));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  // Nothing to show at all until there's KB text or the user asks for AI text.
  if (!staticText && !ai && !error && !loading) {
    return (
      <div className="card">
        <div className="card-title">Remediation</div>
        <button className="btn" onClick={generate} disabled={loading}>
          ✨ Generate AI remediation
        </button>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-title">Remediation</div>
      {staticText && <div className="evidence-block">{staticText}</div>}
      {ai && (
        <div style={{ marginTop: staticText ? 12 : 0 }}>
          <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
            {ai.ai_generated
              ? "✨ AI-tailored remediation"
              : "Knowledge-base remediation (set an LLM key for AI-tailored guidance)"}
          </div>
          <div className="md-block">
            <Markdown>{ai.remediation}</Markdown>
          </div>
        </div>
      )}
      {error && <div className="evidence-block" style={{ color: "var(--red)" }}>{error}</div>}
      <button className="btn" onClick={generate} disabled={loading}
              style={{ marginTop: 12 }}>
        {loading ? "Generating…" : ai ? "↻ Regenerate" : "✨ Generate AI remediation"}
      </button>
    </div>
  );
}

// ── Sub-component: active confirmation + LLM FP review (Gaps 4 + 6) ──

function ExploitAndReviewActions({ id, finding, onChange }) {
  const [proving, setProving]   = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [result, setResult]     = useState(null);

  async function runProof() {
    setProving(true);
    setResult(null);
    try {
      const r = await ExploitProof.prove(id);
      setResult({ kind: "prove", payload: r });
      if (onChange) onChange();
    } catch (e) {
      setResult({ kind: "error", payload: e.message });
    } finally {
      setProving(false);
    }
  }

  async function runReview() {
    setReviewing(true);
    setResult(null);
    try {
      const r = await AI.fpReview({
        id: finding.id, target: finding.target,
        vuln_type: finding.vuln_type, severity: finding.severity,
        confidence: finding.confidence, title: finding.title,
        evidence: finding.evidence,
      });
      setResult({ kind: "review", payload: r });
    } catch (e) {
      setResult({ kind: "error", payload: e.message });
    } finally {
      setReviewing(false);
    }
  }

  return (
    <div className="card">
      <div className="card-title">Active Confirmation</div>
      <div className="dim" style={{ fontSize: 12, marginBottom: 10 }}>
        Run a controlled exploitation proof against the live target, or ask the
        LLM reviewer (if configured) to second-opinion the existing rule-based
        verdict. Both require the operator to have written authorization for the target.
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button className="btn" disabled={proving} onClick={runProof}>
          {proving ? "Proving…" : "Prove via exploit (Gap 4)"}
        </button>
        <button className="btn-small" disabled={reviewing} onClick={runReview}>
          {reviewing ? "Reviewing…" : "LLM FP review (Gap 6)"}
        </button>
      </div>

      {result && result.kind === "error" && (
        <div className="error" style={{ marginTop: 10 }}>{result.payload}</div>
      )}

      {result && result.kind === "prove" && (
        <div style={{ marginTop: 12 }}>
          <div>
            Proved: <strong style={{ color: result.payload.proved ? "var(--text-0)" : "var(--med)" }}>
              {result.payload.proved ? "yes" : "no"}
            </strong>
          </div>
          {result.payload.exploit_proof && result.payload.exploit_proof.length > 0 && (
            <pre className="cli-block" style={{ marginTop: 8, fontSize: 11 }}>
              {JSON.stringify(result.payload.exploit_proof, null, 2)}
            </pre>
          )}
        </div>
      )}

      {result && result.kind === "review" && (
        <div style={{ marginTop: 12 }}>
          {result.payload.skipped ? (
            <div className="dim">Skipped: {result.payload.skipped}</div>
          ) : (
            <>
              <div>
                LLM verdict: <strong style={{ color: result.payload.keep ? "var(--text-0)" : "var(--med)" }}>
                  {result.payload.keep ? "keep" : "false positive"}
                </strong>
                <span className="dim" style={{ marginLeft: 8 }}>
                  Δconfidence: {result.payload.confidence_delta?.toFixed?.(2) ?? "0.00"}
                </span>
              </div>
              {result.payload.reasoning && (
                <div className="dim" style={{ marginTop: 6, fontSize: 12 }}>
                  {result.payload.reasoning}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Sub-component: Exploit-DB lookup widget ──

function ExploitDBLookup({ cve }) {
  const [data, setData] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);

  async function lookup() {
    setLoading(true);
    setError(null);
    try {
      const r = await ExploitDB.lookup(cve);
      setData(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card">
      <div className="card-title">Exploit-DB Lookup</div>
      <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
        Search Exploit-DB for public PoCs matching <code>{cve}</code>.
        Tries local <code>searchsploit</code> first, falls back to the CSV mirror.
      </div>
      <button className="btn-small" onClick={lookup} disabled={loading}>
        {loading ? "Searching…" : `Look up ${cve}`}
      </button>

      {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
      {data && data.count === 0 && (
        <div className="dim" style={{ marginTop: 10 }}>
          No Exploit-DB entries found for {data.cve}.
        </div>
      )}
      {data && data.best && (
        <div style={{ marginTop: 10 }}>
          <div>
            <strong>Best match:</strong>{" "}
            <a href={data.best.url} target="_blank" rel="noopener noreferrer"
               style={{ color: "var(--cyan)" }}>
              EDB-{data.best.edb_id}
            </a>{" "}
            <span style={{ color: data.best.verified ? "var(--text-0)" : "var(--med)" }}>
              {data.best.verified ? "✓ verified" : "unverified"}
            </span>
          </div>
          <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>
            {data.best.title}
          </div>
          <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
            Platform: {data.best.platform} · Source: {data.best.source}
          </div>
        </div>
      )}
      {data && data.entries && data.entries.length > 1 && (
        <details style={{ marginTop: 10 }}>
          <summary className="dim" style={{ cursor: "pointer" }}>
            {data.entries.length} total entries
          </summary>
          <ul style={{ paddingLeft: 18, lineHeight: 1.6, fontSize: 12 }}>
            {data.entries.map((e) => (
              <li key={e.edb_id}>
                <a href={e.url} target="_blank" rel="noopener noreferrer"
                   style={{ color: "var(--cyan)" }}>EDB-{e.edb_id}</a>{" "}
                <span className="dim">[{e.platform}]</span> {e.title}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
