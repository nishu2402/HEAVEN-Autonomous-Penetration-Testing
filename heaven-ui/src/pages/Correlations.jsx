// HEAVEN — Combined Risk (finding correlation) page.
//
// Surfaces combinations of findings that, individually rated, together form a
// more critical issue (e.g. local file inclusion + file upload -> RCE). Loads
// the active engagement's combinations from GET /api/correlations/latest, and
// lets an operator paste their own findings list to correlate on demand
// (POST /api/correlate).

import React, { useEffect, useState } from "react";
import { Correlate, Engagement } from "../api";
import { EmptyState, SkeletonCard } from "../components/Skeleton.jsx";
import HelpTip from "../components/HelpTip.jsx";

const SEV_COLORS = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--cyan)", info: "#666",
};

function SevPill({ sev }) {
  const s = (sev || "info").toLowerCase();
  return (
    <span
      className="pill"
      style={{
        background: SEV_COLORS[s] || "#666", color: "#fff",
        padding: "1px 8px", borderRadius: 6, fontSize: 11,
        fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.3,
      }}
    >
      {s}
    </span>
  );
}

function ComboCard({ c }) {
  return (
    <div
      className="card"
      style={{ marginTop: 12, borderLeft: `4px solid ${SEV_COLORS[c.combined_severity] || "#666"}` }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <SevPill sev={c.combined_severity} />
        <span
          style={{
            fontSize: 11, fontWeight: 700, padding: "1px 8px", borderRadius: 6,
            color: c.confirmation === "Confirmed" ? "var(--green, #12b981)" : "var(--med)",
            border: `1px solid ${c.confirmation === "Confirmed" ? "var(--green, #12b981)" : "var(--med)"}`,
          }}
        >
          {c.confirmation}
        </span>
        <strong style={{ color: "var(--text-0)" }}>{c.name}</strong>
      </div>

      <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
        {c.id} · Representative CVSS {Number(c.representative_cvss || 0).toFixed(1)}
        {" · "}confidence {Math.round((c.confidence || 0) * 100)}%
        {c.priority ? ` · priority ${Math.round(c.priority)}/100` : ""}
        {c.phase ? ` · ${c.phase}` : ""}
        {c.cwe ? ` · ${c.cwe}` : ""}
        {c.owasp ? ` · ${c.owasp}` : ""}
        {c.mitre && c.mitre.length ? ` · MITRE ${c.mitre.join(", ")}` : ""}
        {c.scope && c.scope.length ? ` · scope ${c.scope.join(", ")}` : ""}
      </div>

      <div style={{ marginTop: 8 }}>
        <div className="dim" style={{ fontSize: 11, marginBottom: 3 }}>Combines these findings</div>
        <ul style={{ margin: "2px 0", paddingLeft: 18 }}>
          {(c.components || []).map((comp, i) => {
            const extra = [
              comp.param ? `param ${comp.param}` : null,
              comp.port ? `port ${comp.port}` : null,
              comp.cve || null,
            ].filter(Boolean);
            return (
              <li key={i} style={{ marginBottom: 3 }}>
                <SevPill sev={comp.severity} />{" "}
                {comp.title || comp.vuln_type}
                {comp.target ? <span className="dim" style={{ fontSize: 11 }}> ({comp.target})</span> : null}
                {extra.length ? <span className="dim" style={{ fontSize: 11 }}> [{extra.join(" · ")}]</span> : null}
              </li>
            );
          })}
        </ul>
      </div>

      <p style={{ margin: "6px 0", fontSize: 13 }}>
        <b>Why it is worse together:</b> {c.rationale}
      </p>
      <p style={{ margin: "6px 0", fontSize: 13 }}>
        <b>Impact:</b> {c.impact}
      </p>

      {c.prerequisites && c.prerequisites.length ? (
        <div style={{ margin: "6px 0", fontSize: 13 }}>
          <b>Prerequisites for the chain:</b>
          <ul style={{ margin: "2px 0", paddingLeft: 18 }}>
            {c.prerequisites.map((p, i) => <li key={i} style={{ marginBottom: 2 }}>{p}</li>)}
          </ul>
        </div>
      ) : null}

      {c.playbook && c.playbook.length ? (
        <div style={{ margin: "6px 0", fontSize: 13 }}>
          <b>{c.confirmation === "Confirmed" ? "Reproduction steps" : "Proof / validation steps"}:</b>
          <ol style={{ margin: "2px 0", paddingLeft: 20 }}>
            {c.playbook.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
          </ol>
        </div>
      ) : null}

      <p style={{ margin: "6px 0", fontSize: 13, color: "var(--text-1, inherit)" }}>
        <b>Recommendation:</b> {c.recommendation}
      </p>
    </div>
  );
}

export default function Correlations() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [noEng, setNoEng] = useState(false);
  const [error, setError] = useState(null);

  // Operator-supplied correlation.
  const [showPaste, setShowPaste] = useState(false);
  const [findingsJson, setFindingsJson] = useState("");
  const [running, setRunning] = useState(false);

  function load() {
    setLoading(true);
    setError(null);
    Correlate.get("latest")
      .then((d) => {
        setSummary(d);
        setNoEng((d?.total_input_findings || 0) === 0 && (d?.total_combinations || 0) === 0);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, []);

  async function loadFromEngagement() {
    setError(null);
    try {
      const data = await Engagement.findings({ limit: 200 });
      const rows = (data?.findings || []).map((f) => ({
        id: f.id, target: f.target, vuln_type: f.vuln_type,
        title: f.title, severity: f.severity, confidence: f.confidence,
        status: f.status, evidence: f.evidence,
      }));
      setFindingsJson(JSON.stringify(rows, null, 2));
    } catch (e) {
      setError(e.message);
    }
  }

  async function runOnPasted() {
    setError(null);
    let parsed;
    try {
      parsed = JSON.parse(findingsJson || "[]");
    } catch (e) {
      setError(`Findings JSON is invalid: ${e.message}`);
      return;
    }
    if (!Array.isArray(parsed)) {
      setError("Provide a JSON array of findings.");
      return;
    }
    setRunning(true);
    try {
      const d = await Correlate.run(parsed);
      setSummary(d);
      setNoEng(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  }

  const combos = summary?.combinations || [];

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
          <h2 style={{ color: "var(--text-0)", marginTop: 0, marginBottom: 0 }}>
            🔗 Combined Risk<HelpTip term="correlation" />
          </h2>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn-small" onClick={load} disabled={loading}>Refresh</button>
            <button className="btn-small" onClick={() => setShowPaste((v) => !v)}>
              {showPaste ? "Hide" : "Analyse my findings"}
            </button>
          </div>
        </div>
        <p className="page-lead">
          Suggests where two or more findings, although rated individually, combine into a more
          critical issue, and elevates them accordingly. Every combination names its constituent
          findings and the single fix that breaks the chain. Nothing is invented: a combination shows
          only when each part is a real, distinct finding and the pairing genuinely raises the severity.
        </p>

        {summary && !noEng && (
          <div className="dim" style={{ fontSize: 12 }}>
            {summary.total_combinations} combined risk(s) from {summary.total_input_findings} finding(s)
            {" · "}<span style={{ color: "var(--crit)" }}>{summary.critical_combinations} critical</span>
            {" · "}{summary.confirmed_combinations} confirmed
          </div>
        )}

        {showPaste && (
          <div style={{ marginTop: 12 }}>
            <div style={{ marginBottom: 6 }}>
              <button className="btn-small" onClick={loadFromEngagement}>
                Load findings from active engagement
              </button>
            </div>
            <textarea
              className="form-input mono-input"
              value={findingsJson}
              onChange={(e) => setFindingsJson(e.target.value)}
              rows={10}
              spellCheck={false}
              placeholder='[{"id":"1","target":"http://x","vuln_type":"path_traversal","severity":"high"},{"id":"2","target":"http://x","vuln_type":"file_upload","severity":"high"}]'
            />
            <div style={{ marginTop: 8 }}>
              <button className="btn btn-primary" disabled={running} onClick={runOnPasted}>
                {running ? "Correlating…" : "Correlate these findings"}
              </button>
            </div>
          </div>
        )}

        {(error) && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {loading && <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>}

      {!loading && noEng && (
        <div style={{ marginTop: 12 }}>
          <EmptyState
            icon="⛓"
            headline="No findings to correlate"
            body="Run a scan on the active engagement, or paste a findings list above."
          />
        </div>
      )}

      {!loading && !noEng && combos.length === 0 && (
        <div style={{ marginTop: 12 }}>
          <EmptyState
            icon="✓"
            headline="No elevating combinations found"
            body="None of the current findings combine into a higher-severity issue. This is a good sign."
          />
        </div>
      )}

      {combos.map((c) => <ComboCard key={c.id} c={c} />)}
    </div>
  );
}
