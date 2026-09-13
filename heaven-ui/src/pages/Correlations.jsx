// HEAVEN — Combined Risk (finding correlation) page.
//
// Surfaces combinations of findings that, individually rated, together form a
// more critical issue (e.g. local file inclusion + file upload -> RCE), the
// end-to-end attack paths those combinations chain into (each step hands the
// attacker a capability the next consumes), and the single fixes that break the
// most chains. Loads the active engagement's combinations from
// GET /api/correlations/latest, and lets an operator paste their own findings
// list to correlate on demand (POST /api/correlate).

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

// ── Attack path graph ───────────────────────────────────────────────────────
// One path renders as a horizontal walk of step nodes joined by labelled
// arrows, ending in a filled impact node. It scrolls horizontally on narrow
// screens rather than forcing the page sideways.

function StepNode({ step }) {
  const sev = (step.combined_severity || "info").toLowerCase();
  const color = SEV_COLORS[sev] || "#666";
  return (
    <div
      style={{
        flex: "0 0 auto", width: 190, borderRadius: 8,
        border: "1px solid var(--line, #333)", borderTop: `3px solid ${color}`,
        background: "var(--surface-1, rgba(255,255,255,0.02))",
        padding: "8px 10px",
      }}
    >
      <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 4 }}>
        <span
          style={{
            flex: "0 0 auto", width: 18, height: 18, borderRadius: "50%",
            background: color, color: "#fff", fontSize: 11, fontWeight: 700,
            display: "inline-flex", alignItems: "center", justifyContent: "center",
          }}
        >
          {step.position}
        </span>
        <SevPill sev={sev} />
      </div>
      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-0)", lineHeight: 1.25 }}>
        {step.name}
      </div>
      {(step.hosts || []).length ? (
        <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>
          {step.hosts.join(", ")}
        </div>
      ) : null}
      {(step.grants || []).length ? (
        <div style={{ fontSize: 10, marginTop: 4, color: color }}>
          gains: {step.grants.join(", ").replace(/_/g, " ")}
        </div>
      ) : null}
    </div>
  );
}

function HopArrow({ via }) {
  return (
    <div
      style={{
        flex: "0 0 auto", width: 118, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center", padding: "0 4px",
      }}
    >
      <div style={{ fontSize: 20, color: "var(--text-1, #999)", lineHeight: 1 }}>→</div>
      {via ? (
        <div className="dim" style={{ fontSize: 10, textAlign: "center", marginTop: 2, lineHeight: 1.2 }}>
          {via}
        </div>
      ) : null}
    </div>
  );
}

function ImpactNode({ label, sev }) {
  const color = SEV_COLORS[(sev || "critical").toLowerCase()] || "var(--crit)";
  return (
    <div
      style={{
        flex: "0 0 auto", minWidth: 170, maxWidth: 220, borderRadius: 8,
        background: color, color: "#fff", padding: "10px 12px",
        display: "flex", flexDirection: "column", justifyContent: "center",
      }}
    >
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 0.4, opacity: 0.85 }}>
        Impact
      </div>
      <div style={{ fontSize: 13, fontWeight: 700, lineHeight: 1.25 }}>{label}</div>
    </div>
  );
}

function AttackPathCard({ p }) {
  const color = SEV_COLORS[(p.severity || "info").toLowerCase()] || "#666";
  const hosts = (p.hosts || []).join(" → ");
  return (
    <div className="card" style={{ marginTop: 12, borderLeft: `4px solid ${color}` }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <SevPill sev={p.severity} />
        <strong style={{ color: "var(--text-0)" }}>{p.business_impact}</strong>
        <span className="dim" style={{ fontSize: 11 }}>
          {p.length} steps · confidence {Math.round((p.confidence || 0) * 100)}%
          {hosts ? ` · ${hosts}` : ""}
          {p.confirmation ? ` · ${p.confirmation}` : ""}
        </span>
      </div>
      {p.impact_detail ? (
        <p className="dim" style={{ fontSize: 12, margin: "6px 0 8px" }}>{p.impact_detail}</p>
      ) : null}

      <div style={{ overflowX: "auto", paddingBottom: 4 }}>
        <div style={{ display: "flex", alignItems: "stretch", minWidth: "min-content" }}>
          {(p.steps || []).map((st, i) => (
            <React.Fragment key={st.id || i}>
              {i > 0 ? <HopArrow via={st.via} /> : null}
              <StepNode step={st} />
            </React.Fragment>
          ))}
          <HopArrow via="" />
          <ImpactNode label={p.business_impact} sev={p.severity} />
        </div>
      </div>

      {(p.narrative || []).length ? (
        <ol style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12 }}>
          {p.narrative.map((line, i) => (
            <li key={i} style={{ marginBottom: 2, color: "var(--text-1, inherit)" }}>{line}</li>
          ))}
        </ol>
      ) : null}
    </div>
  );
}

// ── Break the chain (remediation leverage) ────────────────────────────────────

function LeveragePanel({ rem }) {
  const top = rem?.top_fix;
  const byFinding = (rem?.by_finding || []).filter((r) => r.chains_broken);
  if (!top || !top.chains_broken) return null;
  const cut = rem?.path_cut || [];
  return (
    <div
      className="card"
      style={{ marginTop: 12, borderLeft: "4px solid var(--green, #12b981)" }}
    >
      <strong style={{ color: "var(--text-0)" }}>Break the chain</strong>
      <p style={{ fontSize: 13, margin: "6px 0" }}>
        A combined risk needs all of its parts, so fixing any one constituent breaks it.
        Fixing <b>{top.title}</b> alone breaks {top.chains_broken} combined risk(s).
      </p>
      <ul style={{ margin: "4px 0", paddingLeft: 18, fontSize: 13 }}>
        {byFinding.slice(0, 6).map((r, i) => (
          <li key={i} style={{ marginBottom: 3 }}>
            <b>{r.title}</b>
            {r.target ? <span className="dim" style={{ fontSize: 11 }}> ({r.target})</span> : null}
            <span className="dim" style={{ fontSize: 11 }}>
              {" "}breaks {r.chains_broken} combined risk(s)
              {r.paths_broken ? ` · ${r.paths_broken} attack path(s)` : ""}
            </span>
          </li>
        ))}
      </ul>
      {cut.length ? (
        <p style={{ fontSize: 13, margin: "6px 0 0" }}>
          <b>Sever every attack path</b> by fixing: {cut.map((c) => c.title).join(", ")}.
        </p>
      ) : null}
    </div>
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
  const paths = summary?.attack_paths || [];
  const rem = summary?.remediation || {};

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
          Suggests where two or more findings, although rated individually, combine into a single
          materially worse issue, and rates the combination accordingly. It then chains those
          combinations into end-to-end attack paths, where each step hands the attacker a capability
          the next step uses, and points out the single fixes that break the most chains. Nothing is
          invented: a combination shows only when each part is a real, distinct finding, its severity
          is never rated below any of its parts, and a path link is drawn only where one step
          genuinely produces what the next requires.
        </p>

        {summary && !noEng && (
          <div className="dim" style={{ fontSize: 12 }}>
            {summary.total_combinations} combined risk(s) from {summary.total_input_findings} finding(s)
            {" · "}<span style={{ color: "var(--crit)" }}>{summary.critical_combinations} critical</span>
            {" · "}{summary.confirmed_combinations} confirmed
            {summary.total_attack_paths ? ` · ${summary.total_attack_paths} attack path(s)` : ""}
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
            headline="No combined risks found"
            body="None of the current findings form a known amplification chain. This is a good sign."
          />
        </div>
      )}

      {!loading && combos.length > 0 && <LeveragePanel rem={rem} />}

      {!loading && paths.length > 0 && (
        <>
          <h3 style={{ color: "var(--text-0)", margin: "18px 0 0" }}>Attack paths</h3>
          <p className="dim" style={{ fontSize: 12, margin: "4px 0 0" }}>
            Each path is an ordered walk that ends in the business impact shown. Same-host steps are
            marked; cross-host hops are labelled with how the attacker moves (reused credentials or
            internal network reach gained earlier).
          </p>
          {paths.map((p) => <AttackPathCard key={p.id} p={p} />)}
        </>
      )}

      {!loading && combos.length > 0 && (
        <h3 style={{ color: "var(--text-0)", margin: "18px 0 0" }}>Combined risks</h3>
      )}
      {combos.map((c) => <ComboCard key={c.id} c={c} />)}
    </div>
  );
}
