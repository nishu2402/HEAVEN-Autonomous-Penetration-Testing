// HEAVEN — Compliance coverage (live).
//
// The control-coverage analogue of the Methodology page: it maps the ACTIVE
// engagement's real findings onto each compliance framework's controls, so an
// operator (or auditor) can see, control-by-control, which requirements this
// assessment produced evidence of a gap against — and click straight through to
// the findings. It is an honest coverage view, NOT an attestation of compliance.

import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { Compliance as C, downloadCompliance } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import { useToast } from "../components/Toast.jsx";

const SEV_COLORS = {
  critical: "var(--crit)",
  high: "#ff8a3d",
  medium: "#ffd24d",
  low: "var(--cyan)",
  info: "var(--text-2)",
  informational: "var(--text-2)",
};

function SevChip({ sev }) {
  const s = (sev || "info").toLowerCase();
  const c = SEV_COLORS[s] || "var(--text-2)";
  return (
    <span style={{
      display: "inline-block", padding: "0 6px", borderRadius: 4, fontSize: 9.5,
      fontWeight: 800, letterSpacing: "0.04em", color: c,
      border: `1px solid ${c}`, whiteSpace: "nowrap", textTransform: "uppercase",
    }}>{s}</span>
  );
}

function Tile({ label, value, sub, alert }) {
  return (
    <div className="mini-stat" style={alert ? { borderColor: "color-mix(in srgb, var(--brand) 40%, transparent)" } : undefined}>
      <div className="mini-stat-label">{label}</div>
      <div className="mini-stat-value" style={alert ? { color: "var(--brand)" } : undefined}>{value}</div>
      {sub && <div className="mini-stat-sub">{sub}</div>}
    </div>
  );
}

// The findings that provide evidence against one control — each links straight to
// its finding detail (BrowserRouter — never hash-nav).
function ControlFindings({ control }) {
  const refs = control.findings || [];
  if (refs.length === 0) {
    return <div className="dim" style={{ fontSize: 12 }}>No linkable findings.</div>;
  }
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {refs.map((f, i) => {
        const inner = (
          <>
            <SevChip sev={f.severity} />
            <span style={{ color: "var(--text-0)", fontSize: 12.5, fontWeight: 500 }}>
              {f.title || f.vuln_type || "Finding"}
            </span>
            {f.target && <code style={{ fontSize: 11, color: "var(--text-2)" }}>{f.target}</code>}
          </>
        );
        const rowStyle = { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", textDecoration: "none" };
        return f.id ? (
          <Link key={f.id + i} to={`/findings/${encodeURIComponent(f.id)}`} style={rowStyle} title="Open finding detail">
            {inner}
            <span style={{ marginLeft: "auto", color: "var(--brand)", fontSize: 11 }}>open →</span>
          </Link>
        ) : (
          <div key={i} style={rowStyle}>{inner}</div>
        );
      })}
    </div>
  );
}

function ControlRow({ control, expandAll }) {
  const [open, setOpen] = useState(false);
  const isOpen = expandAll || open;
  const hit = (control.count || 0) > 0;
  return (
    <>
      <tr
        onClick={hit ? () => setOpen((v) => !v) : undefined}
        style={{
          borderBottom: "1px solid var(--border)",
          cursor: hit ? "pointer" : "default",
          background: hit ? "color-mix(in srgb, var(--brand) 5%, transparent)" : undefined,
        }}
      >
        <td style={{ padding: "8px 10px", verticalAlign: "top", whiteSpace: "nowrap" }}>
          <code style={{ fontSize: 11.5 }}>{control.id}</code>
        </td>
        <td style={{ padding: "8px 10px", verticalAlign: "top", color: "var(--text-0)", fontSize: 12.5 }}>
          {control.name}
        </td>
        <td style={{ padding: "8px 10px", verticalAlign: "top", whiteSpace: "nowrap" }}>
          <span style={{
            fontSize: 10.5, fontWeight: 700, padding: "2px 7px", borderRadius: 5,
            color: hit ? "var(--brand)" : "var(--text-2)",
            border: `1px solid ${hit ? "var(--brand)" : "var(--border)"}`,
            background: hit ? "color-mix(in srgb, var(--brand) 12%, transparent)" : "transparent",
          }}>
            {control.status}
          </span>
        </td>
        <td style={{ padding: "8px 10px", verticalAlign: "top", textAlign: "center", color: hit ? "var(--brand)" : "var(--text-2)", fontWeight: 700 }}>
          {control.count || 0}
        </td>
        <td style={{ padding: "8px 10px", verticalAlign: "top", color: "var(--text-2)", fontSize: 11 }}>
          {hit ? (isOpen ? "▾ hide" : "▸ show") : "—"}
        </td>
      </tr>
      {hit && isOpen && (
        <tr>
          <td colSpan={5} style={{ padding: "4px 12px 12px 12px", background: "color-mix(in srgb, var(--brand) 4%, transparent)" }}>
            <ControlFindings control={control} />
          </td>
        </tr>
      )}
    </>
  );
}

function FrameworkView({ cov }) {
  const [busy, setBusy] = useState("");
  const [expandAll, setExpandAll] = useState(false);
  const toast = useToast();

  async function dl(fmt) {
    setBusy(fmt);
    try {
      const name = await downloadCompliance(cov.id, fmt);
      toast.success(`Downloaded ${name}`);
    } catch (e) {
      toast.error(e.message || "Compliance export failed");
    } finally {
      setBusy("");
    }
  }

  const controls = cov.controls || [];
  const findingsTotal = cov.findings_total || 0;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10, flexWrap: "wrap", justifyContent: "space-between" }}>
        <h3 style={{ margin: "0 0 6px", color: "var(--text-0)" }}>{cov.title}</h3>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {[["html", "⬇ HTML"], ["pdf", "⬇ PDF"], ["markdown", "⬇ Markdown"], ["json", "⬇ JSON"]].map(([f, lbl]) => (
            <button key={f} type="button" onClick={() => dl(f)} disabled={!!busy}
              style={{
                padding: "6px 10px", fontSize: 11.5, fontWeight: 600, cursor: busy ? "wait" : "pointer",
                background: "rgba(255,255,255,0.03)", color: "var(--text-0)",
                border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
                fontFamily: "var(--font-ui)",
              }}
              title={`Download the ${cov.title} control-coverage report`}>
              {busy === f ? "…" : lbl}
            </button>
          ))}
        </div>
      </div>
      <div className="dim" style={{ fontSize: 12, lineHeight: 1.6 }}>
        {cov.subtitle}
        {cov.reference && (
          <> · <a href={cov.reference} target="_blank" rel="noopener noreferrer" style={{ color: "var(--brand)" }}>reference →</a></>
        )}
      </div>

      {/* Honesty banner — this is a coverage view, not an attestation. */}
      <div style={{
        margin: "12px 0 14px", padding: "10px 14px", borderRadius: "var(--radius-md)",
        border: "1px solid color-mix(in srgb, var(--amber) 40%, transparent)",
        background: "color-mix(in srgb, var(--amber) 8%, transparent)",
        fontSize: 12.5, color: "var(--text-1)", lineHeight: 1.5,
      }}>
        <strong style={{ color: "var(--amber)" }}>Coverage view, not an attestation.</strong>{" "}
        {cov.controls_covered} of {cov.controls_total} controls have at least one finding
        providing evidence of a gap, across <strong>{findingsTotal}</strong> distinct
        finding{findingsTotal === 1 ? "" : "s"}. A control is "Findings present" only when a
        real finding carries a signal it concerns.
      </div>

      <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", marginBottom: 16 }}>
        <Tile label="Controls" value={cov.controls_total} />
        <Tile label="With findings" value={cov.controls_covered} alert />
        <Tile label="Findings mapped" value={findingsTotal} sub="distinct" />
      </div>

      {findingsTotal > 0 && (
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 6 }}>
          <button type="button" onClick={() => setExpandAll((v) => !v)}
            style={{
              padding: "5px 10px", fontSize: 11.5, cursor: "pointer",
              background: "none", color: "var(--brand)", border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)", fontFamily: "var(--font-ui)",
            }}>
            {expandAll ? "▾ Collapse all findings" : "▸ Expand all mapped findings"}
          </button>
        </div>
      )}

      <div style={{ overflowX: "auto", maxWidth: "100%" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-2)" }}>
              <th style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)" }}>Control</th>
              <th style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)" }}>Requirement</th>
              <th style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)" }}>Status</th>
              <th style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)", textAlign: "center" }}>Count</th>
              <th style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)" }}>Findings</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((c) => (
              <ControlRow key={c.id} control={c} expandAll={expandAll} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function Compliance() {
  const [frameworks, setFrameworks] = useState([]);
  const [active, setActive] = useState(null);
  const [cov, setCov] = useState(null);
  const [error, setError] = useState(null);
  const [loadingCov, setLoadingCov] = useState(false);

  useEffect(() => {
    C.frameworks()
      .then((d) => {
        const list = d.frameworks || [];
        setFrameworks(list);
        if (list.length) setActive(list[0].id);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!active) return;
    setLoadingCov(true);
    setCov(null);
    C.coverage(active)
      .then(setCov)
      .catch((e) => setError(e.message))
      .finally(() => setLoadingCov(false));
  }, [active]);

  const activeMeta = useMemo(
    () => frameworks.find((f) => f.id === active),
    [frameworks, active],
  );

  if (error) {
    return <div className="page"><div className="card error">{error}</div></div>;
  }
  if (!frameworks.length) {
    return <div className="page"><SkeletonCard lines={8} /></div>;
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>🛡 Compliance Coverage</h2>
        <p className="dim" style={{ fontSize: 12, lineHeight: 1.6, marginBottom: 0 }}>
          How this engagement's findings map onto each framework's controls, a{" "}
          <strong style={{ color: "var(--brand)" }}>live, control-by-control</strong> coverage
          view you can hand a client or auditor, and download per framework. It maps evidence of
          gaps onto controls; it is <strong style={{ color: "var(--amber)" }}>not an attestation
          of compliance</strong>.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(200px, 240px) 1fr", gap: 12, marginTop: 12, alignItems: "start" }}>
        {/* Framework selector */}
        <div className="card" style={{ padding: 10, position: "sticky", top: 12 }}>
          <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--text-2)", fontWeight: 600, margin: "2px 6px 8px" }}>
            Frameworks
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            {frameworks.map((f) => {
              const on = active === f.id;
              return (
                <button
                  key={f.id}
                  onClick={() => setActive(f.id)}
                  style={{
                    textAlign: "left", padding: "9px 11px", borderRadius: "var(--radius-md)",
                    border: "1px solid", cursor: "pointer", fontFamily: "var(--font-ui)",
                    borderColor: on ? "var(--brand)" : "var(--border)",
                    background: on ? "color-mix(in srgb, var(--brand) 12%, transparent)" : "rgba(255,255,255,0.02)",
                  }}
                >
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-0)" }}>{f.title}</div>
                  <div className="dim" style={{ fontSize: 11 }}>{f.controls_total} controls</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Rendered framework */}
        <div className="card" style={{ minWidth: 0 }}>
          {loadingCov || !cov ? (
            <SkeletonCard lines={6} />
          ) : (
            <FrameworkView cov={cov} key={cov.id} />
          )}
          {!loadingCov && !cov && activeMeta && (
            <div className="dim">No coverage data.</div>
          )}
        </div>
      </div>
    </div>
  );
}
