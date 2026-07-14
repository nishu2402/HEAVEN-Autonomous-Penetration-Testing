// HEAVEN — Methodology coverage (live).
//
// Renders the OWASP WSTG / NIST SP 800-115 / PTES mapping as a structured,
// interactive coverage matrix — NOT a static Markdown dump. Summary counts are
// computed server-side from the mapping rows, and every row is overlaid with
// the ACTIVE ENGAGEMENT's real findings: a row is flagged "exercised" when the
// detector it names actually produced a finding in this engagement. So the page
// reflects what THIS assessment covered and stays in sync with the CLI
// (`heaven methodology coverage`) and the Findings data.

import React, { useEffect, useMemo, useState } from "react";
import { Methodology as M } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";

const STATUS_META = {
  automated: { label: "AUTO", color: "var(--brand)", bg: "color-mix(in srgb, var(--brand) 14%, transparent)" },
  partial:   { label: "PARTIAL", color: "var(--amber)", bg: "color-mix(in srgb, var(--amber) 16%, transparent)" },
  manual:    { label: "MANUAL", color: "var(--text-2)", bg: "rgba(255,255,255,0.04)" },
};

function StatusChip({ status }) {
  const m = STATUS_META[status] || STATUS_META.manual;
  return (
    <span style={{
      display: "inline-block", padding: "2px 7px", borderRadius: 5, fontSize: 10,
      fontWeight: 700, letterSpacing: "0.04em", color: m.color, background: m.bg,
      border: `1px solid ${m.color}`, whiteSpace: "nowrap",
    }}>{m.label}</span>
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

// Render inline `code` spans inside a coverage/description cell.
function inlineCode(text) {
  const parts = String(text || "").split(/(`[^`]+`)/);
  return parts.map((p, i) =>
    p.startsWith("`") && p.endsWith("`")
      ? <code key={i} className="md-inline-code">{p.slice(1, -1)}</code>
      : <React.Fragment key={i}>{p}</React.Fragment>);
}

export default function Methodology() {
  const [data, setData]   = useState(null);   // {standards, engagement}
  const [error, setError] = useState(null);
  const [active, setActive] = useState(null);

  useEffect(() => {
    M.list()
      .then((d) => {
        setData(d);
        const list = d.standards || [];
        if (list.length) setActive(list[0].name);
      })
      .catch((e) => setError(e.message));
  }, []);

  const standards = data?.standards || [];
  const engagement = data?.engagement || {};
  const current = useMemo(
    () => standards.find((s) => s.name === active),
    [standards, active],
  );

  if (error) {
    return <div className="page"><div className="card error">{error}</div></div>;
  }
  if (!data) {
    return <div className="page"><SkeletonCard lines={8} /></div>;
  }

  const engName = engagement.name || "active engagement";
  const findingsTotal = engagement.findings_total || 0;

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>§ Methodology Coverage</h2>
        <p className="dim" style={{ fontSize: 12, lineHeight: 1.6, marginBottom: 0 }}>
          How HEAVEN's scanners map to each industry standard's test IDs — with a{" "}
          <strong style={{ color: "var(--brand)" }}>live overlay</strong> of what your
          current engagement actually exercised. A test is marked{" "}
          <span style={{ color: "var(--brand)", fontWeight: 600 }}>✓ exercised</span> when
          the detector it lists produced a finding in <code>{engName}</code>. Rows marked{" "}
          <StatusChip status="manual" /> are intentionally out of scope for automation.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(190px, 230px) 1fr",
                    gap: 12, marginTop: 12, alignItems: "start" }}>
        {/* Standard selector */}
        <div className="card" style={{ padding: 10, position: "sticky", top: 12 }}>
          <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
                        color: "var(--text-2)", fontWeight: 600, margin: "2px 6px 8px" }}>
            Standards
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            {standards.map((s) => {
              const on = active === s.name;
              const su = s.summary || {};
              return (
                <button
                  key={s.name}
                  onClick={() => setActive(s.name)}
                  style={{
                    textAlign: "left", padding: "9px 11px", borderRadius: "var(--radius-md)",
                    border: "1px solid", cursor: "pointer", fontFamily: "var(--font-ui)",
                    borderColor: on ? "var(--brand)" : "var(--border)",
                    background: on ? "color-mix(in srgb, var(--brand) 12%, transparent)"
                                   : "rgba(255,255,255,0.02)",
                  }}
                >
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-0)" }}>
                    {s.meta_title || s.title}
                  </div>
                  <div className="dim" style={{ fontSize: 11 }}>{s.subtitle}</div>
                  <div style={{ fontSize: 10.5, marginTop: 4, color: "var(--text-2)" }}>
                    {su.covered}/{su.total} automated
                    {su.exercised ? <span style={{ color: "var(--brand)" }}> · ✓{su.exercised} live</span> : null}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Rendered standard */}
        <div className="card" style={{ minWidth: 0 }}>
          {current ? <StandardView std={current} engName={engName} findingsTotal={findingsTotal} />
                   : <div className="dim">No methodology documents found.</div>}
        </div>
      </div>
    </div>
  );
}

function StandardView({ std, engName, findingsTotal }) {
  const su = std.summary || {};
  const covPct = su.total ? Math.round((100 * su.covered) / su.total) : 0;

  return (
    <div>
      <h3 style={{ margin: "0 0 6px", color: "var(--text-0)" }}>{std.title}</h3>
      {std.intro && (
        <div className="dim" style={{ fontSize: 12, lineHeight: 1.6, marginTop: 0 }}>
          <Markdown>{std.intro}</Markdown>
        </div>
      )}

      {/* Live engagement banner */}
      <div style={{
        margin: "12px 0 14px", padding: "10px 14px", borderRadius: "var(--radius-md)",
        border: "1px solid color-mix(in srgb, var(--brand) 35%, transparent)",
        background: "color-mix(in srgb, var(--brand) 8%, transparent)",
        fontSize: 12.5, color: "var(--text-1)", lineHeight: 1.5,
      }}>
        {findingsTotal > 0 ? (
          <>
            <span style={{ color: "var(--brand)", fontWeight: 700 }}>● Live</span>{" "}
            <code>{engName}</code> exercised{" "}
            <strong style={{ color: "var(--brand)" }}>{su.exercised || 0}</strong> of {su.total}{" "}
            methodology tests ({su.exercised_covered || 0} of {su.covered} automated) across{" "}
            <strong>{findingsTotal}</strong> finding{findingsTotal === 1 ? "" : "s"}.
          </>
        ) : (
          <>
            <span style={{ color: "var(--text-2)", fontWeight: 700 }}>○ Idle</span>{" "}
            No findings in <code>{engName}</code> yet — run a scan to light up the tests
            your engagement exercises.
          </>
        )}
      </div>

      {/* Computed summary tiles */}
      <div className="mini-stat-grid" style={{
        gridTemplateColumns: "repeat(4, 1fr)", marginBottom: 16,
      }}>
        <Tile label="Tests mapped" value={su.total} />
        <Tile label="Automated" value={su.covered} sub={`${covPct}% · auto ${su.automated} · partial ${su.partial}`} />
        <Tile label="Manual / OOS" value={su.manual} />
        <Tile label="Exercised here" value={su.exercised || 0} sub="detector fired" alert />
      </div>

      {/* Per-category tables */}
      {std.categories.map((cat) => (
        <CategoryTable key={cat.title} cat={cat} />
      ))}
    </div>
  );
}

function CategoryTable({ cat }) {
  const rows = cat.rows || [];
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, margin: "0 0 8px" }}>
        <h4 style={{ margin: 0, color: "var(--brand)", fontSize: 13.5 }}>{cat.title}</h4>
        {cat.exercised ? (
          <span style={{ fontSize: 10.5, color: "var(--brand)", fontWeight: 600 }}>
            ✓ {cat.exercised} exercised
          </span>
        ) : null}
      </div>
      {rows.length === 0 ? (
        <p className="dim" style={{ fontSize: 12, margin: 0 }}>
          {cat.note || "No automated tests in this category."}
        </p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>
            <thead>
              <tr>
                {["Test", "Description", "HEAVEN detector", "Status"].map((h) => (
                  <th key={h} style={{
                    textAlign: "left", padding: "6px 10px", color: "var(--text-2)",
                    fontWeight: 600, borderBottom: "2px solid var(--border)", whiteSpace: "nowrap",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.id + i} style={{
                  background: r.exercised
                    ? "color-mix(in srgb, var(--brand) 7%, transparent)"
                    : (i % 2 ? "rgba(255,255,255,0.015)" : "transparent"),
                }}>
                  <td style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)",
                               verticalAlign: "top", whiteSpace: "nowrap", fontFamily: "var(--font-mono)",
                               color: "var(--text-0)", fontSize: 11.5 }}>
                    {r.exercised && <span title="Exercised in this engagement"
                      style={{ color: "var(--brand)", marginRight: 5 }}>✓</span>}
                    {r.id}
                  </td>
                  <td style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)",
                               verticalAlign: "top", color: "var(--text-1)" }}>
                    {inlineCode(r.description || r.item)}
                  </td>
                  <td style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)",
                               verticalAlign: "top", color: "var(--text-2)", fontSize: 11.5 }}>
                    {inlineCode(r.coverage)}
                    {r.exercised_count > 0 && (
                      <span style={{ marginLeft: 6, color: "var(--brand)", fontWeight: 600, fontSize: 11 }}>
                        · {r.exercised_count} finding{r.exercised_count === 1 ? "" : "s"}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)",
                               verticalAlign: "top" }}>
                    <StatusChip status={r.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
