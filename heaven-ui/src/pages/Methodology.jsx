// HEAVEN — Methodology mapping viewer (Gap 9)
//
// Renders the OWASP / NIST / PTES mapping docs (Markdown with coverage tables)
// so reviewers can see which scanner output maps to which standard test ID.
// Previously the raw Markdown was dumped into a <pre>, so the mapping tables
// showed as unreadable pipe-delimited text — now they render as real tables.

import React, { useEffect, useMemo, useState } from "react";
import { Methodology as M } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";

const META = {
  owasp_testing_guide: { title: "OWASP Testing Guide", sub: "WSTG v4.2" },
  nist_800_115:        { title: "NIST SP 800-115", sub: "Technical assessment" },
  ptes:                { title: "PTES", sub: "Execution standard" },
};

export default function Methodology() {
  const [docs, setDocs]   = useState(null);
  const [error, setError] = useState(null);
  const [active, setActive] = useState(null);

  useEffect(() => {
    M.list()
      .then((d) => {
        const list = d.docs || [];
        setDocs(list);
        if (list.length) setActive(list[0].name);
      })
      .catch((e) => setError(e.message));
  }, []);

  const current = useMemo(
    () => (docs || []).find((d) => d.name === active),
    [docs, active],
  );

  if (error) {
    return (
      <div className="page">
        <div className="card error">{error}</div>
      </div>
    );
  }
  if (!docs) {
    return <div className="page"><SkeletonCard lines={8} /></div>;
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>§ Methodology Mapping</h2>
        <p className="dim" style={{ fontSize: 12, lineHeight: 1.6, marginBottom: 0 }}>
          Which HEAVEN scanner maps to which test ID in each industry standard —
          use it to satisfy enterprise procurement and academic review. Rows marked{" "}
          <code>(manual)</code> are intentionally out of scope for automation.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 220px) 1fr",
                    gap: 12, marginTop: 12, alignItems: "start" }}>
        {/* Standard selector */}
        <div className="card" style={{ padding: 10, position: "sticky", top: 12 }}>
          <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
                        color: "var(--text-2)", fontWeight: 600, margin: "2px 6px 8px" }}>
            Standards
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            {docs.map((d) => {
              const meta = META[d.name] || { title: d.name, sub: "" };
              const on = active === d.name;
              return (
                <button
                  key={d.name}
                  onClick={() => setActive(d.name)}
                  style={{
                    textAlign: "left", padding: "9px 11px", borderRadius: "var(--radius-md)",
                    border: "1px solid", cursor: "pointer", fontFamily: "var(--font-ui)",
                    borderColor: on ? "var(--brand)" : "var(--border)",
                    background: on ? "color-mix(in srgb, var(--brand) 12%, transparent)"
                                   : "rgba(255,255,255,0.02)",
                  }}
                >
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-0)" }}>
                    {meta.title}
                  </div>
                  {meta.sub && (
                    <div className="dim" style={{ fontSize: 11 }}>{meta.sub}</div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Rendered doc */}
        <div className="card" style={{ minWidth: 0 }}>
          {current
            ? <Markdown>{current.content}</Markdown>
            : <div className="dim" style={{ fontSize: 12 }}>No methodology documents found.</div>}
        </div>
      </div>
    </div>
  );
}
