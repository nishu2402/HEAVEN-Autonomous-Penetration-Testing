// HEAVEN — Methodology mapping viewer (Gap 9)
//
// Renders the OWASP / NIST / PTES mapping docs the operator can show
// reviewers so they know which scanner output maps to which test ID.

import React, { useEffect, useState } from "react";
import { Methodology as M } from "../api";

const PRETTY = {
  owasp_testing_guide: "OWASP Testing Guide v4",
  nist_800_115:        "NIST SP 800-115",
  ptes:                "Penetration Testing Execution Standard",
};

export default function Methodology() {
  const [docs, setDocs]   = useState(null);
  const [error, setError] = useState(null);
  const [active, setActive] = useState(null);

  useEffect(() => {
    M.list()
      .then((d) => {
        setDocs(d.docs || []);
        if (d.docs?.length) setActive(d.docs[0].name);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="page">
        <div className="card error">{error}</div>
      </div>
    );
  }

  if (!docs) {
    return (
      <div className="page">
        <div className="card"><span className="dim blink">Loading methodology docs…</span></div>
      </div>
    );
  }

  const current = docs.find((d) => d.name === active);

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>§ Methodology Mapping</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Which HEAVEN scanner maps to which test ID in each standard.
          Use this to satisfy enterprise procurement and academic review.
        </p>

        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          {docs.map((d) => (
            <button
              key={d.name}
              className={"btn-small" + (active === d.name ? " active" : "")}
              onClick={() => setActive(d.name)}
            >
              {PRETTY[d.name] || d.name}
            </button>
          ))}
        </div>

        {current && (
          <pre
            style={{
              padding: 12,
              background: "rgba(0,0,0,0.4)",
              border: "1px solid var(--border)",
              fontFamily: "monospace",
              fontSize: 12,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              maxHeight: "70vh",
              overflowY: "auto",
            }}
          >
            {current.content}
          </pre>
        )}
      </div>
    </div>
  );
}
