// HEAVEN — Benchmark page (Gap 1)
//
// Shows the latest aggregated DVWA benchmark report. Operator runs the
// benchmark from the CLI (`HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/`)
// and this page renders the resulting markdown.

import React, { useEffect, useState } from "react";
import { Benchmark as B } from "../api";

export default function Benchmark() {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);

  function load() {
    setError(null);
    B.latest().then(setData).catch((e) => setError(e.message));
  }

  useEffect(load, []);

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#00FF41", marginTop: 0 }}>≡ Benchmark — HEAVEN vs. DVWA</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Latest aggregated report from <code>tests/benchmarks/reports/dvwa_aggregated.md</code>.
          To produce / refresh, run on the server:
          <code style={{ display: "block", marginTop: 4 }}>
            HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=3 pytest tests/benchmarks/test_dvwa_baseline.py -v
          </code>
        </p>
        <button className="btn-small" onClick={load}>Refresh</button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

        {data && data.available === false && (
          <div style={{ marginTop: 12 }} className="dim">
            {data.note || "No benchmark report yet."}
          </div>
        )}

        {data && data.available && (
          <pre
            style={{
              marginTop: 12,
              padding: 12,
              background: "rgba(0,0,0,0.4)",
              border: "1px solid rgba(0,255,65,0.2)",
              fontFamily: "monospace",
              fontSize: 12,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {data.markdown}
          </pre>
        )}
      </div>
    </div>
  );
}
