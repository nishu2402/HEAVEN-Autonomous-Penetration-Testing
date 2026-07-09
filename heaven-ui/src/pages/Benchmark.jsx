// HEAVEN — Benchmark page (Gap 1)
//
// Shows the latest aggregated DVWA benchmark report. Operator runs the
// benchmark from the CLI (`HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/`)
// and this page renders the resulting markdown.

import React, { useEffect, useState } from "react";
import { Benchmark as B } from "../api";
import { SkeletonLine, EmptyState } from "../components/Skeleton.jsx";

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
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>≡ Benchmark — HEAVEN vs. DVWA</h2>
        <p className="page-lead">
          Latest aggregated report from <code>tests/benchmarks/reports/dvwa_aggregated.md</code>.
          To produce / refresh, run on the server:
        </p>
        <pre className="cli-block" style={{ marginBottom: 12 }}>{`HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=3 pytest tests/benchmarks/test_dvwa_baseline.py -v`}</pre>
        <button className="btn-small" onClick={load}>Refresh</button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

        {!data && !error && (
          <div style={{ marginTop: 12 }}>
            <SkeletonLine width="40%" />
            <div style={{ height: 8 }} />
            <SkeletonLine /><SkeletonLine width="92%" /><SkeletonLine width="70%" />
          </div>
        )}

        {data && data.available === false && (
          <EmptyState
            icon="≡"
            headline="No benchmark report yet"
            body={data.note || "Run the DVWA benchmark on the server (command above), then click Refresh to load the results here."}
          />
        )}

        {data && data.available && (
          <pre className="cli-block" style={{ marginTop: 12, wordBreak: "break-word" }}>
            {data.markdown}
          </pre>
        )}
      </div>
    </div>
  );
}
