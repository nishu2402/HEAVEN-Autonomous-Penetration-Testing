// HEAVEN — Benchmark page
//
// Shows the latest scanner benchmark: precision / recall / F1 against a labelled
// ground-truth set. The API prefers a valid live Docker-DVWA aggregate and falls
// back to the always-fresh native controlled benchmark (`heaven benchmark`), and
// never surfaces a failed washout run. This page renders the parsed headline
// metrics as tiles plus the full report as real Markdown, and says exactly which
// target produced the numbers so nothing is overstated.

import React, { useEffect, useState } from "react";
import { Benchmark as B } from "../api";
import { SkeletonLine, EmptyState } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";

function fmtWhen(iso) {
  if (!iso) return null;
  try {
    const d = new Date(iso);
    const diffMs = Date.now() - d.getTime();
    const mins = Math.round(diffMs / 60000);
    let rel;
    if (mins < 1) rel = "just now";
    else if (mins < 60) rel = `${mins} min ago`;
    else if (mins < 1440) rel = `${Math.round(mins / 60)} h ago`;
    else rel = `${Math.round(mins / 1440)} d ago`;
    return `${d.toLocaleString()} (${rel})`;
  } catch {
    return iso;
  }
}

const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);

// Per-source explanatory caption — keeps the claim honest.
const SOURCE_NOTE = {
  "native-controlled":
    "Controlled functional benchmark: HEAVEN's real detectors run against a " +
    "faithful, in-process reproduction of DVWA's vulnerable endpoints. Docker-free " +
    "and regenerated on every test run — not a claim against any live third-party app.",
  "live-dvwa":
    "Live benchmark: HEAVEN scanned a real Docker DVWA instance, scored against " +
    "the DVWA ground-truth set and aggregated over multiple runs.",
};

function MetricTile({ label, value, hint }) {
  return (
    <div className="mini-stat">
      <div className="mini-stat-label">{label}</div>
      <div className="mini-stat-value">{value}</div>
      {hint && <div className="mini-stat-sub">{hint}</div>}
    </div>
  );
}

export default function Benchmark() {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);

  function load() {
    setError(null);
    setData(null);
    B.latest().then(setData).catch((e) => setError(e.message));
  }

  useEffect(load, []);

  const m = data?.metrics || null;
  const isNative = data?.source === "native-controlled";

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
          <div>
            <h2 style={{ color: "var(--text-0)", marginTop: 0, marginBottom: 4 }}>
              ≡ Scanner Benchmark
            </h2>
            <p className="page-lead" style={{ margin: 0 }}>
              Precision / recall / F1 against a labelled ground-truth target.
            </p>
          </div>
          <button className="btn-small" onClick={load}>↻ Refresh</button>
        </div>

        {data && data.available && (
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-2)" }}>
            <span style={{ color: "var(--brand)", fontWeight: 700 }}>● </span>
            {data.label || "Benchmark"}
            {data.generated_at ? <> · generated <strong style={{ color: "var(--text-1)" }}>{fmtWhen(data.generated_at)}</strong></> : null}
            {data.target ? <> · target <code>{data.target}</code></> : null}
          </div>
        )}

        {/* Headline metric tiles (parsed from the report) */}
        {data && data.available && m && (
          <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", marginTop: 14 }}>
            <MetricTile label="Precision" value={pct(m.precision)} hint="findings that were real" />
            <MetricTile label="Recall" value={pct(m.recall)} hint="required GT detected" />
            <MetricTile label="F1" value={pct(m.f1)} hint="harmonic mean" />
          </div>
        )}

        {data && data.available && SOURCE_NOTE[data.source] && (
          <p className="dim" style={{ fontSize: 11.5, lineHeight: 1.6, marginTop: 12, marginBottom: 0 }}>
            {SOURCE_NOTE[data.source]}
          </p>
        )}

        <p className="dim" style={{ fontSize: 12, marginTop: 14, marginBottom: 6 }}>
          To (re)generate the built-in benchmark — Docker-free, ~1&nbsp;s:
        </p>
        <pre className="cli-block" style={{ marginBottom: 8 }}>{`heaven benchmark`}</pre>
        <p className="dim" style={{ fontSize: 12, marginTop: 0, marginBottom: 6 }}>
          For a live head-to-head against a real Docker DVWA instance:
        </p>
        <pre className="cli-block" style={{ marginBottom: 0 }}>{`HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=3 pytest tests/benchmarks/test_dvwa_baseline.py -v`}</pre>

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
            body={data.note || "Run `heaven benchmark` on the server, then click Refresh to load the results here."}
          />
        )}

        {data && data.available && (
          <div className="md-block" style={{ marginTop: 14, maxHeight: "none" }}>
            <Markdown>{data.markdown}</Markdown>
          </div>
        )}
      </div>
    </div>
  );
}
