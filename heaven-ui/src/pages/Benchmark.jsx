// HEAVEN — Benchmark page
//
// Shows the latest scanner benchmarks: precision / recall / F1 against labelled
// ground-truth targets, one card per tier. The API returns every tier present on
// disk — the always-on native web + API tiers, plus the live DVWA / Metasploitable-2
// runs once an operator has produced them — and never surfaces a failed washout
// run. Each card renders the parsed headline metrics as tiles plus the full report
// as real Markdown, and says exactly which target produced the numbers so nothing
// is overstated.

import React, { useEffect, useState } from "react";
import { Benchmark as B } from "../api";
import { SkeletonLine, EmptyState } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";
import { useToast } from "../components/Toast.jsx";

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
    "Controlled functional benchmark: HEAVEN's real web detectors run against a " +
    "faithful, in-process reproduction of DVWA's vulnerable endpoints. Docker-free " +
    "and regenerated on every run, not a claim against any live third-party app.",
  "native-controlled-api":
    "Controlled functional benchmark: HEAVEN's real API scanner (OWASP API Top 10) " +
    "runs against a faithful, in-process reproduction of a BOLA / mass-assignment / " +
    "secret-leak / GraphQL-vulnerable API. Docker-free and regenerated on every run, " +
    "not a claim against any live third-party API.",
  "live-dvwa":
    "Live benchmark: HEAVEN scanned a real Docker DVWA instance, scored against " +
    "the DVWA ground-truth set and aggregated over multiple runs.",
  "live-network":
    "Live benchmark: HEAVEN scanned a real Metasploitable-2 host in network / " +
    "service mode, scored against the MSF2 ground-truth set. Reproduce against your " +
    "own authorised lab with the msf2 baseline test.",
};

// A small tier badge so the web vs. API vs. network distinction reads at a glance.
const TIER_BADGE = {
  "native-controlled": { text: "WEB · native", color: "var(--brand)" },
  "native-controlled-api": { text: "API · native", color: "var(--brand)" },
  "live-dvwa": { text: "WEB · live", color: "var(--ok, #34d399)" },
  "live-network": { text: "NETWORK · live", color: "var(--ok, #34d399)" },
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

function TierCard({ tier, dim }) {
  const m = tier.metrics || null;
  const badge = TIER_BADGE[tier.source];
  return (
    <div
      className="card"
      style={{ marginTop: 14, opacity: dim ? 0.5 : 1, transition: "opacity .2s" }}
    >
      <div style={{ fontSize: 12, color: "var(--text-2)" }}>
        {badge && (
          <span
            style={{
              display: "inline-block", fontSize: 10, fontWeight: 800, letterSpacing: 0.5,
              padding: "2px 7px", borderRadius: 6, marginRight: 8,
              color: badge.color, border: `1px solid ${badge.color}`,
            }}
          >
            {badge.text}
          </span>
        )}
        <strong style={{ color: "var(--text-1)" }}>{tier.label || "Benchmark"}</strong>
        {tier.generated_at ? <> · generated {fmtWhen(tier.generated_at)}</> : null}
        {tier.target ? <> · target <code>{tier.target}</code></> : null}
      </div>

      {m && (
        <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", marginTop: 12 }}>
          <MetricTile label="Precision" value={pct(m.precision)} hint="findings that were real" />
          <MetricTile label="Recall" value={pct(m.recall)} hint="required GT detected" />
          <MetricTile label="F1" value={pct(m.f1)} hint="harmonic mean" />
        </div>
      )}

      {SOURCE_NOTE[tier.source] && (
        <p className="dim" style={{ fontSize: 11.5, lineHeight: 1.6, marginTop: 12, marginBottom: 0 }}>
          {SOURCE_NOTE[tier.source]}
        </p>
      )}

      {tier.markdown && (
        <div className="md-block" style={{ marginTop: 12, maxHeight: "none" }}>
          <Markdown>{tier.markdown}</Markdown>
        </div>
      )}
    </div>
  );
}

export default function Benchmark() {
  const toast = useToast();
  const [data, setData]     = useState(null);
  const [error, setError]   = useState(null);
  const [running, setRunning] = useState(false);

  // Initial paint from the last cached reports (fast, read-only).
  function load() {
    setError(null);
    setData(null);
    B.latest().then(setData).catch((e) => setError(e.message));
  }

  // Actually re-run the native, Docker-free benchmarks on the server and show the
  // fresh numbers. Keeps the current reports visible (dimmed) while it runs
  // instead of blanking the page, and surfaces any server error verbatim.
  async function rerun() {
    setRunning(true);
    setError(null);
    try {
      const fresh = await B.run();
      setData(fresh);
      toast.success?.("Benchmark re-run complete");
    } catch (e) {
      setError(e.message);
      toast.error?.("Benchmark re-run failed");
    } finally {
      setRunning(false);
    }
  }

  useEffect(load, []);

  // Prefer the tiers array; fall back to the pre-tiers single-object shape so an
  // older server still renders.
  const tiers =
    data && data.available
      ? (data.tiers && data.tiers.length ? data.tiers : (data.markdown ? [data] : []))
      : [];

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
          <div>
            <h2 style={{ color: "var(--text-0)", marginTop: 0, marginBottom: 4 }}>
              ≡ Scanner Benchmark
            </h2>
            <p className="page-lead" style={{ margin: 0 }}>
              Precision / recall / F1 against labelled ground-truth targets, per tier.
            </p>
          </div>
          <button
            className="btn-small"
            onClick={rerun}
            disabled={running}
            title="Re-run the native, Docker-free benchmarks (web + API) on the server and load fresh numbers"
          >
            {running ? "⏳ Running…" : "↻ Re-run benchmarks"}
          </button>
        </div>

        {running && (
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-2)" }}>
            Running the native benchmarks on the server (Docker-free, web + API),
            this usually takes a few seconds…
          </div>
        )}

        <p className="dim" style={{ fontSize: 12, marginTop: 14, marginBottom: 6 }}>
          To (re)generate the built-in benchmarks, Docker-free, ~1&nbsp;s each:
        </p>
        <pre className="cli-block" style={{ marginBottom: 8 }}>{`heaven benchmark --tier all`}</pre>
        <p className="dim" style={{ fontSize: 12, marginTop: 0, marginBottom: 6 }}>
          For a live head-to-head against a real Docker DVWA / Metasploitable-2 lab:
        </p>
        <pre className="cli-block" style={{ marginBottom: 0 }}>{`HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py tests/benchmarks/test_msf2_baseline.py -v`}</pre>

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
            headline="No benchmark reports yet"
            body={data.note || "Run `heaven benchmark --tier all` on the server, then Refresh to load the results here."}
          />
        )}
      </div>

      {tiers.map((tier, i) => (
        <TierCard key={tier.source || i} tier={tier} dim={running} />
      ))}
    </div>
  );
}
