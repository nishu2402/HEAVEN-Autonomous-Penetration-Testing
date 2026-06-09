// HEAVEN — Autonomous Loop launcher + live result viewer
//
// The run executes as a BACKGROUND job on the server (POST /api/autonomous/run
// returns a job_id immediately). This page then shows progress two ways:
//   1. A WebSocket (/api/autonomous/jobs/{id}/stream) pushes each iteration the
//      instant it finishes — a live, real-time table.
//   2. Polling GET /api/autonomous/jobs/{id} is kept as a fallback (covers a
//      dropped socket, a proxy that blocks WS, or a late page load).
// The active job_id is persisted to sessionStorage, so the run survives
// navigating away and back — and a full page refresh.

import React, { useState, useRef, useEffect, useCallback } from "react";
import { Autonomous, Engagement, openAutonomousStream } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";

const JOB_KEY = "heaven.autonomous.job";
const POLL_MS = 4000;

function loadStoredJob() {
  try {
    const raw = sessionStorage.getItem(JOB_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function storeJob(job) {
  try {
    if (job) sessionStorage.setItem(JOB_KEY, JSON.stringify(job));
    else sessionStorage.removeItem(JOB_KEY);
  } catch {
    /* sessionStorage unavailable — degrade to in-memory only */
  }
}

// Merge iteration rows, de-duped by iteration number `n`, sorted ascending.
function mergeRows(...lists) {
  const byN = new Map();
  for (const list of lists) {
    for (const row of list || []) {
      if (row && typeof row.n === "number") byN.set(row.n, row);
    }
  }
  return [...byN.values()].sort((a, b) => a.n - b.n);
}

export default function AutonomousPage() {
  const [engagement, setEngagement] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [maxIter, setMaxIter] = useState(5);
  const [budget, setBudget] = useState(600);
  const [objective, setObjective] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const [job, setJob] = useState(() => loadStoredJob());
  const [liveRows, setLiveRows] = useState(() => loadStoredJob()?.progress || []);
  const [streaming, setStreaming] = useState(false);
  const pollRef = useRef(null);
  const wsRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  const closeStream = useCallback(() => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch { /* already closed */ }
      wsRef.current = null;
    }
    setStreaming(false);
  }, []);

  const finish = useCallback((finalJob) => {
    setJob(finalJob);
    storeJob(finalJob);
    setLiveRows(mergeRows(finalJob?.progress, finalJob?.result?.iterations));
    stopPolling();
    closeStream();
  }, [stopPolling, closeStream]);

  const pollOnce = useCallback(async (jobId) => {
    try {
      const fresh = await Autonomous.job(jobId);
      setJob(fresh);
      storeJob(fresh);
      setLiveRows((prev) => mergeRows(prev, fresh.progress, fresh.result?.iterations));
      if (fresh.status !== "running") { stopPolling(); closeStream(); }
    } catch (e) {
      stopPolling();
      closeStream();
      setJob((prev) => {
        const next = { ...(prev || {}), status: "error", error: e.message };
        storeJob(next);
        return next;
      });
    }
  }, [stopPolling, closeStream]);

  const startPolling = useCallback((jobId) => {
    stopPolling();
    pollOnce(jobId);
    pollRef.current = setInterval(() => pollOnce(jobId), POLL_MS);
  }, [pollOnce, stopPolling]);

  const startStream = useCallback((jobId) => {
    closeStream();
    const ws = openAutonomousStream(jobId, (msg) => {
      if (!msg) return;
      if (msg.type === "snapshot") {
        setLiveRows((prev) => mergeRows(prev, msg.progress));
        setStreaming(true);
      } else if (msg.type === "iteration") {
        setLiveRows((prev) => mergeRows(prev, [msg.data]));
      } else if (msg.type === "done") {
        if (msg.job) finish(msg.job);
      }
    });
    wsRef.current = ws;
    if (ws) {
      ws.onclose = () => { if (wsRef.current === ws) wsRef.current = null; setStreaming(false); };
      ws.onerror = () => { /* polling fallback already running */ };
    }
  }, [closeStream, finish]);

  // Default engagement to the active one.
  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
  }, []);

  // On mount: resume a stored running job (stream + poll fallback).
  useEffect(() => {
    const stored = loadStoredJob();
    if (stored?.job_id && stored.status === "running") {
      startStream(stored.job_id);
      startPolling(stored.job_id);
    }
    return () => { stopPolling(); closeStream(); };
  }, [startStream, startPolling, stopPolling, closeStream]);

  async function run() {
    setError(null);
    if (!authorized) { setError("You must confirm written authorization before running."); return; }
    const targets = targetsText.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean);
    if (!targets.length) { setError("Enter at least one target."); return; }
    const body = {
      engagement: engagement || undefined,
      ips: targets.filter((t) => !t.startsWith("http")),
      urls: targets.filter((t) => t.startsWith("http")),
      max_iterations: parseInt(maxIter, 10),
      time_budget_s: parseInt(budget, 10),
      objective,
      use_llm: useLLM,
    };
    setSubmitting(true);
    try {
      const { job_id } = await Autonomous.run(body);
      const initial = {
        job_id, status: "running", engagement: engagement || null,
        seeds: { ips: body.ips, urls: body.urls }, objective,
        max_iterations: body.max_iterations, started_at: Date.now() / 1000,
        result: null, error: null, progress: [],
      };
      setJob(initial);
      storeJob(initial);
      setLiveRows([]);
      startStream(job_id);
      startPolling(job_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  }

  function clearJob() {
    stopPolling();
    closeStream();
    setJob(null);
    setLiveRows([]);
    storeJob(null);
  }

  const isRunning = job?.status === "running";
  const result = job?.result;
  // While running, render the live rows; once done, the authoritative summary.
  const rows = result?.iterations?.length ? result.iterations : liveRows;

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--crit)", marginTop: 0 }}>⚙ Autonomous Loop</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Iterative observe → plan → act loop. The LLM-driven planner picks
          the next action each iteration; falls back to a deterministic
          rule-based playbook when no <code>ANTHROPIC/OPENAI/GEMINI</code> key
          is set. Runs in the background with <strong>live streaming</strong> —
          you can leave this page and come back; the run keeps going. For very
          long runs the CLI streams progress too:
          <code style={{ display: "block", marginTop: 4 }}>
            heaven autonomous -t &lt;target&gt; --engagement &lt;name&gt; --max-iterations 8 --i-have-authorization
          </code>
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <div style={{ gridColumn: "1 / -1" }}>
            <label className="form-label">Targets (URLs or IPs, one per line)</label>
            <textarea
              value={targetsText} rows={3}
              placeholder={"10.0.0.5\nhttps://app.example.com"}
              onChange={(e) => setTargetsText(e.target.value)}
              style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
            />
          </div>
          <div>
            <label className="form-label">Engagement</label>
            <input type="text" value={engagement}
                   onChange={(e) => setEngagement(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }}
                   placeholder="active engagement name" />
          </div>
          <div>
            <label className="form-label">Objective (optional)</label>
            <input type="text" value={objective}
                   onChange={(e) => setObjective(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }}
                   placeholder="rce on internal host" />
          </div>
          <div>
            <label className="form-label">Max iterations</label>
            <input type="number" min={1} max={20} value={maxIter}
                   onChange={(e) => setMaxIter(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }} />
          </div>
          <div>
            <label className="form-label">Time budget (seconds)</label>
            <input type="number" min={60} max={3600} value={budget}
                   onChange={(e) => setBudget(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }} />
          </div>
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <input type="checkbox" checked={useLLM}
                 onChange={(e) => setUseLLM(e.target.checked)} />
          <span>Use LLM planner (falls back to rule-based when no API key set)</span>
        </label>
        <label style={{ display: "flex", alignItems: "flex-start", gap: 10,
                        color: authorized ? "var(--text-0)" : "var(--med)", marginBottom: 12 }}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I confirm written authorization for every target listed.</span>
        </label>

        <button className="btn" disabled={submitting || isRunning || !authorized} onClick={run}>
          {submitting ? "Starting…" : isRunning ? "Run in progress…" : "Launch autonomous run"}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {/* Live run banner */}
      {isRunning && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="scan-running-dot" />
            <strong style={{ color: "var(--text-0)" }}>Autonomous run in progress</strong>
            <span className="dim" style={{ fontSize: 12 }}>
              job {job.job_id} · {rows.length} iteration{rows.length === 1 ? "" : "s"} so far
              {streaming ? " · live" : " · polling"}
              {job.engagement ? ` · ${job.engagement}` : ""}
            </span>
          </div>
          {rows.length === 0 && (
            <div style={{ marginTop: 8 }}><SkeletonCard lines={3} /></div>
          )}
        </div>
      )}

      {job?.status === "error" && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="error">Autonomous run failed: {job.error || "unknown error"}</div>
          <button className="btn-small" style={{ marginTop: 10 }} onClick={clearJob}>Dismiss</button>
        </div>
      )}

      {/* Iteration table — live while running, authoritative summary when done */}
      {(rows.length > 0 || result) && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <h3 style={{ color: "var(--text-0)", margin: 0 }}>
              {result ? (
                <>Run summary — <span style={{ color: "var(--cyan)" }}>{result.stop_reason}</span></>
              ) : "Live progress"}
            </h3>
            {!isRunning && <button className="btn-small" onClick={clearJob}>Clear</button>}
          </div>
          {result && (
            <div className="dim" style={{ fontSize: 12, marginTop: 6 }}>
              Iterations: {result.iterations_run} · Duration: {result.duration_s?.toFixed(0)}s ·
              Findings: {result.total_findings} (critical: {result.total_critical}, high: {result.total_high})
            </div>
          )}
          {result?.objective_met && (
            <div style={{ color: "var(--text-0)", marginTop: 8 }}>
              ✓ Objective met: {result.objective}
            </div>
          )}
          <table style={{ width: "100%", marginTop: 12, fontSize: 12 }}>
            <thead><tr style={{ color: "var(--cyan)" }}>
              <th align="left">#</th><th align="left">Action</th>
              <th align="left">Target</th><th align="right">+Find</th>
              <th align="right">Reward</th><th align="left">Rationale</th>
            </tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.n}>
                  <td>{r.n}</td>
                  <td>{r.action?.kind}</td>
                  <td><code>{(r.action?.target || "").slice(0, 32)}</code></td>
                  <td align="right">{r.new_findings}</td>
                  <td align="right">{typeof r.reward === "number" ? r.reward.toFixed(2) : r.reward}</td>
                  <td className="dim" style={{ fontSize: 11 }}>{r.action?.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
