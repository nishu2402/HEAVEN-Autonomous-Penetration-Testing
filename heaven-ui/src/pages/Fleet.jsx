// HEAVEN — Agent Fleet launcher + live result viewer
//
// The fleet runs as a BACKGROUND job on the server (POST /api/fleet/run returns a
// job_id immediately). Progress is shown two ways, exactly like the Autonomous
// page: a WebSocket (/api/fleet/jobs/{id}/stream) pushes each iteration the moment
// it finishes, and polling GET /api/fleet/jobs/{id} is the fallback. The active
// job_id is persisted to sessionStorage so the run survives navigating away.
//
// The web launcher is strictly READ-ONLY: the Exploit lead and active hypothesis
// verification stay behind the CLI's `heaven fleet --i-have-authorization`, so a
// browser can never arm active exploitation.

import React, { useState, useRef, useEffect, useCallback } from "react";
import { Link } from "react-router";
import { Fleet, Engagement, openFleetStream } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import TargetsInput from "../components/TargetsInput.jsx";
import EngagementPicker from "../components/EngagementPicker.jsx";

const JOB_KEY = "heaven.fleet.job";
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

export default function FleetPage() {
  const [engagement, setEngagement] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [mode, setMode] = useState("full");
  const [modes, setModes] = useState(["full"]);
  const [maxIter, setMaxIter] = useState(6);
  const [budget, setBudget] = useState(1800);
  const [objective, setObjective] = useState("");
  const [brain, setBrain] = useState(null);
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
      const fresh = await Fleet.job(jobId);
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
    const ws = openFleetStream(jobId, (msg) => {
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

  // Default engagement to the active one; load the honest brain/mode status.
  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
    Fleet.status()
      .then((s) => { setBrain(s); if (Array.isArray(s.modes) && s.modes.length) setModes(s.modes); })
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
    const targets = targetsText.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean);
    if (!targets.length) { setError("Enter at least one target."); return; }
    if (!engagement) { setError("Pick an engagement — the fleet persists every finding."); return; }
    const body = {
      engagement,
      ips: targets.filter((t) => !t.startsWith("http")),
      urls: targets.filter((t) => t.startsWith("http")),
      mode,
      max_iterations: parseInt(maxIter, 10),
      time_budget_s: parseInt(budget, 10),
      objective,
    };
    setSubmitting(true);
    try {
      const { job_id } = await Fleet.run(body);
      const initial = {
        job_id, status: "running", engagement, mode,
        seeds: { ips: body.ips, urls: body.urls }, objective,
        max_iterations: body.max_iterations, authorized: false,
        started_at: Date.now() / 1000, result: null, error: null, progress: [],
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
  const rows = result?.iterations?.length ? result.iterations : liveRows;
  const brainLabel = brain
    ? (brain.available
        ? `${brain.label} brain${brain.model ? ` (${brain.model})` : ""}`
        : "deterministic · AI optional")
    : "…";

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>⚙ Agent Fleet</h2>
        <p className="page-lead">
          A role-scoped multi-agent engine over the whole engagement: one lead
          agent per scan mode plus recon, strategy, hypothesis, FP-critic and
          coverage roles. Agents <strong>propose</strong>, the real deterministic
          oracles <strong>verify</strong> · no agent ever writes a finding. Runs at
          full strength with <strong>no API key</strong>; brain: <code>{brainLabel}</code>.
          On by default and a <strong>superset</strong> of the pipeline (same verify
          oracles plus fan-out), so classic <code>heaven scan</code> stays unchanged.
        </p>
        <pre className="cli-block" style={{ marginBottom: 14 }}>{`heaven fleet -u https://app.example.com --engagement <name> --mode ${mode}`}</pre>
        <p className="dim" style={{ fontSize: 12, marginTop: -6, marginBottom: 12 }}>
          The web launcher is <strong>read-only</strong>. To arm the Exploit lead and
          active hypothesis verification, run <code>heaven fleet --i-have-authorization</code>{" "}
          from the CLI against a target you are authorized to exploit.
          {brain?.scale_out
            ? ` Scale-out is on: ${brain.workers} worker processes share the engagement DB.`
            : " For the very biggest engagements, add "}
          {!brain?.scale_out && <code>heaven fleet --workers N</code>}
          {!brain?.scale_out && " to fan scans across worker processes."}
        </p>

        <div className="scan-form" style={{ marginBottom: 4 }}>
          <div className="form-group form-full">
            <label className="form-label" htmlFor="fleet-targets">
              Seed targets <span className="dim">, type a URL or IP and press Enter · or paste a list</span>
            </label>
            <TargetsInput
              id="fleet-targets"
              value={targetsText}
              onChange={setTargetsText}
              placeholder="e.g. 10.0.0.5  ·  https://app.example.com"
            />
          </div>
          <EngagementPicker value={engagement} onChange={setEngagement}
                            id="fleet-engagement"
                            label="Save findings to engagement" />
          <label className="form-group">
            <span className="form-label">Focus mode</span>
            <select className="form-input" value={mode} onChange={(e) => setMode(e.target.value)}>
              {modes.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
          <label className="form-group">
            <span className="form-label">Objective (optional)</span>
            <input className="form-input" type="text" value={objective}
                   onChange={(e) => setObjective(e.target.value)}
                   placeholder="critical rce on internal host" />
          </label>
          <label className="form-group">
            <span className="form-label">Max iterations</span>
            <input className="form-input" type="number" min={1} max={50} value={maxIter}
                   onChange={(e) => setMaxIter(e.target.value)} />
          </label>
          <label className="form-group">
            <span className="form-label">Time budget (seconds)</span>
            <input className="form-input" type="number" min={30} max={7200} value={budget}
                   onChange={(e) => setBudget(e.target.value)} />
          </label>
        </div>

        <button className="btn btn-primary" disabled={submitting || isRunning} onClick={run}>
          {submitting ? "Starting…" : isRunning ? "Fleet running…" : "Launch fleet run"}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {/* Live run banner */}
      {isRunning && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="scan-running-dot" />
            <strong style={{ color: "var(--text-0)" }}>Fleet run in progress</strong>
            <span className="dim" style={{ fontSize: 12 }}>
              job {job.job_id} · {rows.length} iteration{rows.length === 1 ? "" : "s"} so far
              {streaming ? " · live" : " · polling"}
              {job.mode ? ` · ${job.mode}` : ""}
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
          <div className="error">Fleet run failed: {job.error || "unknown error"}</div>
          <button className="btn-small" style={{ marginTop: 10 }} onClick={clearJob}>Dismiss</button>
        </div>
      )}

      {/* Iteration trace — live while running, authoritative summary when done */}
      {(rows.length > 0 || result) && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <h3 style={{ color: "var(--text-0)", margin: 0 }}>
              {result ? (
                <>Run summary: <span style={{ color: "var(--cyan)" }}>{result.stop_reason}</span></>
              ) : "Live progress"}
            </h3>
            {!isRunning && <button className="btn-small" onClick={clearJob}>Clear</button>}
          </div>
          {result && (
            <div className="dim" style={{ fontSize: 12, marginTop: 6 }}>
              Iterations: {result.iterations_run} · Duration: {result.duration_s?.toFixed(0)}s ·
              Hosts engaged: {result.hosts_engaged?.length ?? 0} ·
              Findings: {result.total_findings}
              {result.coverage?.modes_count ? ` · Modes exercised: ${result.coverage.modes_count}` : ""}
            </div>
          )}
          {result?.objective_met && (
            <div style={{ color: "var(--brand)", marginTop: 8 }}>
              ✓ Objective met: {result.objective}
            </div>
          )}

          {/* Severity breakdown chips */}
          {result?.severity_breakdown && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
              {["critical", "high", "medium", "low", "info"].map((sev) => (
                <span key={sev} className={`sev-chip sev-${sev}`}
                      style={{ fontSize: 12, padding: "3px 10px", borderRadius: 12 }}>
                  {sev}: <strong>{result.severity_breakdown[sev] ?? 0}</strong>
                </span>
              ))}
            </div>
          )}

          {/* Combined risk headline */}
          {result?.combined_risk?.total_combinations > 0 && (
            <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-1)" }}>
              <strong>Combined risk:</strong> {result.combined_risk.total_combinations} correlated
              issue(s) · {result.combined_risk.critical_combinations || 0} critical ·{" "}
              {result.combined_risk.total_attack_paths || 0} attack path(s)
            </div>
          )}

          {/* Top findings */}
          {result?.top_findings?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div className="form-label" style={{ marginBottom: 6 }}>Top findings</div>
              <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
                {result.top_findings.map((f, i) => (
                  <li key={i}>
                    <span className={`sev-dot sev-${f.severity}`} style={{ marginRight: 6 }} />
                    <span style={{ color: "var(--text-0)" }}>{f.title}</span>
                    {f.cve_id && (
                      <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank"
                         rel="noreferrer" style={{ marginLeft: 6, fontSize: 12 }}>{f.cve_id}</a>
                    )}
                    {f.target && <code className="dim" style={{ marginLeft: 6, fontSize: 11 }}>{String(f.target).slice(0, 40)}</code>}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Per-iteration trace: what each planning cycle proposed and verified */}
          <table className="data-table" style={{ marginTop: 14 }}>
            <thead><tr>
              <th className="num">Iter</th><th className="num">Proposed</th>
              <th className="num">Ran</th><th className="num">Skipped</th>
              <th className="num">+Findings</th><th>Roles</th>
            </tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.n}>
                  <td className="num">{r.n}</td>
                  <td className="num">{r.proposed}</td>
                  <td className="num">{r.ran}</td>
                  <td className="num">{r.skipped}</td>
                  <td className="num">{r.new_findings}</td>
                  <td className="dim" style={{ fontSize: 11 }}>
                    {r.by_role ? Object.entries(r.by_role).map(([k, v]) => `${k}×${v}`).join(", ") : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {result && (result.total_findings ?? 0) > 0 && (
            <Link to="/findings" className="btn-small" style={{ marginTop: 12 }}>
              View {result.total_findings} finding{result.total_findings === 1 ? "" : "s"} →
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
