// HEAVEN — Watch Mode (continuous monitoring) launcher + live viewer
//
// Runs a bounded watch loop as a BACKGROUND job on the server (POST
// /api/watch/start returns a job_id immediately). The loop scans on an
// interval, diffs each run against the previous, and alerts ONLY when a NEW or
// REGRESSED finding appears (or every run when heartbeat is on) — no Slack spam
// from unchanged re-scans. Progress is shown two ways, exactly like the
// Autonomous page:
//   1. A WebSocket (/api/watch/jobs/{id}/stream) pushes each iteration live.
//   2. Polling GET /api/watch/jobs/{id} is the fallback (dropped socket / WS-
//      blocking proxy / late page load).
// The active job_id is persisted to sessionStorage, so the run survives
// navigating away and back — and a full page refresh.

import React, { useState, useRef, useEffect, useCallback } from "react";
import { Link } from "react-router";
import { Watch, Engagement, openWatchStream } from "../api";
import { SkeletonCard, EmptyState } from "../components/Skeleton.jsx";
import TargetsInput from "../components/TargetsInput.jsx";
import EngagementPicker from "../components/EngagementPicker.jsx";

const JOB_KEY = "heaven.watch.job";
const POLL_MS = 5000;

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

export default function WatchPage() {
  // ── Launcher form ──
  const [engagement, setEngagement] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [intervalMin, setIntervalMin] = useState(30);
  const [maxIter, setMaxIter] = useState(6);
  const [mode, setMode] = useState("web");
  const [heartbeat, setHeartbeat] = useState(false);
  const [autoTickets, setAutoTickets] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  // ── Live job state ──
  const [job, setJob] = useState(() => loadStoredJob());
  const [liveRows, setLiveRows] = useState(() => loadStoredJob()?.progress || []);
  const [streaming, setStreaming] = useState(false);
  const [channels, setChannels] = useState(null);
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
      const fresh = await Watch.job(jobId);
      setJob(fresh);
      storeJob(fresh);
      setLiveRows((prev) => mergeRows(prev, fresh.progress));
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
    const ws = openWatchStream(jobId, (msg) => {
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

  // Default engagement to the active one; load honest channel state.
  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
    Watch.channels().then(setChannels).catch(() => setChannels(null));
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
    if (!engagement) { setError("Pick an engagement — the watch loop persists every run into one."); return; }
    const body = {
      engagement,
      ips: targets.filter((t) => !/^https?:\/\//i.test(t)),
      urls: targets.filter((t) => /^https?:\/\//i.test(t)),
      interval_s: Math.max(1, parseInt(intervalMin, 10) || 1) * 60,
      max_iterations: parseInt(maxIter, 10),
      mode,
      heartbeat,
      auto_tickets: autoTickets,
    };
    setSubmitting(true);
    try {
      const { job_id } = await Watch.start(body);
      const initial = {
        job_id, status: "running", engagement,
        targets: { ips: body.ips, urls: body.urls }, mode,
        interval_s: body.interval_s, max_iterations: body.max_iterations,
        heartbeat, auto_tickets: autoTickets,
        started_at: Date.now() / 1000, ended_at: null,
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

  async function stop() {
    if (!job?.job_id) return;
    try {
      await Watch.stop(job.job_id);
      setJob((prev) => (prev ? { ...prev, status: "stopping" } : prev));
    } catch (e) {
      setError(e.message);
    }
  }

  function clearJob() {
    stopPolling();
    closeStream();
    setJob(null);
    setLiveRows([]);
    storeJob(null);
  }

  const isRunning = job?.status === "running" || job?.status === "stopping";
  const result = job?.result;
  const rows = result?.iterations?.length
    ? mergeRows(liveRows, result.iterations)
    : liveRows;
  const changeCount = rows.reduce((n, r) => n + (r.changed ? 1 : 0), 0);

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--cyan)", marginTop: 0 }}>🔁 Watch Mode</h2>
        <p className="page-lead">
          Continuous monitoring with auto-diff. Runs scans on an interval,
          diffs each against the previous, and alerts <strong>only</strong> when
          something changes (a new or regressed finding) — no Slack spam from
          unchanged re-scans. Runs in the background with <strong>live
          streaming</strong>: leave this page and come back, the loop keeps going.
        </p>

        <div className="scan-form" style={{ marginBottom: 4 }}>
          <div className="form-group form-full">
            <label className="form-label" htmlFor="watch-targets">
              Targets <span className="dim">— type a URL or IP and press Enter · or paste a list</span>
            </label>
            <TargetsInput
              id="watch-targets"
              value={targetsText}
              onChange={setTargetsText}
              placeholder="e.g. 10.0.0.5  ·  https://app.example.com"
            />
          </div>
          <EngagementPicker value={engagement} onChange={setEngagement}
                            id="watch-engagement"
                            label="Record runs into engagement" />
          <label className="form-group">
            <span className="form-label">Scan mode</span>
            <select className="form-input" value={mode}
                    onChange={(e) => setMode(e.target.value)}>
              <option value="web">Web application</option>
              <option value="network">Network</option>
              <option value="api">API</option>
              <option value="full">Full (all modules)</option>
            </select>
          </label>
          <label className="form-group">
            <span className="form-label">Interval (minutes)</span>
            <input className="form-input" type="number" min={1} max={1440} value={intervalMin}
                   onChange={(e) => setIntervalMin(e.target.value)} />
          </label>
          <label className="form-group">
            <span className="form-label">
              Iterations <span className="dim">— then it stops (1–500)</span>
            </span>
            <input className="form-input" type="number" min={1} max={500} value={maxIter}
                   onChange={(e) => setMaxIter(e.target.value)} />
          </label>
        </div>

        <label className="consent-row">
          <input type="checkbox" checked={heartbeat}
                 onChange={(e) => setHeartbeat(e.target.checked)} />
          <span>Heartbeat — alert every run (default: only on change)</span>
        </label>
        <label className="consent-row">
          <input type="checkbox" checked={autoTickets}
                 onChange={(e) => setAutoTickets(e.target.checked)} />
          <span>Auto-create tickets on new criticals + every regression (Jira / Linear)</span>
        </label>
        <label className={"consent-row" + (authorized ? " is-ack" : "")}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I confirm <strong>written authorization</strong> for every target listed.</span>
        </label>

        <button className="btn btn-primary"
                disabled={submitting || isRunning || !authorized}
                onClick={run}>
          {submitting ? "Starting…" : isRunning ? "Watch in progress…" : "Start watch loop"}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

        <p className="dim" style={{ fontSize: 12, marginTop: 12 }}>
          Want a truly endless monitor (no iteration cap)? Run it from the CLI:
        </p>
        <pre className="cli-block">{`heaven watch -u https://app.example.com \\
    --engagement prod-monitor \\
    --interval 30m \\
    --auto-tickets \\
    --i-have-authorization`}</pre>
      </div>

      {/* Live run banner */}
      {isRunning && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span className="scan-running-dot" />
            <strong style={{ color: "var(--text-0)" }}>
              {job.status === "stopping" ? "Watch stopping…" : "Watch loop in progress"}
            </strong>
            <span className="dim" style={{ fontSize: 12 }}>
              job {job.job_id} · {rows.length}/{job.max_iterations} iteration{rows.length === 1 ? "" : "s"}
              {streaming ? " · live" : " · polling"}
              {job.engagement ? ` · ${job.engagement}` : ""}
              {changeCount > 0 ? ` · ${changeCount} with changes` : " · no changes yet"}
            </span>
            <button className="btn-small" style={{ marginLeft: "auto" }}
                    disabled={job.status === "stopping"} onClick={stop}>
              {job.status === "stopping" ? "Stopping…" : "Stop"}
            </button>
          </div>
          {rows.length === 0 && (
            <div style={{ marginTop: 8 }}>
              <SkeletonCard lines={2} />
              <div className="dim" style={{ fontSize: 12, marginTop: 6 }}>
                First scan running — the baseline. Alerts start from the next run.
              </div>
            </div>
          )}
        </div>
      )}

      {job?.status === "error" && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="error">Watch loop failed: {job.error || "unknown error"}</div>
          <button className="btn-small" style={{ marginTop: 10 }} onClick={clearJob}>Dismiss</button>
        </div>
      )}

      {/* Iteration table — live while running, authoritative summary when done */}
      {(rows.length > 0 || result) && (
        <div className="card" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <h3 style={{ color: "var(--text-0)", margin: 0 }}>
              {result ? (
                <>Watch summary — <span style={{ color: "var(--cyan)" }}>{result.stop_reason || "finished"}</span></>
              ) : "Live iterations"}
            </h3>
            {!isRunning && <button className="btn-small" onClick={clearJob}>Clear</button>}
          </div>
          {result && (
            <div className="dim" style={{ fontSize: 12, marginTop: 6 }}>
              Iterations: {result.iterations} · Duration: {result.duration_s?.toFixed(0)}s ·
              Iterations with changes: {result.changes_detected ?? changeCount} ·
              Alerts sent: {result.alerts_dispatched ?? 0} ·
              Tickets: {result.tickets_created ?? 0}
            </div>
          )}

          <div style={{ overflowX: "auto" }}>
            <table className="data-table" style={{ marginTop: 12 }}>
              <thead><tr>
                <th className="num">#</th>
                <th>Scan</th>
                <th className="num">🆕 New</th>
                <th className="num">⚠ Regressed</th>
                <th className="num">✅ Resolved</th>
                <th>Alert</th>
                <th>What changed</th>
              </tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.n} style={r.changed ? { background: "var(--hover)" } : undefined}>
                    <td className="num">
                      {r.n}{r.baseline ? <span className="dim" title="baseline — nothing to diff against yet"> (base)</span> : ""}
                    </td>
                    <td><code>{(r.scan_id || "").slice(0, 8) || "—"}</code></td>
                    <td className="num" style={r.new ? { color: "var(--danger)", fontWeight: 600 } : undefined}>{r.new ?? 0}</td>
                    <td className="num" style={r.regressed ? { color: "var(--warn, var(--danger))", fontWeight: 600 } : undefined}>{r.regressed ?? 0}</td>
                    <td className="num">{r.resolved ?? 0}</td>
                    <td>{r.alert_dispatched ? "✓ sent" : (r.baseline ? "—" : "·")}</td>
                    <td className="dim" style={{ fontSize: 11 }}>
                      {r.error
                        ? <span className="error" style={{ fontSize: 11 }}>{r.error}</span>
                        : (r.changes && r.changes.length
                            ? r.changes.slice(0, 3).map((c, i) => (
                                <span key={i} style={{ marginRight: 6 }}>
                                  <span className={`sev-dot sev-${c.severity}`} style={{ marginRight: 3 }} />
                                  {c.kind === "regressed" ? "↩ " : "+ "}
                                  {(c.title || c.vuln_type).slice(0, 28)}
                                </span>
                              ))
                            : (r.baseline ? "baseline captured" : "no change"))}
                      {r.changes && r.changes.length > 3 ? ` +${r.changes.length - 3} more` : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {result && (
            <Link to="/findings" className="btn-small" style={{ marginTop: 12 }}>
              View findings →
            </Link>
          )}
        </div>
      )}

      {!isRunning && !job && rows.length === 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <EmptyState
            icon="🔁"
            headline="No watch loop running"
            body="Fill in the targets above and start a loop — its iterations, diffs, and alerts stream here live."
          />
        </div>
      )}

      {/* Outgoing alert channels — honest, driven by /api/watch/channels */}
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">Outgoing alert channels</div>
        <p className="dim" style={{ fontSize: 12, marginTop: 0 }}>
          Change alerts are pushed to whichever of these is configured. All are
          optional — with none set, the loop still runs and records its diff
          history here.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
          <Channel
            name="Webhook (Slack / Teams / Discord)"
            active={!!channels?.webhook_active}
            note={channels?.webhook_active ? "Active" : "Set the WEBHOOK_URL env var"}
          />
          <Channel
            name="SIEM (Splunk HEC / Elastic)"
            active={(channels?.siem_backends_active?.length || 0) > 0}
            note={channels?.siem_backends_active?.length
              ? `Active: ${channels.siem_backends_active.join(", ")}`
              : "Set HEAVEN_SPLUNK_HEC_* or HEAVEN_ELASTIC_* env vars"}
          />
          <Channel
            name="Ticketing (Jira / Linear)"
            active={(channels?.ticketing_backends?.length || 0) > 0}
            note={channels?.ticketing_backends?.length
              ? `Active: ${channels.ticketing_backends.join(", ")}`
              : "Set HEAVEN_JIRA_* or HEAVEN_LINEAR_* env vars"}
          />
        </div>
      </div>
    </div>
  );
}

function Channel({ name, active, note }) {
  return (
    <div className={"status-tile " + (active ? "is-active" : "is-inactive")}>
      <div className="status-tile-title">{name}</div>
      <div style={{ color: active ? "var(--brand)" : "var(--med)", fontSize: 12 }}>
        {active ? "✓ active" : "✗ not configured"}
      </div>
      <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>{note}</div>
    </div>
  );
}
