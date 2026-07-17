// HEAVEN — reusable scan-activity list
//
// The expandable list of scans (status, mode, targets, duration, findings,
// replay/remove, and an inline findings panel) used by the Scans page and, with
// a `kind` filter, by the SAST and SCA sections — so each analysis type shows
// its own runs in one consistent, well-managed place instead of everything
// piling into a single merged list.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Scans as ScansApi, Replay } from "../api";
import { useToast } from "./Toast.jsx";
import { sevColor } from "../theme";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const isRunning = (s) => s.status === "running" || s.status === "pending";

// Smoothly eases the fill toward the real server percentage each time it
// changes, so a jump like 12% → 35% animates over ~1s instead of teleporting.
// It only ever moves toward the true value the backend reports — no fabricated
// progress — turning the coarse steps into continuous motion.
function ProgressFill({ target }) {
  const tgt = Math.max(0, Math.min(100, Number(target) || 0));
  const [w, setW] = useState(tgt);
  const wRef = useRef(tgt);
  useEffect(() => {
    let raf;
    const step = () => {
      const cur = wRef.current;
      const diff = tgt - cur;
      if (Math.abs(diff) < 0.25) { wRef.current = tgt; setW(tgt); return; }
      const next = cur + diff * 0.08;   // ease ~8% of the gap per frame
      wRef.current = next; setW(next);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [tgt]);
  return <div className="progress-fill" style={{ width: `${w}%`, transition: "none" }} />;
}

function fmtStarted(s) {
  const raw = s.created || s.started_at || "";
  return raw ? raw.slice(0, 16).replace("T", " ") : "—";
}

// Human duration: elapsed for a live scan (ticks with `now`), total for a finished one.
function fmtDuration(s, now) {
  const start = Date.parse(s.created || s.started_at || "");
  if (!start) return null;
  const end = isRunning(s) ? now : (Date.parse(s.completed_at || "") || null);
  if (!end) return null;
  const sec = Math.max(0, Math.floor((end - start) / 1000));
  const m = Math.floor(sec / 60), h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${sec % 60}s`;
  return `${sec}s`;
}

// Targets a scan ran against (only present for in-session scans via their config).
function scanTargets(s) {
  const c = s.config || {};
  return [...(c.targets || []), ...(c.urls || [])];
}

function statusClass(s) {
  if (s === "running")   return "running";
  if (s === "completed") return "completed";
  if (s === "failed")    return "failed";
  if (s === "paused")    return "paused";
  return "";
}

/**
 * @param {string}  kind        "pentest" | "sast" | "sca" | "all" — which section to list.
 * @param {string}  title       Heading for the card.
 * @param {boolean} showReplay  Show the Replay action (pentest scans only — replaying
 *                              a code-analysis run through the pentest pipeline is wrong).
 * @param {object}  emptyState  { icon, title, hint } shown when there are no scans.
 * @param {number}  refreshKey  Bump to force an immediate reload (e.g. after a new run).
 */
export default function ScanList({
  kind = "pentest",
  title = "Scan Activity",
  showReplay = true,
  emptyState = {},
  refreshKey = 0,
}) {
  const [scans, setScans]       = useState(null);
  const [error, setError]       = useState(null);
  const [selected, setSelected] = useState(null);
  const [details, setDetails]   = useState({});   // scanId -> {loading, findings, error}
  const [deleting, setDeleting] = useState({});    // scanId -> bool
  const [refreshing, setRefreshing] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  // True while any scan is running — drives a faster poll so the progress bar
  // reflects real work closely instead of teleporting between sparse samples.
  const runningRef = useRef(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const d = await ScansApi.list(50, kind);
      const list = d.scans || [];
      setScans(list);
      runningRef.current = list.some(isRunning);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  }, [kind]);

  // Adaptive polling: every 2s while a scan is live (so progress updates feel
  // continuous), backing off to 8s when everything is idle.
  useEffect(() => {
    let timer;
    let cancelled = false;
    const tick = async () => {
      await load();
      if (cancelled) return;
      timer = setTimeout(tick, runningRef.current ? 2000 : 8000);
    };
    tick();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [load, refreshKey]);

  // 1-second tick so a running scan's elapsed time updates live.
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // Expand a scan row to show the findings it produced (fetched on demand).
  function toggleScan(id) {
    const opening = selected !== id;
    setSelected(opening ? id : null);
    if (opening && !details[id]) {
      setDetails((d) => ({ ...d, [id]: { loading: true } }));
      ScansApi.findings(id)
        .then((r) => setDetails((d) => ({ ...d, [id]: { loading: false, findings: r.findings || [] } })))
        .catch((e) => setDetails((d) => ({ ...d, [id]: { loading: false, error: e.message } })));
    }
  }

  // Cancel a running scan, or permanently remove a finished one.
  async function removeScan(id, status) {
    const running = status === "running" || status === "pending";
    const msg = running
      ? "Cancel this running scan?"
      : "Remove this scan and its findings permanently? This cannot be undone.";
    if (!window.confirm(msg)) return;
    setDeleting((d) => ({ ...d, [id]: true }));
    try {
      const r = await ScansApi.remove(id);
      toast.success(r.status === "cancelled" ? "Scan cancelled" : "Scan removed");
      if (selected === id) setSelected(null);
      setDetails((d) => { const n = { ...d }; delete n[id]; return n; });
      load();
    } catch (e) {
      toast.error("Could not remove scan", e.message);
    } finally {
      setDeleting((d) => { const n = { ...d }; delete n[id]; return n; });
    }
  }

  // At-a-glance counts for the activity header.
  const runningCount   = (scans || []).filter(isRunning).length;
  const completedCount = (scans || []).filter((s) => s.status === "completed").length;
  const failedCount    = (scans || []).filter((s) => s.status === "failed").length;

  const empty = {
    icon: emptyState.icon || "🛰",
    title: emptyState.title || "No scans yet",
    hint: emptyState.hint || "Launch a scan above, run the demo, or start one from the CLI.",
  };

  if (error) return <div className="card error">{error}</div>;
  if (scans === null) return null;

  return (
    <div className="card">
      <div className="scan-list-head">
        <div className="card-title" style={{ marginBottom: 0 }}>{title}</div>
        <div className="scan-list-head-right">
          {scans.length > 0 && (
            <div className="scan-summary">
              <span>{scans.length} total</span>
              {runningCount > 0 && <span className="scan-summary-run">● {runningCount} running</span>}
              {completedCount > 0 && <span className="dim">{completedCount} completed</span>}
              {failedCount > 0 && <span className="scan-summary-fail">{failedCount} failed</span>}
            </div>
          )}
          <button className="btn-small" onClick={load} disabled={refreshing}>
            {refreshing ? "⏳ Refreshing…" : "↻ Refresh"}
          </button>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="info-state">
          <div style={{ fontSize: 30, marginBottom: 8 }}>{empty.icon}</div>
          <h3>{empty.title}</h3>
          <div className="dim">{empty.hint}</div>
        </div>
      ) : (
        <div className="scan-list">
          {scans.map((s, i) => {
            const id = s.scan_id || s.id || `scan-${i}`;
            const progress = s.progress_pct ?? null;
            const isActive = selected === id;
            const det = details[id];
            const running = isRunning(s);
            const mode = (s.mode || s.config?.scan_type || "full");
            const dur = fmtDuration(s, now);
            const tgts = scanTargets(s);
            const label = s.name && s.name !== "HEAVEN Scan" ? s.name : (tgts[0] || null);
            const fc = s.findings_count;
            const st = statusClass(s.status) || "unknown";
            return (
              <div key={id} className={"scan-row" + (isActive ? " is-open" : "") + (running ? " is-running" : "")}>
                <div
                  className="scan-row-head"
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleScan(id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleScan(id); }
                  }}
                >
                  <span className="scan-chevron">{isActive ? "▾" : "▸"}</span>

                  <span className={`scan-badge scan-badge-${st}`}>
                    <span className="scan-badge-dot" />
                    {s.status || "unknown"}
                  </span>

                  <span className="scan-mode-tag">{String(mode).toUpperCase()}</span>

                  <div className="scan-row-main">
                    <div className="scan-row-title">
                      {label
                        ? <span className="scan-name" title={label}>{label}</span>
                        : <code className="scan-id-chip">{id.slice(0, 12)}</code>}
                    </div>
                    <div className="scan-row-sub">
                      <code className="scan-id-mini">{id.slice(0, 8)}</code>
                      <span className="dim">· {fmtStarted(s)}</span>
                      {dur && <span className="dim">· {running ? "elapsed" : "took"} {dur}</span>}
                      {label && tgts.length > 1 && <span className="dim">· {tgts.length} targets</span>}
                    </div>
                  </div>

                  {running ? (
                    <div className="scan-progress-wrap">
                      <div className={`progress-bar ${progress === null ? "progress-indeterminate" : ""}`}>
                        {progress === null
                          ? <div className="progress-fill" style={{ width: "40%" }} />
                          : <ProgressFill target={progress} />}
                      </div>
                      {progress !== null && <span className="scan-progress-pct">{Math.round(progress)}%</span>}
                    </div>
                  ) : (
                    <span className={"scan-findings-chip" + (fc > 0 ? " has-findings" : "")}>
                      <span className="scan-findings-num">{fc != null ? fc : "—"}</span>
                      <span className="scan-findings-lbl">finding{fc === 1 ? "" : "s"}</span>
                    </span>
                  )}

                  <div className="scan-actions" onClick={(e) => e.stopPropagation()}>
                    {showReplay && (s.status === "completed" || s.status === "failed") && (
                      <button
                        className="btn-small"
                        title="Re-execute this scan with the stored seed (reproducible)"
                        onClick={async () => {
                          try {
                            const r = await Replay.scan(id, {});
                            toast.success(
                              "Replay started",
                              `New scan ${String(r.new_scan_id || "").slice(0, 8)}` +
                              (r.seed != null
                                ? ` · seed ${r.seed} (deterministic)`
                                : " · no seed stored (non-deterministic)")
                            );
                            load();
                          } catch (err) {
                            toast.error("Replay failed", err.message);
                          }
                        }}
                      >
                        ↻ Replay
                      </button>
                    )}
                    <button
                      className="btn-small scan-remove"
                      disabled={!!deleting[id]}
                      title={running ? "Cancel this running scan" : "Remove this scan and its findings"}
                      onClick={() => removeScan(id, s.status)}
                    >
                      {deleting[id] ? "…" : (running ? "✕ Cancel" : "🗑 Remove")}
                    </button>
                  </div>
                </div>

                {isActive && (
                  <div className="scan-body">
                    <ScanDetail det={det} status={s.status} navigate={navigate} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Inline result panel shown when a scan row is expanded. Lists the findings that
// scan produced (fetched on demand); each is clickable through to its detail.
function ScanDetail({ det, status, navigate }) {
  if (!det || det.loading) {
    return <div className="scan-detail-msg">Loading findings…</div>;
  }
  if (det.error) {
    return <div className="scan-detail-msg scan-detail-err">Could not load findings: {det.error}</div>;
  }
  const findings = det.findings || [];
  if (findings.length === 0) {
    const running = status === "running" || status === "pending";
    return (
      <div className="scan-detail-msg">
        {running
          ? "Scan in progress — findings will appear here as they're confirmed."
          : "No findings recorded for this scan."}
      </div>
    );
  }
  // Severity breakdown for the summary strip.
  const counts = {};
  for (const f of findings) {
    const k = String(f.severity || "info").toLowerCase();
    counts[k] = (counts[k] || 0) + 1;
  }
  const bySev = SEV_ORDER.filter((k) => counts[k]);
  // Highest-risk findings first so the most important row is at the top.
  const sorted = [...findings].sort(
    (a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0),
  );
  return (
    <div className="scan-detail">
      <div className="scan-detail-top">
        <span className="dim" style={{ fontSize: 11.5 }}>
          {findings.length} finding{findings.length !== 1 ? "s" : ""} — click any row to open it
        </span>
        <div className="scan-sev-strip">
          {bySev.map((k) => (
            <span key={k} className="scan-sev-pill" style={{ color: sevColor(k), borderColor: sevColor(k) }}>
              <span className="scan-sev-dot" style={{ background: sevColor(k) }} />
              {counts[k]} {k}
            </span>
          ))}
        </div>
      </div>
      <div className="scan-finding-rows">
        {sorted.map((f) => (
          <button key={f.id} className="scan-finding-row" onClick={() => navigate(`/findings/${f.id}`)}>
            <span className="scan-finding-dot" style={{ background: sevColor(f.severity) }} />
            <span className="scan-finding-title">{f.title || f.vuln_type || "Finding"}</span>
            <span className="dim scan-finding-target">{f.target}</span>
            <span className="scan-finding-score mono">{Number(f.risk_score || 0).toFixed(1)}</span>
            <span className="scan-finding-arrow">→</span>
          </button>
        ))}
      </div>
    </div>
  );
}
