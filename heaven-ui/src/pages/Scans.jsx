import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Scans as ScansApi, Replay, Demo, Engagement } from "../api";
import { useToast } from "../components/Toast.jsx";
import HelpTip from "../components/HelpTip.jsx";
import TargetsInput, { classifyTarget } from "../components/TargetsInput.jsx";
import { sevColor } from "../theme";

const MODES = ["web", "network", "full", "ad", "cloud"];
const STEALTH = [
  { value: "1", label: "1 — Paranoid (very slow, evasive)" },
  { value: "2", label: "2 — Stealth (slow, low noise)" },
  { value: "3", label: "3 — Normal (balanced)" },
  { value: "4", label: "4 — Aggressive (fast, loud)" },
];

// Severity display order for the expanded-scan breakdown strip.
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// ── Small formatting helpers for the scan-activity list ──
const isRunning = (s) => s.status === "running" || s.status === "pending";

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

export default function Scans() {
  const [scans, setScans]   = useState(null);
  const [error, setError]   = useState(null);
  const [selected, setSelected] = useState(null);
  const [details, setDetails]   = useState({});   // scanId -> {loading, findings, error}
  const [deleting, setDeleting] = useState({});    // scanId -> bool
  const [refreshing, setRefreshing] = useState(false);
  const navigate = useNavigate();

  // Launcher form
  const [targets, setTargets]   = useState("");
  const [mode, setMode]         = useState("web");
  const [stealth, setStealth]   = useState("3");
  const [engagement, setEngagement] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [launching, setLaunching]   = useState(false);
  const [launchError, setLaunchError] = useState(null);
  const [launchSuccess, setLaunchSuccess] = useState(null);
  const toast = useToast();

  async function load() {
    setRefreshing(true);
    try {
      const d = await ScansApi.list(50);
      setScans(d.scans || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
    const i = setInterval(load, 8000);
    return () => clearInterval(i);
  }, []);

  // 1-second tick so a running scan's elapsed time updates live.
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // Engagement summary → scope context in the launcher.
  const [engSummary, setEngSummary] = useState(null);
  useEffect(() => { Engagement.summary().then(setEngSummary).catch(() => {}); }, []);
  const scopeCount = engSummary?.stats?.scope_targets ?? 0;
  const engName = engSummary?.engagement?.name;

  // Parse + classify targets live for inline validation feedback.
  const parsed = useMemo(() => {
    const raw = targets.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    const valid = [], invalid = [];
    for (const t of raw) (classifyTarget(t) ? valid : invalid).push(t);
    return { valid, invalid };
  }, [targets]);

  const [demoRunning, setDemoRunning] = useState(false);
  async function runDemoScan() {
    setDemoRunning(true);
    try {
      await Demo.scan();
      toast.success("Demo scan started — watch it run in the list below");
      // Re-poll a few times so the running → completed loop is visible quickly
      // (the demo scan runs ~10s; the default poll is every 8s).
      [500, 2500, 5000, 8000, 11000, 14000].forEach((ms) => setTimeout(load, ms));
    } catch (e) {
      toast.error(e.message || "Could not start demo scan");
    } finally {
      setDemoRunning(false);
    }
  }

  async function launchScan(e) {
    e.preventDefault();
    if (!authorized) { setLaunchError("You must confirm written authorization before scanning."); return; }
    const rawTargets = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (rawTargets.length === 0) { setLaunchError("Enter at least one target URL or IP."); return; }

    setLaunching(true);
    setLaunchError(null);
    setLaunchSuccess(null);
    try {
      const payload = {
        targets: rawTargets,
        mode,
        stealth_level: parseInt(stealth, 10),
        engagement: engagement.trim() || undefined,
        i_have_authorization: true,
      };
      const result = await ScansApi.create(payload);
      setLaunchSuccess(`Scan launched · ID: ${result.scan_id || result.id || "—"}`);
      setTargets("");
      setAuthorized(false);
      setTimeout(load, 1500);
    } catch (err) {
      setLaunchError(err.message || "Launch failed");
    } finally {
      setLaunching(false);
    }
  }

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

  function statusClass(s) {
    if (s === "running")   return "running";
    if (s === "completed") return "completed";
    if (s === "failed")    return "failed";
    if (s === "paused")    return "paused";
    return "";
  }

  // At-a-glance counts for the activity header.
  const runningCount   = (scans || []).filter(isRunning).length;
  const completedCount = (scans || []).filter((s) => s.status === "completed").length;
  const failedCount    = (scans || []).filter((s) => s.status === "failed").length;

  return (
    <div className="page">
      {/* Scan launcher */}
      <div className="card">
        <div className="card-title">Launch Scan</div>
        <form onSubmit={launchScan} className="scan-form">
          <div className="form-group form-full">
            <label className="form-label" htmlFor="scan-targets">
              Targets <span className="dim">— type a URL, IP or CIDR and press Enter · or paste a list</span>
            </label>
            <TargetsInput
              id="scan-targets"
              value={targets}
              onChange={setTargets}
              placeholder="e.g. https://app.example.com  ·  10.0.0.1  ·  192.168.1.0/24"
            />
            {targets.trim() && (
              <div className="field-hints">
                {parsed.valid.length > 0 && (
                  <span className="field-hint-ok">
                    ✓ {parsed.valid.length} valid target{parsed.valid.length !== 1 ? "s" : ""}
                  </span>
                )}
                {parsed.invalid.length > 0 && (
                  <span className="field-hint-warn">
                    ⚠ {parsed.invalid.length} unrecognized: {parsed.invalid.slice(0, 3).join(", ")}
                    {parsed.invalid.length > 3 ? "…" : ""}
                  </span>
                )}
                {parsed.valid.length > 0 && (
                  <span className="dim">
                    → added to scope{engName ? ` in “${engName}”` : ""} on launch
                  </span>
                )}
              </div>
            )}
            <span className="dim" style={{ fontSize: 11, marginTop: 4 }}>
              Scope: {scopeCount} target{scopeCount !== 1 ? "s" : ""} currently in
              {engName ? ` “${engName}”` : " this engagement"}.
            </span>
          </div>

          <label className="form-group">
            <span className="form-label">Scan Mode</span>
            <select className="form-select" value={mode} onChange={e => setMode(e.target.value)}>
              {MODES.map(m => <option key={m} value={m}>{m.toUpperCase()}</option>)}
            </select>
          </label>

          <label className="form-group">
            <span className="form-label">
              Stealth Level
              <HelpTip text="How aggressive/evasive the scan is. 1 = paranoid (slow, low noise, honeypot-aware) → 4 = aggressive (fast, loud). Lower is stealthier but slower." />
            </span>
            <select className="form-select" value={stealth} onChange={e => setStealth(e.target.value)}>
              {STEALTH.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </label>

          <label className="form-group form-full">
            <span className="form-label">Engagement name <span className="dim">(optional)</span></span>
            <input
              className="form-input"
              type="text"
              value={engagement}
              onChange={e => setEngagement(e.target.value)}
              placeholder="e.g. acme-webapp-pentest"
            />
          </label>

          <label className={"consent-row form-full" + (authorized ? " is-ack" : "")}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
            />
            <span>
              I confirm I have <strong>written authorization</strong> from the target system owner.
              Unauthorized scanning is illegal. HEAVEN logs all scan activity.
              <HelpTip text="Active scanning sends real traffic to the target. HEAVEN refuses to launch without this confirmation, and every action is written to an HMAC-signed audit log." />
            </span>
          </label>

          {launchError && (
            <div className="form-full form-banner form-banner-error">✗ {launchError}</div>
          )}
          {launchSuccess && (
            <div className="form-full form-banner form-banner-ok">✓ {launchSuccess}</div>
          )}

          <div className="form-full" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button
              type="submit"
              disabled={launching || !authorized || parsed.valid.length === 0}
              className="btn btn-primary"
            >
              {launching ? "⏳ Launching…" : "⚡ Launch Scan"}
            </button>
            <button type="button" onClick={runDemoScan} disabled={demoRunning} className="btn">
              {demoRunning ? "Starting…" : "▶ Run demo scan"}
            </button>
            <span className="dim" style={{ fontSize: 11 }}>
              New here? <b>Run demo scan</b> simulates the full loop against sample
              data — no target, no authorization needed.
            </span>
          </div>
        </form>
      </div>

      {/* CLI reference */}
      <div className="card">
        <div className="card-title">CLI Reference</div>
        <p className="dim" style={{ fontSize: 11, lineHeight: 1.7, marginBottom: 10 }}>
          Scans can also be launched from the terminal (authorization gate is enforced in both places).
        </p>
        <pre className="code" style={{ fontSize: 11 }}>{`# Web scan
heaven scan -u https://app.example.com -m web \\
    --engagement my-eng --i-have-authorization

# Network scan
heaven scan -t 10.0.0.0/24 -m network \\
    --engagement my-eng --i-have-authorization

# Resume interrupted scan
heaven resume --engagement my-eng --i-have-authorization`}</pre>
      </div>

      {error && <div className="card error">{error}</div>}

      {scans !== null && (
        <div className="card">
          <div className="scan-list-head">
            <div className="card-title" style={{ marginBottom: 0 }}>Scan Activity</div>
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
              <div style={{ fontSize: 30, marginBottom: 8 }}>🛰</div>
              <h3>No scans yet</h3>
              <div className="dim">Launch a scan above, run the demo, or start one from the CLI.</div>
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
                            <div className="progress-fill" style={{ width: `${progress ?? 40}%` }} />
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
                        {(s.status === "completed" || s.status === "failed") && (
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
