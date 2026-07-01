import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Scans as ScansApi, Replay, Demo, Engagement } from "../api";
import { useToast } from "../components/Toast.jsx";
import HelpTip from "../components/HelpTip.jsx";

const SEV_COLOR = {
  critical: "var(--crit)", high: "#ff8a3d", medium: "#ffd24d",
  low: "var(--cyan)", info: "var(--text-2)",
};

// Live target validation — classify each entry so the operator gets instant
// feedback instead of a server-side rejection after clicking Launch.
const _IP = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const _URL = /^https?:\/\/[^\s/$.?#][^\s]*$/i;
const _HOST = /^([a-z0-9-]+\.)+[a-z]{2,}$/i;
function classifyTarget(t) {
  if (_URL.test(t)) return "url";
  if (_IP.test(t)) return "ip/cidr";
  if (_HOST.test(t)) return "host";
  return null;
}

const MODES = ["web", "network", "full", "ad", "cloud"];
const STEALTH = [
  { value: "1", label: "1 — Paranoid (very slow, evasive)" },
  { value: "2", label: "2 — Stealth (slow, low noise)" },
  { value: "3", label: "3 — Normal (balanced)" },
  { value: "4", label: "4 — Aggressive (fast, loud)" },
];

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

  return (
    <div className="page">
      {/* Scan launcher */}
      <div className="card">
        <div className="card-title">Launch Scan</div>
        <form onSubmit={launchScan}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 14 }}>
            <div style={{ gridColumn: "1 / -1" }}>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
                Targets <span className="dim">(URLs or IPs, one per line or comma-separated)</span>
              </label>
              <textarea
                value={targets}
                onChange={e => setTargets(e.target.value)}
                placeholder={"https://app.example.com\n10.0.0.1\n192.168.1.0/24"}
                rows={4}
                style={{
                  width: "100%", background: "var(--border)",
                  border: "1px solid var(--border)", color: "var(--text-0)",
                  fontFamily: "monospace", fontSize: 12, padding: "8px 10px",
                  outline: "none", resize: "vertical", boxSizing: "border-box",
                }}
              />
              {targets.trim() && (
                <div style={{ fontSize: 11, marginTop: 5, display: "flex", gap: 12, flexWrap: "wrap" }}>
                  {parsed.valid.length > 0 && (
                    <span style={{ color: "var(--brand)" }}>
                      ✓ {parsed.valid.length} valid target{parsed.valid.length !== 1 ? "s" : ""}
                    </span>
                  )}
                  {parsed.invalid.length > 0 && (
                    <span style={{ color: "var(--med)" }}>
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
              <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
                Scope: {scopeCount} target{scopeCount !== 1 ? "s" : ""} currently in
                {engName ? ` “${engName}”` : " this engagement"}.
              </div>
            </div>

            <div>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>Scan Mode</label>
              <select
                value={mode}
                onChange={e => setMode(e.target.value)}
                style={{
                  width: "100%", background: "var(--bg-1)", color: "var(--text-0)",
                  border: "1px solid var(--border)", padding: "8px 10px",
                  fontFamily: "monospace", fontSize: 12, outline: "none",
                }}
              >
                {MODES.map(m => <option key={m} value={m}>{m.toUpperCase()}</option>)}
              </select>
            </div>

            <div>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
                Stealth Level
                <HelpTip text="How aggressive/evasive the scan is. 1 = paranoid (slow, low noise, honeypot-aware) → 4 = aggressive (fast, loud). Lower is stealthier but slower." />
              </label>
              <select
                value={stealth}
                onChange={e => setStealth(e.target.value)}
                style={{
                  width: "100%", background: "var(--bg-1)", color: "var(--text-0)",
                  border: "1px solid var(--border)", padding: "8px 10px",
                  fontFamily: "monospace", fontSize: 12, outline: "none",
                }}
              >
                {STEALTH.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>

            <div style={{ gridColumn: "1 / -1" }}>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
                Engagement name <span className="dim">(optional)</span>
              </label>
              <input
                type="text"
                value={engagement}
                onChange={e => setEngagement(e.target.value)}
                placeholder="e.g. acme-webapp-pentest"
                style={{
                  width: "100%", background: "var(--border)",
                  border: "1px solid var(--border)", color: "var(--text-0)",
                  fontFamily: "monospace", fontSize: 12, padding: "8px 10px",
                  outline: "none", boxSizing: "border-box",
                }}
              />
            </div>
          </div>

          <label style={{
            display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer",
            marginBottom: 16, fontSize: 12, color: authorized ? "var(--text-0)" : "var(--med)",
          }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
              style={{ marginTop: 2, accentColor: "var(--text-0)" }}
            />
            <span>
              I confirm I have <strong>written authorization</strong> from the target system owner.
              Unauthorized scanning is illegal. HEAVEN logs all scan activity.
              <HelpTip text="Active scanning sends real traffic to the target. HEAVEN refuses to launch without this confirmation, and every action is written to an HMAC-signed audit log." />
            </span>
          </label>

          {launchError && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "var(--border)", border: "1px solid var(--crit)",
              color: "var(--crit)", fontSize: 11, fontFamily: "monospace",
            }}>✗ {launchError}</div>
          )}
          {launchSuccess && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "var(--border)", border: "1px solid var(--text-2)",
              color: "var(--text-0)", fontSize: 11, fontFamily: "monospace",
            }}>✓ {launchSuccess}</div>
          )}

          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <button
              type="submit"
              disabled={launching || !authorized || parsed.valid.length === 0}
              className="btn"
              style={{
                opacity: (!authorized || launching || parsed.valid.length === 0) ? 0.5 : 1,
                borderColor: "var(--text-0)", color: "var(--text-0)",
              }}
            >
              {launching ? "⏳ Launching..." : "⚡ Launch Scan"}
            </button>
            <button type="button" onClick={runDemoScan} disabled={demoRunning} className="btn">
              {demoRunning ? "Starting…" : "▶ Run demo scan"}
            </button>
          </div>
          <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>
            New here? <b>Run demo scan</b> simulates the full loop (recon →
            findings → report) against sample data — no target, no authorization
            needed.
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
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {scans.length === 0 ? "No scans yet" : `${scans.length} scan${scans.length !== 1 ? "s" : ""}`}
            </div>
            <button className="btn-small" onClick={load} disabled={refreshing}>
              {refreshing ? "⏳ Refreshing…" : "↻ Refresh"}
            </button>
          </div>

          {scans.length === 0 ? (
            <div className="info-state">
              <h3>No scans recorded</h3>
              <div className="dim">Launch a scan above or run one from the CLI</div>
            </div>
          ) : (
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Started</th>
                  <th>Findings</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s, i) => {
                  const id = s.scan_id || s.id || `scan-${i}`;
                  const progress = s.progress_pct ?? null;
                  const isActive = selected === id;
                  const det = details[id];
                  return (
                    <React.Fragment key={id}>
                    <tr onClick={() => toggleScan(id)}
                        style={{ cursor: "pointer", background: isActive ? "var(--border)" : "" }}>
                      <td>
                        <span style={{ color: "var(--text-2)", marginRight: 4 }}>
                          {isActive ? "▾" : "▸"}
                        </span>
                        <code style={{ fontSize: 11 }}>{id.slice(0, 8)}</code>
                      </td>
                      <td>{s.mode || s.config?.scan_type || "full"}</td>
                      <td>
                        <span className={`scan-status ${statusClass(s.status)}`}>
                          {s.status || "unknown"}
                        </span>
                        {s.status === "running" && (() => {
                          const start = Date.parse(s.created || s.started_at || "");
                          if (!start) return null;
                          const sec = Math.max(0, Math.floor((now - start) / 1000));
                          const mm = Math.floor(sec / 60);
                          return (
                            <div className="dim" style={{ fontSize: 10, marginTop: 2 }}>
                              ⏱ {mm}m {sec % 60}s
                            </div>
                          );
                        })()}
                      </td>
                      <td style={{ width: 100 }}>
                        {progress !== null ? (
                          <div className={`progress-bar ${s.status === "running" ? "progress-indeterminate" : ""}`}>
                            <div className="progress-fill" style={{ width: `${progress}%` }} />
                          </div>
                        ) : (
                          s.status === "running" ? (
                            <div className="progress-bar progress-indeterminate">
                              <div className="progress-fill" style={{ width: "40%" }} />
                            </div>
                          ) : "—"
                        )}
                      </td>
                      <td className="dim" style={{ fontSize: 11 }}>
                        {(s.created || s.started_at || "").slice(0, 16).replace("T", " ")}
                      </td>
                      <td>
                        {s.findings_count != null
                          ? <span style={{ color: s.findings_count > 0 ? "var(--med)" : "var(--text-1)" }}>
                              {s.findings_count}
                            </span>
                          : "—"
                        }
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {(s.status === "completed" || s.status === "failed") && (
                            <button
                              className="btn-small"
                              title="Re-execute this scan with the stored seed (Gap 8: reproducibility)"
                              onClick={async (e) => {
                                e.stopPropagation();
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
                            className="btn-small"
                            disabled={!!deleting[id]}
                            title={s.status === "running" || s.status === "pending"
                              ? "Cancel this running scan"
                              : "Remove this scan and its findings"}
                            style={{ borderColor: "var(--crit)", color: "var(--crit)" }}
                            onClick={(e) => { e.stopPropagation(); removeScan(id, s.status); }}
                          >
                            {deleting[id]
                              ? "…"
                              : (s.status === "running" || s.status === "pending" ? "✕ Cancel" : "🗑 Remove")}
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isActive && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-1)", padding: 0 }}>
                          <ScanDetail det={det} status={s.status} navigate={navigate} />
                        </td>
                      </tr>
                    )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
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
    return <div className="dim" style={{ padding: "12px 16px", fontSize: 12 }}>Loading findings…</div>;
  }
  if (det.error) {
    return (
      <div style={{ padding: "12px 16px", fontSize: 12, color: "var(--crit)" }}>
        Could not load findings: {det.error}
      </div>
    );
  }
  const findings = det.findings || [];
  if (findings.length === 0) {
    const running = status === "running" || status === "pending";
    return (
      <div className="dim" style={{ padding: "12px 16px", fontSize: 12 }}>
        {running
          ? "Scan in progress — findings will appear here as they're confirmed."
          : "No findings recorded for this scan."}
      </div>
    );
  }
  return (
    <div style={{ padding: "10px 14px", display: "grid", gap: 6 }}>
      <div className="dim" style={{ fontSize: 11, marginBottom: 2 }}>
        {findings.length} finding{findings.length !== 1 ? "s" : ""} — click any row to open it
      </div>
      {findings.map((f) => (
        <button
          key={f.id}
          onClick={() => navigate(`/findings/${f.id}`)}
          style={{
            display: "flex", alignItems: "center", gap: 10, textAlign: "left",
            background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)",
            borderRadius: "var(--radius-md)", padding: "8px 11px", cursor: "pointer",
            color: "var(--text-0)", fontFamily: "var(--font-ui)", width: "100%",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--brand)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        >
          <span style={{
            width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
            background: SEV_COLOR[(f.severity || "info").toLowerCase()] || "var(--text-2)",
          }} />
          <span style={{ flex: 1, fontSize: 12.5, fontWeight: 600, overflow: "hidden",
                         textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {f.title || f.vuln_type || "Finding"}
          </span>
          <span className="dim" style={{ fontSize: 11, overflow: "hidden",
                         textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 220 }}>
            {f.target}
          </span>
          <span className="mono" style={{ fontSize: 11, color: "var(--text-2)", flexShrink: 0 }}>
            {Number(f.risk_score || 0).toFixed(1)}
          </span>
        </button>
      ))}
    </div>
  );
}
