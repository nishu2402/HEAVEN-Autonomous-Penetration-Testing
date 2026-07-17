import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Engagement, SIEM, Scans, getUser, logout } from "../api";
import { useJobs } from "../context/Jobs.jsx";

export default function Header({ onMenu }) {
  const { jobs } = useJobs();
  // Long-running operations (post-ex, lateral, SAST, …) tracked globally so they
  // stay visible from any page — clicking returns you to where the job runs.
  const runningJobs = Object.values(jobs).filter((j) => j.status === "running");
  const [eng, setEng] = useState(null);
  const [siem, setSiem] = useState(null);
  const [running, setRunning] = useState(0);
  const [clock, setClock] = useState(new Date().toLocaleTimeString());
  const [light, setLight] = useState(
    () => document.documentElement.dataset.theme === "light"
  );
  const navigate = useNavigate();
  const location = useLocation();
  const user = getUser();

  function toggleTheme() {
    const next = !light;
    setLight(next);
    document.documentElement.dataset.theme = next ? "light" : "dark";
    try { localStorage.setItem("heaven.theme", next ? "light" : "dark"); } catch { /* ignore */ }
  }

  useEffect(() => {
    const loadEng = () => Engagement.summary().then(setEng).catch(() => {});
    loadEng();
    SIEM.status().then(setSiem).catch(() => setSiem(null));
    // The engagement can change without a route change — switching or deleting
    // one on the Dashboard. Re-fetch on an explicit event (immediate) and poll
    // as a fallback so this chip never disagrees with the dashboard selector.
    const onChange = () => loadEng();
    window.addEventListener("heaven:engagement-changed", onChange);
    const t = setInterval(loadEng, 8000);
    return () => {
      window.removeEventListener("heaven:engagement-changed", onChange);
      clearInterval(t);
    };
  }, [location.pathname]);

  useEffect(() => {
    // Self-correcting clock. A plain setInterval(…, 1000) drifts off the wall-
    // clock second (it fires 1000ms after mount, wherever in the second that
    // fell), so the shown time lagged real time by up to ~1s. Re-arm each tick
    // to fire just after the *next* whole second instead.
    let timer;
    const tick = () => {
      setClock(new Date().toLocaleTimeString());
      timer = setTimeout(tick, 1000 - (Date.now() % 1000) + 20);
    };
    tick();
    return () => clearTimeout(timer);
  }, []);

  // Global "scan running" indicator — polls so it stays visible after you
  // navigate away from the Scans page.
  useEffect(() => {
    let alive = true;
    const poll = () =>
      Scans.list(50)
        .then((d) => {
          if (alive) setRunning((d.scans || []).filter((s) => s.status === "running").length);
        })
        .catch(() => {});
    poll();
    const t = setInterval(poll, 10000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const hasEngagement = eng && !eng.no_engagement && eng.engagement;

  return (
    <header className="header">
      <div className="header-left">
        <button
          type="button"
          className="nav-toggle"
          onClick={onMenu}
          aria-label="Toggle navigation menu"
        >
          ☰
        </button>
        {hasEngagement ? (
          <div
            className="eng-chip"
            title={`Engagement: ${eng.engagement.name}${eng.engagement.client ? ` · ${eng.engagement.client}` : ""} · ${eng.stats.total_findings ?? 0} findings · ${eng.stats.scope_targets ?? 0} in scope`}
          >
            <span className="eng-label">Engagement</span>
            <span className="eng-name">{eng.engagement.name}</span>
            {eng.engagement.client && (
              <span className="eng-stats">· {eng.engagement.client}</span>
            )}
            <span className="eng-stats">
              · {eng.stats.total_findings ?? 0} finding{(eng.stats.total_findings ?? 0) !== 1 ? "s" : ""}
              {" · "}{eng.stats.scope_targets ?? 0} target{(eng.stats.scope_targets ?? 0) !== 1 ? "s" : ""}
            </span>
          </div>
        ) : (
          <span className="eng-warn">
            ⚠ No active engagement — run <span className="mono">heaven engage init &lt;name&gt;</span>
          </span>
        )}
      </div>
      <div className="header-right">
        {running > 0 && (
          <button
            type="button"
            className="scan-running-badge"
            onClick={() => navigate("/scans")}
            title={`${running} scan${running !== 1 ? "s" : ""} in progress — view`}
          >
            <span className="scan-running-dot" />
            {running} scanning
          </button>
        )}
        {runningJobs.length > 0 && (
          <button
            type="button"
            className="scan-running-badge job-running-badge"
            onClick={() => navigate(runningJobs[0].path || "/")}
            title={runningJobs.map((j) => j.label || j.key).join(", ") + " — running (safe to navigate away)"}
          >
            <span className="scan-running-dot" />
            {runningJobs.length === 1
              ? (runningJobs[0].label || "1 task running")
              : `${runningJobs.length} tasks running`}
          </button>
        )}
        {siem && (
          <span
            className="user-badge"
            title={
              siem.siem_backends_active.length
                ? `SIEM forwarding active: ${siem.siem_backends_active.join(", ")}`
                : "No SIEM configured — set HEAVEN_SPLUNK_HEC_* or HEAVEN_ELASTIC_* env vars"
            }
            style={{
              borderColor: siem.siem_backends_active.length ? "var(--brand)" : "var(--border)",
              color: siem.siem_backends_active.length ? "var(--brand)" : "var(--text-2)",
            }}
          >
            SIEM {siem.siem_backends_active.length ? "✓" : "—"}
          </span>
        )}
        <button
          type="button"
          className="theme-toggle"
          onClick={toggleTheme}
          title={light ? "Switch to dark theme" : "Switch to light theme"}
          aria-label={light ? "Switch to dark theme" : "Switch to light theme"}
        >
          {light ? "☾" : "☀"}
        </button>
        <span className="header-clock">{clock}</span>
        {user && (
          <span
            className="user-identity"
            title={`Signed in as ${user.username} (role: ${user.role})`}
          >
            <span className="user-name">{user.username}</span>
            <span className="user-role-chip">{user.role}</span>
          </span>
        )}
        <button className="logout-btn" onClick={handleLogout}>Sign out</button>
      </div>
    </header>
  );
}
