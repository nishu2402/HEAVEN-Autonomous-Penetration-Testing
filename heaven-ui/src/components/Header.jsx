import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate, useLocation } from "react-router";
import { Engagement, Engagements, SIEM, Scans, getUser, logout } from "../api";
import { tzLabel } from "../datetime.js";
import { useJobs } from "../context/Jobs.jsx";
import { useToast } from "./Toast.jsx";

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
  const toast = useToast();

  // Header engagement chip doubles as a switcher: open a dropdown of the
  // operator's engagements and switch which one the whole app is viewing.
  const [engList, setEngList] = useState([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [busyEng, setBusyEng] = useState("");
  // How the switcher list is ordered. Remembered per viewer so the operator's
  // preference sticks between opens (falls back to "suggested" if storage is
  // unavailable, e.g. a private window).
  const [engSort, setEngSort] = useState(() => {
    try { return localStorage.getItem("heaven.engSort") || "suggested"; }
    catch { return "suggested"; }
  });
  const switchRef = useRef(null);   // the chip button wrapper (the anchor)
  const menuRef = useRef(null);     // the dropdown itself (portaled to <body>)
  const [menuPos, setMenuPos] = useState({ top: 0, left: 0, width: 0 });

  const loadEngList = () =>
    Engagements.list().then((d) => setEngList(d.engagements || [])).catch(() => {});

  function changeSort(mode) {
    setEngSort(mode);
    try { localStorage.setItem("heaven.engSort", mode); } catch { /* ignore */ }
  }

  // Order the switcher rows for display. Sorting lives on the client so changing
  // the order is instant (no refetch): the server just supplies the raw rows plus
  // an `updated` timestamp for the "recent" mode. "suggested" mirrors the server's
  // default (active first, then most findings, then name) so the list is stable
  // when nothing is chosen.
  const sortedEngList = useMemo(() => {
    const byName = (a, b) =>
      (a.display_name || a.name).localeCompare(
        b.display_name || b.name, undefined, { sensitivity: "base", numeric: true });
    const rows = [...engList];
    switch (engSort) {
      case "name":
        rows.sort(byName);
        break;
      case "findings":
        rows.sort((a, b) => (b.findings - a.findings) || byName(a, b));
        break;
      case "recent":
        rows.sort((a, b) => ((b.updated || 0) - (a.updated || 0)) || byName(a, b));
        break;
      default: // "suggested"
        rows.sort((a, b) =>
          (Number(b.active) - Number(a.active)) ||
          (b.findings - a.findings) ||
          byName(a, b));
    }
    return rows;
  }, [engList, engSort]);

  // The dropdown is rendered through a PORTAL to <body> (see the JSX), not as a
  // child of the chip. That is deliberate: the header's `.header-left` sets
  // `overflow: hidden` (to truncate a long engagement name) and
  // `container-type: inline-size`, both of which used to CLIP an
  // absolutely-positioned child menu so it opened but was invisible — the exact
  // reason the switcher looked "not working". A portal escapes every ancestor's
  // clipping/stacking context, so we position it manually from the chip's rect.
  function placeMenu() {
    const el = switchRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const GAP = 6;
    const width = Math.max(250, Math.min(r.width, 340));
    const left = Math.max(GAP, Math.min(r.left, window.innerWidth - width - GAP));
    setMenuPos({ top: r.bottom + GAP, left, width });
  }

  function toggleMenu() {
    setMenuOpen((o) => {
      const next = !o;
      if (next) { placeMenu(); loadEngList(); }   // anchor + fresh counts on open
      return next;
    });
  }

  // Switch the active engagement for the WHOLE app. setActive fires
  // "heaven:engagement-changed", which this header (and the dashboard, findings,
  // correlations, kill-chain, assets pages) already listen for and re-fetch on.
  async function switchEngagement(name) {
    if (!name || busyEng) return;
    if (name === eng?.engagement?.name) { setMenuOpen(false); return; }
    setBusyEng(name);
    try {
      await Engagements.setActive(name);
      toast.success(`Now viewing "${name}"`);
      setMenuOpen(false);
    } catch (e) {
      toast.error(e?.message || "Could not switch engagement");
    } finally {
      setBusyEng("");
    }
  }

  // Close the dropdown on outside-click or Escape, and keep it anchored to the
  // chip while it's open. Because the menu is portaled to <body> (outside
  // switchRef), an "outside" click must also exempt the menu itself (menuRef) —
  // otherwise a mousedown on a menu row would close the menu before the row's
  // click fires and the switch would silently never happen.
  useEffect(() => {
    if (!menuOpen) return;
    const onDocDown = (e) => {
      const t = e.target;
      if (switchRef.current && switchRef.current.contains(t)) return;
      if (menuRef.current && menuRef.current.contains(t)) return;
      setMenuOpen(false);
    };
    const onKey = (e) => { if (e.key === "Escape") setMenuOpen(false); };
    const reflow = () => placeMenu();
    document.addEventListener("mousedown", onDocDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", reflow);
    window.addEventListener("scroll", reflow, true);
    return () => {
      document.removeEventListener("mousedown", onDocDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", reflow);
      window.removeEventListener("scroll", reflow, true);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [menuOpen]);

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
          <div className="eng-switch" ref={switchRef}>
            <button
              type="button"
              className="eng-chip eng-chip-btn"
              aria-haspopup="listbox"
              aria-expanded={menuOpen}
              onClick={toggleMenu}
              title={`Engagement: ${eng.engagement.name}${eng.engagement.client ? ` · ${eng.engagement.client}` : ""} · ${eng.stats.total_findings ?? 0} findings · ${eng.stats.scope_targets ?? 0} in scope · click to switch`}
            >
              <span className="eng-label">Engagement</span>
              <span className="eng-name">{eng.engagement.name}</span>
              {eng.engagement.client && (
                <span className="eng-stats eng-client">· {eng.engagement.client}</span>
              )}
              <span className="eng-stats eng-counts">
                · {eng.stats.total_findings ?? 0} finding{(eng.stats.total_findings ?? 0) !== 1 ? "s" : ""}
                {" · "}{eng.stats.scope_targets ?? 0} target{(eng.stats.scope_targets ?? 0) !== 1 ? "s" : ""}
              </span>
              <span className="eng-caret" aria-hidden="true">▾</span>
            </button>
            {menuOpen && createPortal(
              <div
                className="eng-menu"
                role="listbox"
                aria-label="Switch engagement"
                ref={menuRef}
                style={{ top: menuPos.top, left: menuPos.left, width: menuPos.width }}
              >
                <div className="eng-menu-head">
                  <span>Switch engagement</span>
                  <select
                    className="eng-sort"
                    value={engSort}
                    onChange={(e) => changeSort(e.target.value)}
                    aria-label="Sort engagements"
                    title="Sort engagements"
                  >
                    <option value="suggested">Suggested</option>
                    <option value="name">Name (A-Z)</option>
                    <option value="findings">Most findings</option>
                    <option value="recent">Recently updated</option>
                  </select>
                </div>
                <div className="eng-switch-list">
                  {engList.length === 0 && (
                    <div className="eng-menu-empty">Loading engagements…</div>
                  )}
                  {sortedEngList.map((e) => (
                    <div
                      key={e.name}
                      className={`eng-switch-row${e.active ? " is-active" : ""}`}
                    >
                      <button
                        type="button"
                        className="eng-switch-pick"
                        role="option"
                        aria-selected={e.active}
                        disabled={busyEng === e.name || e.active}
                        onClick={() => switchEngagement(e.name)}
                        title={e.active ? "Currently viewing" : `Switch to "${e.display_name || e.name}"`}
                      >
                        <span className="eng-switch-dot" />
                        <span className="eng-switch-name">{e.display_name || e.name}</span>
                        {e.active && <span className="eng-switch-tag">current</span>}
                        <span className="eng-switch-count">
                          {e.findings} finding{e.findings === 1 ? "" : "s"}
                        </span>
                      </button>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  className="eng-menu-manage"
                  onClick={() => { setMenuOpen(false); navigate("/"); }}
                >
                  Manage engagements (create · rename · delete) →
                </button>
              </div>,
              document.body,
            )}
          </div>
        ) : (
          <span className="eng-warn">
            ⚠ No active engagement, run <span className="mono">heaven engage init &lt;name&gt;</span>
          </span>
        )}
      </div>
      <div className="header-right">
        {running > 0 && (
          <button
            type="button"
            className="scan-running-badge"
            onClick={() => navigate("/scans")}
            title={`${running} scan${running !== 1 ? "s" : ""} in progress, view`}
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
            title={runningJobs.map((j) => j.label || j.key).join(", ") + ", running (safe to navigate away)"}
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
                : "No SIEM configured: set HEAVEN_SPLUNK_HEC_* or HEAVEN_ELASTIC_* env vars"
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
        <span className="header-clock">{clock} {tzLabel()}</span>
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
