// HEAVEN — Sidebar with collapsible groups
//
// 17 flat items was overwhelming. Groups mirror the operator's mental
// model: Operations (what you launch) → Findings (what you triage) →
// Engagement (workspace state) → Reporting (what you ship).

import React, { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router";
import Logo from "./Logo.jsx";
import NavIcon from "./NavIcons.jsx";
import { localClock, tzLabel } from "../datetime.js";

const GROUPS = [
  {
    name: "Operations",
    items: [
      { to: "/",            label: "Dashboard",    icon: "dashboard" },
      { to: "/scans",       label: "Scans",        icon: "scans" },
      { to: "/assets",      label: "Assets",       icon: "assets" },
      { to: "/watch",       label: "Watch",        icon: "watch" },
      { to: "/autonomous",  label: "Autonomous",   icon: "autonomous" },
      { to: "/fleet",       label: "Agent Fleet",  icon: "fleet" },
      { to: "/diff",        label: "Scan Diff",    icon: "diff" },
      { to: "/sast",        label: "SAST",         icon: "sast" },
      { to: "/sca",         label: "SCA · Deps",   icon: "sca" },
      { to: "/cve",         label: "CVE Lookup",   icon: "cve" },
      { to: "/analyze",     label: "Analyze",      icon: "analyze" },
    ],
  },
  {
    name: "Findings",
    items: [
      { to: "/findings",    label: "Findings",     icon: "findings" },
      { to: "/leads",       label: "Leads",        icon: "leads" },
      { to: "/correlations", label: "Combined Risk", icon: "risk" },
      { to: "/kill-chain",  label: "Kill Chain",   icon: "killchain" },
      { to: "/ai-plans",    label: "AI Plans",     icon: "aiplans" },
      { to: "/chat",        label: "Assistant",    icon: "assistant" },
      { to: "/coverage",    label: "Coverage",     icon: "coverage" },
    ],
  },
  {
    name: "Engagement",
    items: [
      { to: "/engagement",  label: "Engagement",   icon: "engagement" },
      { to: "/knowledge",   label: "Knowledge",    icon: "knowledge" },
      { to: "/lateral",     label: "Lateral",      icon: "lateral" },
      { to: "/exploit",     label: "Exploit",      icon: "exploit" },
      { to: "/pivot",       label: "Pivot",        icon: "pivot" },
      { to: "/postex",      label: "Post-Ex",      icon: "postex" },
    ],
  },
  {
    name: "Reporting",
    items: [
      { to: "/reports",     label: "Reports",      icon: "reports" },
      { to: "/tickets",     label: "Tickets",      icon: "tickets" },
      { to: "/benchmark",   label: "Benchmark",    icon: "benchmark" },
      { to: "/methodology", label: "Methodology",  icon: "methodology" },
      { to: "/compliance",  label: "Compliance",   icon: "compliance" },
    ],
  },
  {
    name: "System",
    items: [
      { to: "/health",      label: "System Health", icon: "health" },
      { to: "/bin",         label: "Bin",           icon: "bin" },
      { to: "/settings",    label: "Settings",      icon: "settings" },
    ],
  },
];


function useSidebarGroupState() {
  // Default: all groups expanded. Persist collapsed state per browser.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      const raw = localStorage.getItem("heaven.sidebar.collapsed");
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch { return new Set(); }
  });

  function toggle(name) {
    setCollapsed(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      try {
        localStorage.setItem("heaven.sidebar.collapsed", JSON.stringify([...next]));
      } catch { /* localStorage disabled */ }
      return next;
    });
  }
  return [collapsed, toggle];
}


export default function Sidebar() {
  const [time, setTime] = useState(new Date());
  const [collapsed, toggleGroup] = useSidebarGroupState();
  const loc = useLocation();

  useEffect(() => {
    // Self-correcting clock — re-arm each tick to fire just after the next whole
    // second so the display never lags real time (a plain 1000ms interval
    // drifts off the second boundary). Mirrors the header clock.
    let timer;
    const tick = () => {
      setTime(new Date());
      timer = setTimeout(tick, 1000 - (Date.now() % 1000) + 20);
    };
    tick();
    return () => clearTimeout(timer);
  }, []);

  return (
    <aside className="sidebar">
      <div className="brand">
        <Logo size={38} className="brand-logo" />
        <div className="brand-text">
          <span className="brand-title">HEAVEN</span>
          <span className="brand-sub">Pentest Platform</span>
        </div>
      </div>

      <nav aria-label="Primary">
        {GROUPS.map((group) => {
          const isCollapsed = collapsed.has(group.name);
          // Auto-expand a group if the active route belongs to it
          const hasActive = group.items.some(it => loc.pathname === it.to);
          const effectivelyCollapsed = isCollapsed && !hasActive;

          return (
            <div
              key={group.name}
              className={"nav-group" + (effectivelyCollapsed ? " collapsed" : "")}
            >
              <button
                type="button"
                className="nav-group-header"
                aria-expanded={!effectivelyCollapsed}
                onClick={() => toggleGroup(group.name)}
              >
                <span>{group.name}</span>
                <span className="nav-group-chevron" aria-hidden="true">▾</span>
              </button>
              <div className="nav-group-items">
                {group.items.map((it) => (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    end={it.to === "/"}
                    className={({ isActive }) => "nav-item" + (isActive ? " active" : "")}
                  >
                    <span className="nav-icon" aria-hidden="true"><NavIcon name={it.icon} /></span>
                    <span>{it.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-status">
        <div className="flex items-center justify-between">
          <span><span className="status-dot" />System online</span>
          <span className="mono" style={{ color: 'var(--text-2)' }}>
            {localClock(time)} {tzLabel(time)}
          </span>
        </div>
        <div style={{ marginTop: 8, fontSize: 10.5, color: 'var(--text-2)' }}>
          v4.5.0 · press <kbd>⌘K</kbd> for commands
        </div>
      </div>
    </aside>
  );
}
