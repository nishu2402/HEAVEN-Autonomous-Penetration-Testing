// HEAVEN — Sidebar with collapsible groups
//
// 17 flat items was overwhelming. Groups mirror the operator's mental
// model: Operations (what you launch) → Findings (what you triage) →
// Engagement (workspace state) → Reporting (what you ship).

import React, { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";

const GROUPS = [
  {
    name: "Operations",
    items: [
      { to: "/",            label: "Dashboard",    icon: "▣" },
      { to: "/scans",       label: "Scans",        icon: "⚡" },
      { to: "/watch",       label: "Watch",        icon: "🔁" },
      { to: "/autonomous",  label: "Autonomous",   icon: "∞" },
      { to: "/diff",        label: "Scan Diff",    icon: "↹" },
      { to: "/sast",        label: "SAST",         icon: "🔬" },
      { to: "/sca",         label: "SCA · Deps",   icon: "📦" },
    ],
  },
  {
    name: "Findings",
    items: [
      { to: "/findings",    label: "Findings",     icon: "⚠" },
      { to: "/kill-chain",  label: "Kill Chain",   icon: "⛓" },
      { to: "/ai-plans",    label: "AI Plans",     icon: "✦" },
      { to: "/coverage",    label: "Coverage",     icon: "◐" },
    ],
  },
  {
    name: "Engagement",
    items: [
      { to: "/engagement",  label: "Engagement",   icon: "◈" },
      { to: "/knowledge",   label: "Knowledge",    icon: "🧠" },
      { to: "/lateral",     label: "Lateral",      icon: "↔" },
      { to: "/postex",      label: "Post-Ex",      icon: "☣" },
    ],
  },
  {
    name: "Reporting",
    items: [
      { to: "/reports",     label: "Reports",      icon: "📄" },
      { to: "/tickets",     label: "Tickets",      icon: "🎫" },
      { to: "/benchmark",   label: "Benchmark",    icon: "≡" },
      { to: "/methodology", label: "Methodology",  icon: "§" },
    ],
  },
  {
    name: "System",
    items: [
      { to: "/health",      label: "System Health", icon: "🩺" },
      { to: "/settings",    label: "Settings",      icon: "⚙" },
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
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">⚡</div>
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
                    <span className="nav-icon" aria-hidden="true">{it.icon}</span>
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
            {time.toISOString().slice(11, 19)}
          </span>
        </div>
        <div style={{ marginTop: 8, fontSize: 10.5, color: 'var(--text-2)' }}>
          v1.0 · press <kbd>⌘K</kbd> for commands
        </div>
      </div>
    </aside>
  );
}
