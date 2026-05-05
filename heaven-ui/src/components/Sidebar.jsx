import React, { useState, useEffect } from "react";
import { NavLink } from "react-router-dom";

const ITEMS = [
  { to: "/",           label: "Dashboard",  icon: "▣" },
  { to: "/engagement", label: "Engagement", icon: "◈" },
  { to: "/findings",   label: "Findings",   icon: "⚠" },
  { to: "/kill-chain", label: "Kill Chain", icon: "⛓" },
  { to: "/scans",      label: "Scans",      icon: "⚡" },
];

export default function Sidebar() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div>⚡ HEAVEN</div>
        <div className="brand-sub">AUTONOMOUS PEN-TESTING</div>
      </div>

      <nav>
        {ITEMS.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            end={it.to === "/"}
            className={({ isActive }) => "nav-item" + (isActive ? " active" : "")}
          >
            <span className="nav-icon">{it.icon}</span>
            <span>{it.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-status">
        <div><span className="status-dot" />ONLINE</div>
        <div style={{ marginTop: 4, fontFamily: 'monospace', letterSpacing: '0.05em' }}>
          {time.toISOString().slice(11, 19)} UTC
        </div>
        <div style={{ marginTop: 6, fontSize: 9 }}>v1.0 · operator-driven</div>
      </div>
    </aside>
  );
}
