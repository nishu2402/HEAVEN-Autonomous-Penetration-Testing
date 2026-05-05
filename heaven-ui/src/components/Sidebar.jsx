import React from "react";
import { NavLink } from "react-router-dom";

const ITEMS = [
  { to: "/", label: "Dashboard", icon: "▣" },
  { to: "/engagement", label: "Engagement", icon: "◈" },
  { to: "/findings", label: "Findings", icon: "⚠" },
  { to: "/kill-chain", label: "Kill Chain", icon: "⛓" },
  { to: "/scans", label: "Scans", icon: "⚡" },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">⚡ HEAVEN</div>
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
      <div className="sidebar-footer">v1.0 — operator-driven</div>
    </aside>
  );
}
