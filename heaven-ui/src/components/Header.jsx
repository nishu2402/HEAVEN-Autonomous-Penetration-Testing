import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Engagement, SIEM, getUser, logout } from "../api";

export default function Header() {
  const [eng, setEng] = useState(null);
  const [siem, setSiem] = useState(null);
  const [clock, setClock] = useState(new Date().toLocaleTimeString());
  const navigate = useNavigate();
  const location = useLocation();
  const user = getUser();

  useEffect(() => {
    Engagement.summary().then(setEng).catch(() => {});
    SIEM.status().then(setSiem).catch(() => setSiem(null));
  }, [location.pathname]);

  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const hasEngagement = eng && !eng.no_engagement && eng.engagement;

  return (
    <header className="header">
      <div className="header-left">
        {hasEngagement ? (
          <div className="eng-chip">
            <span className="eng-label">Engagement</span>
            <span className="eng-name">{eng.engagement.name}</span>
            {eng.engagement.client && (
              <span className="eng-stats">· {eng.engagement.client}</span>
            )}
            <span className="eng-stats">
              · {eng.stats.total_findings ?? 0} findings · {eng.stats.scope_targets ?? 0} targets
            </span>
          </div>
        ) : (
          <span className="eng-warn">
            ⚠ No active engagement — run <span className="mono">heaven engage init &lt;name&gt;</span>
          </span>
        )}
      </div>
      <div className="header-right">
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
        <span className="header-clock">{clock}</span>
        {user && (
          <span className="user-badge">{user.username} · {user.role}</span>
        )}
        <button className="logout-btn" onClick={handleLogout}>Sign out</button>
      </div>
    </header>
  );
}
