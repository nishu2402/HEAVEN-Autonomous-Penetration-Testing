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
          <>
            <span className="eng-label">ENG</span>
            <span className="eng-name">{eng.engagement.name}</span>
            {eng.engagement.client && (
              <span className="eng-stats"> — {eng.engagement.client}</span>
            )}
            <span className="eng-stats">
              {" · "}{eng.stats.total_findings ?? 0} findings
              {" · "}{eng.stats.scope_targets ?? 0} targets
            </span>
          </>
        ) : (
          <span className="eng-warn">
            No engagement — run: heaven engage init &lt;name&gt;
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
              borderColor: siem.siem_backends_active.length ? "#00FF41" : "rgba(255,255,255,0.2)",
              color: siem.siem_backends_active.length ? "#00FF41" : "rgba(255,255,255,0.5)",
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
