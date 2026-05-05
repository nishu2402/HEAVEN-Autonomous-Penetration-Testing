import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Engagement, getUser, logout } from "../api";

export default function Header() {
  const [eng, setEng] = useState(null);
  const [clock, setClock] = useState(new Date().toLocaleTimeString());
  const navigate = useNavigate();
  const location = useLocation();
  const user = getUser();

  useEffect(() => {
    Engagement.summary().then(setEng).catch(() => {});
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
        <span className="header-clock">{clock}</span>
        {user && (
          <span className="user-badge">{user.username} · {user.role}</span>
        )}
        <button className="logout-btn" onClick={handleLogout}>Sign out</button>
      </div>
    </header>
  );
}
