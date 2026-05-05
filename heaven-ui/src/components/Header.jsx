import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Engagement, getUser, logout } from "../api";

export default function Header() {
  const [eng, setEng] = useState(null);
  const [err, setErr] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const user = getUser();

  useEffect(() => {
    Engagement.summary()
      .then(setEng)
      .catch((e) => setErr(e.message));
  }, [location.pathname]);

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <header className="header">
      <div className="header-left">
        {eng && eng.engagement ? (
          <>
            <span className="eng-label">Engagement:</span>{" "}
            <strong>{eng.engagement.name}</strong>
            {eng.engagement.client && (
              <span className="eng-client"> — {eng.engagement.client}</span>
            )}
            <span className="eng-stats">
              {" · "}
              {eng.stats.total_findings} findings · {eng.stats.scope_targets} in scope
            </span>
          </>
        ) : err ? (
          <span className="eng-warn">No active engagement (set HEAVEN_ENGAGEMENT)</span>
        ) : (
          <span className="dim">Loading engagement...</span>
        )}
      </div>
      <div className="header-right">
        {user && <span className="user-badge">{user.username} ({user.role})</span>}
        <button className="logout-btn" onClick={handleLogout}>Sign out</button>
      </div>
    </header>
  );
}
