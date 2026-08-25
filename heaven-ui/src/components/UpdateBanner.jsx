// HEAVEN — "update available" banner.
//
// Shown at the top of every authenticated page when a newer HEAVEN version is
// available on the git remote. Detection runs on app open only when the operator
// has turned on auto-check (Settings → Updates) — otherwise no network call is
// made. Everyone sees the banner; only an admin can apply the update (git pull +
// rebuild on the server), which never overwrites uncommitted work. Dismissing
// remembers the version so it won't nag again until a newer one appears.
// Theme-aware via CSS variables; identical in light & dark.

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { Update, getUser } from "../api";
import { useToast } from "./Toast.jsx";

const DISMISS_KEY = "heaven.update.dismissed";

function readDismissed() {
  try { return localStorage.getItem(DISMISS_KEY) || ""; } catch { return ""; }
}
function writeDismissed(v) {
  try { localStorage.setItem(DISMISS_KEY, v || ""); } catch { /* storage off */ }
}

export default function UpdateBanner() {
  const [status, setStatus] = useState(null);
  const [dismissed, setDismissed] = useState(readDismissed());
  const [applying, setApplying] = useState(false);
  const [log, setLog] = useState([]);
  const [finished, setFinished] = useState(null); // {ok}
  const pollRef = useRef(null);
  const toast = useToast();
  const user = getUser();
  const isAdmin = user?.role === "admin";

  useEffect(() => {
    let alive = true;
    // Cheap local check first (no network); it also tells us the auto-check pref.
    Update.status({ fetch: false })
      .then((s) => {
        if (!alive) return;
        setStatus(s);
        // Only reach out to the remote when the operator opted in.
        if (s.auto_check) {
          Update.status().then((s2) => alive && setStatus(s2)).catch(() => {});
        }
      })
      .catch(() => {});
    return () => { alive = false; if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const startPoll = useCallback(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const s = await Update.applyStatus();
        setLog(s.log || []);
        if (s.done) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setApplying(false);
          setFinished({ ok: s.ok });
          if (s.ok) toast.success("Update applied: restart the server to run it");
          else toast.error("Update did not complete: see the log");
        }
      } catch { /* transient, keep polling */ }
    }, 2000);
  }, [toast]);

  async function updateNow() {
    setApplying(true);
    setLog([]);
    setFinished(null);
    try {
      await Update.apply();
      startPoll();
    } catch (e) {
      setApplying(false);
      toast.error(e.message || "Could not start the update");
    }
  }

  function dismiss() {
    const v = status?.latest_version || "dismissed";
    writeDismissed(v);
    setDismissed(v);
  }

  if (!status || !status.available) return null;
  const latest = status.latest_version || "";
  if (!applying && !finished && latest && latest === dismissed) return null;

  const cur = status.current_version || "?";

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
      padding: "10px 14px", marginBottom: 14, borderRadius: "var(--radius-md)",
      border: "1px solid color-mix(in srgb, var(--brand) 45%, transparent)",
      background: "color-mix(in srgb, var(--brand) 10%, transparent)",
      fontSize: 13,
    }}>
      <span style={{ fontSize: 18, lineHeight: 1 }} aria-hidden="true">⬆️</span>
      <div style={{ flex: 1, minWidth: 200 }}>
        {finished ? (
          <span style={{ color: finished.ok ? "var(--ok, #46d39a)" : "var(--crit)", fontWeight: 600 }}>
            {finished.ok
              ? "✓ Update applied, restart the HEAVEN server to run the new version."
              : "⚠ Update didn't complete, open Settings → Updates for the full log."}
          </span>
        ) : applying ? (
          <span style={{ color: "var(--text-0)" }}>
            <strong>Updating…</strong>{" "}
            <span className="dim">{log.length ? log[log.length - 1] : "starting…"}</span>
          </span>
        ) : (
          <span style={{ color: "var(--text-0)" }}>
            <strong style={{ color: "var(--brand)" }}>HEAVEN update available</strong>:{" "}
            v{cur} → <strong>v{latest}</strong>
            {status.behind ? (
              <span className="dim"> · {status.behind} commit{status.behind === 1 ? "" : "s"} behind</span>
            ) : null}
            {isAdmin && !status.can_apply && status.dirty ? (
              <span className="dim"> · uncommitted changes on the server block auto-apply</span>
            ) : null}
          </span>
        )}
      </div>

      {!applying && !finished && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {isAdmin && status.can_apply && (
            <button type="button" onClick={updateNow} style={btnPrimary}>Update now</button>
          )}
          <Link to="/settings" style={btnGhost}>Details</Link>
          <button type="button" onClick={dismiss} style={btnGhost}>Dismiss</button>
        </div>
      )}
      {finished && (
        <Link to="/settings" style={btnGhost}>Open Settings</Link>
      )}
    </div>
  );
}

const btnPrimary = {
  padding: "7px 13px", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
  background: "var(--brand)", color: "#fff", border: "none",
  borderRadius: "var(--radius-md)", fontFamily: "var(--font-ui)",
};
const btnGhost = {
  padding: "7px 13px", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
  background: "rgba(255,255,255,0.04)", color: "var(--text-0)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  fontFamily: "var(--font-ui)", textDecoration: "none", display: "inline-block",
};
