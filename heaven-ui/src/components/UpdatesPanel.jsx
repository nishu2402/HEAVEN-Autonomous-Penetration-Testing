// HEAVEN — Settings → Updates panel.
//
// The full self-update surface: current vs latest version, a "Check now" button
// (network), and an admin-only "Update now" that fast-forwards the checkout and
// rebuilds on the server, with a live progress log. The auto-check on/off toggle
// itself is the HEAVEN_UPDATE_AUTO_CHECK setting rendered by the Settings loop
// above this panel. Honest about non-git installs (mirrors `heaven update`).

import React, { useEffect, useRef, useState } from "react";
import { Update, getUser } from "../api";
import { useToast } from "./Toast.jsx";

const btn = {
  padding: "8px 12px", background: "rgba(255,255,255,0.03)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  color: "var(--text-0)", fontSize: 12, cursor: "pointer", fontFamily: "var(--font-ui)",
};
const btnPrimary = { ...btn, background: "var(--brand)", borderColor: "var(--brand)", color: "#fff", fontWeight: 600 };

export default function UpdatesPanel() {
  const [status, setStatus] = useState(null);
  const [checking, setChecking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [log, setLog] = useState([]);
  const [done, setDone] = useState(null);
  const pollRef = useRef(null);
  const toast = useToast();
  const isAdmin = getUser()?.role === "admin";

  useEffect(() => {
    Update.status({ fetch: false }).then(setStatus).catch(() => {});
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function check() {
    setChecking(true);
    try {
      setStatus(await Update.status());
    } catch (e) {
      toast.error(e.message || "Update check failed");
    } finally {
      setChecking(false);
    }
  }

  function startPoll() {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const s = await Update.applyStatus();
        setLog(s.log || []);
        if (s.done) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setApplying(false);
          setDone({ ok: s.ok });
          if (s.ok) { toast.success("Update applied: restart the server to run it"); check(); }
          else toast.error("Update did not complete: see the log");
        }
      } catch { /* transient */ }
    }, 2000);
  }

  async function updateNow() {
    if (!window.confirm(
      "Apply the update now? HEAVEN will fast-forward its code and rebuild on the "
      + "server. Uncommitted changes are never overwritten. The new version becomes "
      + "active after you restart the server.")) return;
    setApplying(true);
    setLog([]);
    setDone(null);
    try {
      await Update.apply();
      startPoll();
    } catch (e) {
      setApplying(false);
      toast.error(e.message || "Could not start the update");
    }
  }

  if (!status) {
    return <div className="dim" style={{ fontSize: 12 }}>Checking update status…</div>;
  }

  const notGit = status.is_git === false;
  // Deploy-time kill switch: applying from the browser can be turned off server
  // side (HEAVEN_DISABLE_WEB_UPDATE). Detection still works; apply must be run
  // from the shell. Only surface the notice when there's actually an update.
  const webApplyOff = status.web_apply_enabled === false;

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 12.5 }}>
        <span>Installed: <strong style={{ color: "var(--text-0)" }}>
          v{status.current_version || "?"}</strong></span>
        {status.latest_version && (
          <span>Latest: <strong style={{
            color: status.available ? "var(--brand)" : "var(--text-0)" }}>
            v{status.latest_version}</strong></span>
        )}
        {status.branch && <span className="dim">branch {status.branch}</span>}
      </div>

      {notGit ? (
        <div className="dim" style={{ fontSize: 12, lineHeight: 1.7 }}>
          This HEAVEN wasn't installed as an editable git checkout, so it can't
          self-update in place. Update via <code>git pull &amp;&amp; ./scripts/install.sh</code>,
          a fresh Docker image, or the latest GitHub release.
        </div>
      ) : status.available ? (
        <div style={{ fontSize: 12.5, color: "var(--brand)", fontWeight: 600 }}>
          Update available, {status.behind} commit{status.behind === 1 ? "" : "s"} behind
          {status.upstream ? ` ${status.upstream}` : ""}.
          {status.dirty ? (
            <span className="dim" style={{ fontWeight: 400 }}>
              {" "}({status.dirty_files?.length || 0} uncommitted change(s) on the server, 
              commit/stash them to enable auto-apply.)
            </span>
          ) : null}
        </div>
      ) : (
        <div style={{ fontSize: 12.5, color: "var(--ok, #46d39a)" }}>
          ✓ You're on the latest version.
        </div>
      )}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button type="button" onClick={check} disabled={checking || applying} style={btn}>
          {checking ? "Checking…" : "Check now"}
        </button>
        {!notGit && status.available && isAdmin && !webApplyOff && (
          <button type="button" onClick={updateNow}
            disabled={applying || !status.can_apply}
            title={status.can_apply ? "" : "Blocked: uncommitted changes or an update already running"}
            style={{ ...btnPrimary, opacity: (applying || !status.can_apply) ? 0.5 : 1 }}>
            {applying ? "Updating…" : "Update now"}
          </button>
        )}
        {!notGit && status.available && isAdmin && webApplyOff && (
          <span className="dim" style={{ fontSize: 11.5 }}>
            Web-based apply is disabled on this server, run <code>heaven update</code> from the shell.
          </span>
        )}
        {!notGit && status.available && !isAdmin && !webApplyOff && (
          <span className="dim" style={{ fontSize: 11.5 }}>
            Applying an update requires an admin account.
          </span>
        )}
      </div>

      {(applying || log.length > 0 || done) && (
        <pre style={{
          margin: 0, padding: "10px 12px", maxHeight: 200, overflow: "auto",
          background: "var(--console-bg, #0d1117)", color: "var(--console-fg, #d6deeb)",
          border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
          fontSize: 11.5, fontFamily: "var(--font-mono, monospace)", lineHeight: 1.6,
          whiteSpace: "pre-wrap", wordBreak: "break-word",
        }}>
          {log.length ? log.join("\n") : "starting…"}
          {done && (done.ok
            ? "\n\n✓ Done. Restart `heaven serve` to run the new version."
            : "\n\n⚠ Update did not complete.")}
        </pre>
      )}
    </div>
  );
}
