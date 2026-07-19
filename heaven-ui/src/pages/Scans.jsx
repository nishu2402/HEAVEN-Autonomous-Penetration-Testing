import React, { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Scans as ScansApi, Demo, Engagement, Engagements } from "../api";
import { useToast } from "../components/Toast.jsx";
import HelpTip from "../components/HelpTip.jsx";
import TargetsInput, { classifyTarget } from "../components/TargetsInput.jsx";
import ScanList from "../components/ScanList.jsx";
import { MODE_OPTIONS, MODE_VALUES } from "../scanModes.js";

// Active-scan modes come from the shared scanModes.js source of truth, so the
// launcher <select> and the Dashboard quick-launch grid can never drift apart.
const MODES = MODE_OPTIONS;
const STEALTH = [
  { value: "1", label: "1 — Paranoid (very slow, evasive)" },
  { value: "2", label: "2 — Stealth (slow, low noise)" },
  { value: "3", label: "3 — Normal (balanced)" },
  { value: "4", label: "4 — Aggressive (fast, loud)" },
];

export default function Scans() {
  const toast = useToast();
  const [searchParams] = useSearchParams();

  // Launcher form. A ?mode= query param (from a Dashboard quick-launch tile)
  // preselects the scan mode; anything unrecognized falls back to FULL.
  const initialMode = MODE_VALUES.has(searchParams.get("mode"))
    ? searchParams.get("mode")
    : "full";
  const [targets, setTargets]   = useState("");
  const [mode, setMode]         = useState(initialMode);
  const [stealth, setStealth]   = useState("3");
  // Which engagement the scan's findings will be saved into. A picker of the
  // engagements on disk (+ "new") replaces the old free-text field so a scan
  // can never silently pile into a surprise/sticky engagement — the operator
  // always SEES and chooses the destination. "__new__" reveals the name input.
  const [engList, setEngList]   = useState([]);
  const [engChoice, setEngChoice] = useState("");   // name | "__new__" | "" (loading)
  const [newEng, setNewEng]     = useState("");
  const [authorized, setAuthorized] = useState(false);
  // Optional authenticated-scan credentials (the TARGET's login, so HEAVEN can
  // reach pages behind auth and run the IDOR / Broken Access Control audits).
  // Empty by default — the section is a collapsed disclosure.
  const [cookie, setCookie]               = useState("");   // raw Cookie header
  const [authSpec, setAuthSpec]           = useState("");   // form-login spec
  const [lowPrivCookie, setLowPrivCookie] = useState("");   // 2nd identity cookie
  const [lowPrivAuth, setLowPrivAuth]     = useState("");   // 2nd identity login
  const [launching, setLaunching]   = useState(false);
  // Hard guard against a double-submit firing two POSTs before `launching`
  // re-renders the disabled button (double click / Enter-then-click).
  const submittingRef = useRef(false);
  const [launchError, setLaunchError] = useState(null);
  const [launchSuccess, setLaunchSuccess] = useState(null);
  // Bumping this forces the scan list to reload right after a launch/demo,
  // instead of waiting for its 8-second poll.
  const [listRefresh, setListRefresh] = useState(0);
  const bumpList = () => setListRefresh((n) => n + 1);

  // Keep the mode in sync if the ?mode= param changes while the page stays
  // mounted (e.g. clicking a different Dashboard tile without a full remount).
  useEffect(() => {
    const q = searchParams.get("mode");
    if (q && MODE_VALUES.has(q)) setMode(q);
  }, [searchParams]);

  // Engagement summary → scope context in the launcher.
  const [engSummary, setEngSummary] = useState(null);
  useEffect(() => { Engagement.summary().then(setEngSummary).catch(() => {}); }, []);
  const scopeCount = engSummary?.stats?.scope_targets ?? 0;
  const engName = engSummary?.engagement?.name;

  // Load the engagements on disk and default the destination to the active one
  // so the operator always knows (and can change) where findings will be saved.
  useEffect(() => {
    Engagements.list()
      .then((r) => {
        const list = r.engagements || [];
        setEngList(list);
        setEngChoice((prev) => {
          if (prev) return prev;                       // keep an explicit choice
          const active = list.find((e) => e.active);
          return active ? active.name : (list[0]?.name || "__new__");
        });
      })
      .catch(() => {});
  }, [listRefresh]);

  // Resolved destination engagement name for the launch payload.
  const destEngagement = engChoice === "__new__" ? newEng.trim() : (engChoice || "").trim();

  // Parse + classify targets live for inline validation feedback.
  const parsed = useMemo(() => {
    const raw = targets.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    const valid = [], invalid = [];
    for (const t of raw) (classifyTarget(t) ? valid : invalid).push(t);
    return { valid, invalid };
  }, [targets]);

  const [demoRunning, setDemoRunning] = useState(false);
  async function runDemoScan() {
    setDemoRunning(true);
    try {
      await Demo.scan();
      toast.success("Demo scan started — watch it run in the list below");
      // Re-poll a few times so the running → completed loop is visible quickly.
      [500, 2500, 5000, 8000, 11000, 14000].forEach((ms) => setTimeout(bumpList, ms));
    } catch (e) {
      toast.error(e.message || "Could not start demo scan");
    } finally {
      setDemoRunning(false);
    }
  }

  async function launchScan(e) {
    e.preventDefault();
    if (submittingRef.current) return;               // ignore a rapid double-submit
    if (!authorized) { setLaunchError("You must confirm written authorization before scanning."); return; }
    const rawTargets = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (rawTargets.length === 0) { setLaunchError("Enter at least one target URL or IP."); return; }
    if (engChoice === "__new__" && !destEngagement) {
      setLaunchError("Name the new engagement, or pick an existing one."); return;
    }

    submittingRef.current = true;
    setLaunching(true);
    setLaunchError(null);
    setLaunchSuccess(null);
    try {
      const payload = {
        targets: rawTargets,
        mode,
        stealth_level: parseInt(stealth, 10),
        engagement: destEngagement || undefined,
        i_have_authorization: true,
        // Only send auth fields that are actually filled in.
        ...(cookie.trim()        && { cookie: cookie.trim() }),
        ...(authSpec.trim()      && { auth: authSpec.trim() }),
        ...(lowPrivCookie.trim() && { low_priv_cookie: lowPrivCookie.trim() }),
        ...(lowPrivAuth.trim()   && { low_priv_auth: lowPrivAuth.trim() }),
      };
      const result = await ScansApi.create(payload);
      setLaunchSuccess(
        `Scan launched · ID: ${result.scan_id || result.id || "—"}` +
        (destEngagement ? ` · saving to “${destEngagement}”` : "")
      );
      setTargets("");
      setAuthorized(false);
      setCookie(""); setAuthSpec(""); setLowPrivCookie(""); setLowPrivAuth("");
      setTimeout(bumpList, 1500);
    } catch (err) {
      setLaunchError(err.message || "Launch failed");
    } finally {
      submittingRef.current = false;
      setLaunching(false);
    }
  }

  return (
    <div className="page">
      {/* Scan launcher */}
      <div className="card">
        <div className="card-title">Launch Scan</div>
        <form onSubmit={launchScan} className="scan-form">
          <div className="form-group form-full">
            <label className="form-label" htmlFor="scan-targets">
              Targets <span className="dim">— type a URL, IP or CIDR and press Enter · or paste a list</span>
            </label>
            <TargetsInput
              id="scan-targets"
              value={targets}
              onChange={setTargets}
              placeholder="e.g. https://app.example.com  ·  10.0.0.1  ·  192.168.1.0/24"
            />
            {targets.trim() && (
              <div className="field-hints">
                {parsed.valid.length > 0 && (
                  <span className="field-hint-ok">
                    ✓ {parsed.valid.length} valid target{parsed.valid.length !== 1 ? "s" : ""}
                  </span>
                )}
                {parsed.invalid.length > 0 && (
                  <span className="field-hint-warn">
                    ⚠ {parsed.invalid.length} unrecognized: {parsed.invalid.slice(0, 3).join(", ")}
                    {parsed.invalid.length > 3 ? "…" : ""}
                  </span>
                )}
                {parsed.valid.length > 0 && (
                  <span className="dim">
                    → added to scope{engName ? ` in “${engName}”` : ""} on launch
                  </span>
                )}
              </div>
            )}
            <span className="dim" style={{ fontSize: 11, marginTop: 4 }}>
              Scope: {scopeCount} target{scopeCount !== 1 ? "s" : ""} currently in
              {engName ? ` “${engName}”` : " this engagement"}.
            </span>
          </div>

          <label className="form-group">
            <span className="form-label">
              Scan Mode
              <HelpTip text="FULL runs every module (recommended). The focused modes name the surface you're primarily assessing — web app, network, API, cloud, containers, IoT/OT, Active Directory or email posture." />
            </span>
            <select className="form-select" value={mode} onChange={e => setMode(e.target.value)}>
              {MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </label>

          <label className="form-group">
            <span className="form-label">
              Stealth Level
              <HelpTip text="How aggressive/evasive the scan is. 1 = paranoid (slow, low noise, honeypot-aware) → 4 = aggressive (fast, loud). Lower is stealthier but slower." />
            </span>
            <select className="form-select" value={stealth} onChange={e => setStealth(e.target.value)}>
              {STEALTH.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </label>

          <label className="form-group form-full">
            <span className="form-label">
              Save findings to engagement
              <HelpTip text="The engagement the scan's findings, scope and report are saved into. Defaults to the one you're currently viewing — change it here so a scan never lands in the wrong engagement. Pick “＋ New engagement…” to start a fresh one." />
            </span>
            <select
              className="form-select"
              value={engChoice}
              onChange={e => setEngChoice(e.target.value)}
            >
              {engList.map(e => (
                <option key={e.name} value={e.name}>
                  {(e.display_name || e.name)}{e.active ? " — current" : ""}
                  {` (${e.findings} finding${e.findings === 1 ? "" : "s"})`}
                </option>
              ))}
              <option value="__new__">＋ New engagement…</option>
            </select>
            {engChoice === "__new__" && (
              <input
                className="form-input"
                type="text"
                value={newEng}
                onChange={e => setNewEng(e.target.value)}
                placeholder="e.g. acme-webapp-pentest"
                style={{ marginTop: 8 }}
                autoFocus
              />
            )}
            {destEngagement && (
              <span className="dim" style={{ fontSize: 11, marginTop: 4 }}>
                Findings, scope and report will be saved to “{destEngagement}”.
              </span>
            )}
          </label>

          {/* Optional authenticated scanning — collapsed by default so the
              common (unauthenticated) launch stays uncluttered. */}
          <details className="form-full" style={{ border: "1px solid var(--border)", borderRadius: 8, padding: "10px 12px" }}>
            <summary style={{ cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
              🔐 Authenticated scan <span className="dim" style={{ fontWeight: 400 }}>— optional · reach pages behind a login (enables IDOR &amp; access-control audits)</span>
            </summary>
            <div style={{ marginTop: 12, display: "grid", gap: 12 }}>
              <span className="dim" style={{ fontSize: 11, lineHeight: 1.6 }}>
                Supply the <b>target’s</b> credentials so HEAVEN can crawl and test
                authenticated pages. Use either a raw cookie header or a form login —
                same as the CLI’s <code>--cookie-file</code> / <code>--auth</code>.
              </span>

              <label className="form-group form-full">
                <span className="form-label">
                  Session cookie
                  <HelpTip text="A raw Cookie header copied from your browser's dev tools, e.g. 'session=abc123; csrftoken=xyz'. HEAVEN sends it with every request." />
                </span>
                <input className="form-input" type="text" value={cookie}
                  onChange={e => setCookie(e.target.value)}
                  placeholder="session=abc123; role=admin" autoComplete="off" />
              </label>

              <label className="form-group form-full">
                <span className="form-label">
                  …or form login
                  <HelpTip text="HEAVEN logs in once and reuses the session. Format: url=/login,user=admin,pass=secret. Add csrf_field=<name> for CSRF-protected forms." />
                </span>
                <input className="form-input" type="text" value={authSpec}
                  onChange={e => setAuthSpec(e.target.value)}
                  placeholder="url=/login,user=admin,pass=secret" autoComplete="off" />
              </label>

              <span className="dim" style={{ fontSize: 11, marginTop: 2 }}>
                <b>Lower-privilege identity (optional)</b> — a second, less-privileged
                account. Enables the multi-role Broken Access Control audit to
                <i> prove</i> when a low-priv user reaches protected content.
              </span>
              <label className="form-group form-full">
                <span className="form-label">Low-priv session cookie</span>
                <input className="form-input" type="text" value={lowPrivCookie}
                  onChange={e => setLowPrivCookie(e.target.value)}
                  placeholder="session=def456" autoComplete="off" />
              </label>
              <label className="form-group form-full">
                <span className="form-label">…or low-priv form login</span>
                <input className="form-input" type="text" value={lowPrivAuth}
                  onChange={e => setLowPrivAuth(e.target.value)}
                  placeholder="url=/login,user=guest,pass=guest" autoComplete="off" />
              </label>
            </div>
          </details>

          <label className={"consent-row form-full" + (authorized ? " is-ack" : "")}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
            />
            <span>
              I confirm I have <strong>written authorization</strong> from the target system owner.
              Unauthorized scanning is illegal. HEAVEN logs all scan activity.
              <HelpTip text="Active scanning sends real traffic to the target. HEAVEN refuses to launch without this confirmation, and every action is written to an HMAC-signed audit log." />
            </span>
          </label>

          {launchError && (
            <div className="form-full form-banner form-banner-error">✗ {launchError}</div>
          )}
          {launchSuccess && (
            <div className="form-full form-banner form-banner-ok">✓ {launchSuccess}</div>
          )}

          <div className="form-full" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button
              type="submit"
              disabled={launching || !authorized || parsed.valid.length === 0}
              className="btn btn-primary"
            >
              {launching ? "⏳ Launching…" : "⚡ Launch Scan"}
            </button>
            <button type="button" onClick={runDemoScan} disabled={demoRunning} className="btn">
              {demoRunning ? "Starting…" : "▶ Run demo scan"}
            </button>
            <span className="dim" style={{ fontSize: 11 }}>
              New here? <b>Run demo scan</b> simulates the full loop against sample
              data — no target, no authorization needed.
            </span>
          </div>
        </form>
      </div>

      {/* CLI reference */}
      <div className="card">
        <div className="card-title">CLI Reference</div>
        <p className="dim" style={{ fontSize: 11, lineHeight: 1.7, marginBottom: 10 }}>
          Scans can also be launched from the terminal (authorization gate is enforced in both places).
        </p>
        <pre className="code" style={{ fontSize: 11 }}>{`# Full scan (every module)
heaven scan -u https://app.example.com -m full \\
    --engagement my-eng --i-have-authorization

# Network scan
heaven scan -t 10.0.0.0/24 -m network \\
    --engagement my-eng --i-have-authorization

# Resume interrupted scan
heaven resume --engagement my-eng --i-have-authorization`}</pre>
      </div>

      {/* Pentest scan activity — SAST/SCA live in their own sections, so they
          never merge into this list. */}
      <ScanList kind="pentest" title="Scan Activity" refreshKey={listRefresh} />
    </div>
  );
}
