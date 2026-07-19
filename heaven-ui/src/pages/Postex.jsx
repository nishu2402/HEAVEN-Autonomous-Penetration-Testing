// HEAVEN — Post-Exploitation triggers (linpeas / bloodhound / cred-reuse)
// Wraps POST /api/postex/{module}/run. Admin-only — refuses to run for non-admin.

import React, { useState } from "react";
import { Postex, getUser } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";

const MODULES = [
  { key: "full", label: "★ Full playbook (enum + loot + AI kill-chain)" },
  { key: "enum", label: "Privesc enum — Linux (self-contained)" },
  { key: "win-enum", label: "Privesc enum — Windows (services/privs/AIE)" },
  { key: "loot", label: "Loot harvest (creds, redacted)" },
  { key: "linpeas", label: "Linpeas (SSH → privesc enum)" },
  { key: "bloodhound", label: "BloodHound (AD enumeration)" },
  { key: "cred-reuse", label: "Credential reuse spray" },
];

export default function PostexPage() {
  const [module, setModule] = useState("full");
  const [bodyText, setBodyText] = useState(EXAMPLES.full);
  const [authorized, setAuthorized] = useState(false);
  // The post-ex run is a long, blocking request. Tracking it in the global jobs
  // store (instead of local state) means it keeps running — and keeps its result
  // — when you navigate to another page and come back. `formError` stays local
  // because it's pre-flight validation, not part of the running job.
  const { loading, result, error, start, clear } = useJob("postex");
  const [formError, setFormError] = useState(null);
  const user = getUser();
  const isAdmin = (user?.role === "admin");

  function selectModule(m) {
    setModule(m);
    setBodyText(EXAMPLES[m]);
    setFormError(null);
    clear();
  }

  function runModule(mod, body) {
    if (mod === "full") return Postex.full(body);
    if (mod === "enum") return Postex.enum(body);
    if (mod === "win-enum") return Postex.winEnum(body);
    if (mod === "loot") return Postex.loot(body);
    if (mod === "linpeas") return Postex.linpeas(body);
    if (mod === "bloodhound") return Postex.bloodhound(body);
    return Postex.credReuse(body);
  }

  function run() {
    setFormError(null);
    if (!authorized) {
      setFormError("Authorization checkbox is required.");
      return;
    }
    let body;
    try {
      body = JSON.parse(bodyText || "{}");
    } catch (e) {
      setFormError(`Body JSON is invalid: ${e.message}`);
      return;
    }
    const mod = module;
    start(
      { label: `Post-Ex · ${mod}`, kind: "postex", path: "/postex" },
      () => runModule(mod, body),
    );
  }

  if (!isAdmin) {
    return (
      <div className="page">
        <div className="card error">
          Post-exploitation is admin-only. You're signed in as
          {" "}<strong>{user?.username || "?"}</strong> ({user?.role || "no role"}).
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--crit)", marginTop: 0 }}>⚡ Post-Exploitation</h2>
        <p className="page-lead">
          Destructive operations. Every module is admin-gated server-side and
          requires <code>authorized=True</code>; this UI checkbox is the
          operator's explicit ack.
        </p>

        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          {MODULES.map((m) => (
            <button key={m.key}
                    className={"btn-small" + (module === m.key ? " active" : "")}
                    onClick={() => selectModule(m.key)}>
              {m.label}
            </button>
          ))}
        </div>

        <label className="form-group">
          <span className="form-label">Body JSON</span>
          <textarea className="form-input mono-input" value={bodyText} rows={10}
                    spellCheck={false}
                    onChange={(e) => setBodyText(e.target.value)} />
        </label>

        <label className={"consent-row" + (authorized ? " is-ack" : "")}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I have <strong>written authorization</strong> for this destructive action.</span>
        </label>

        <button className="btn btn-danger" disabled={loading || !authorized} onClick={run}>
          {loading ? "Running…" : `Run ${module}`}
        </button>

        {(formError || error) && (
          <div className="error" style={{ marginTop: 12 }}>{formError || error}</div>
        )}
        {loading && (
          <div className="dim" style={{ marginTop: 10, fontSize: 12 }}>
            This runs on the server — you can switch pages and come back; it keeps running.
          </div>
        )}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>
      )}

      {result && <ResultView result={result} />}
    </div>
  );
}

// Structured view for the advanced modules; falls back to raw JSON otherwise.
function ResultView({ result }) {
  const killChain = result.kill_chain || [];
  const ai = result.ai_analysis;
  const findings = result.findings || [];
  const facts = result.facts;
  const loot = result.loot;

  return (
    <>
      {facts && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">Host</div>
          <div style={{ fontSize: 13 }}>
            <strong>{facts.hostname || "?"}</strong>
            {" "}<span className="dim">{facts.os} · kernel {facts.kernel}</span>
            <div className="dim" style={{ marginTop: 4 }}>
              user {facts.username} (uid={String(facts.uid)}, root={String(facts.is_root)})
              {facts.groups?.length ? ` · groups: ${facts.groups.join(", ")}` : ""}
            </div>
            {facts.listening_ports?.length ? (
              <div className="dim">listening: {facts.listening_ports.join(", ")}</div>
            ) : null}
          </div>
        </div>
      )}

      {killChain.length > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">ATT&CK kill-chain</div>
          {killChain.map((step, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <span className="badge" style={{ background: "var(--accent-dim)" }}>
                {step.tactic}
              </span>
              {" "}
              <span className="dim" style={{ fontSize: 12 }}>
                {(step.techniques || []).map((t) => `${t.id} ${t.name}`).join(", ")}
              </span>
            </div>
          ))}
        </div>
      )}

      {ai && ai.available && (
        <div className="card" style={{ marginTop: 12, borderLeft: "3px solid var(--accent)" }}>
          <div className="card-title">
            AI prioritisation <span className="dim">({ai.provider}/{ai.model})</span>
          </div>
          {ai.top_vector && (
            <div><strong>Top path:</strong> {ai.top_vector}</div>
          )}
          {ai.rationale && <Markdown>{ai.rationale}</Markdown>}
          {ai.recommended_next_steps?.length > 0 && (
            <ul style={{ fontSize: 13, marginBottom: 6 }}>
              {ai.recommended_next_steps.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          )}
          {ai.pivot_targets?.length > 0 && (
            <div className="dim" style={{ fontSize: 12 }}>
              Pivot targets: {ai.pivot_targets.join(", ")}
            </div>
          )}
        </div>
      )}

      {findings.length > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">Findings ({findings.length})</div>
          {findings.map((f, i) => (
            <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
              <span className={"sev-pill sev-" + (f.severity || "info")}>
                {f.severity}
              </span>{" "}
              <strong style={{ fontSize: 13 }}>{f.title}</strong>
              {f.evidence?.abuse && (
                <div className="dim" style={{ fontSize: 12 }}>{f.evidence.abuse}</div>
              )}
              {f.mitre?.techniques?.length > 0 && (
                <div className="dim" style={{ fontSize: 11 }}>
                  {f.mitre.techniques.map((t) => t.id).join(", ")}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {loot && loot.item_count > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">
            Loot ({loot.item_count} items · {loot.credential_count} creds)
            <span className="dim" style={{ fontSize: 11 }}> — secrets redacted</span>
          </div>
          {(loot.items || []).map((it, i) => (
            <div key={i} style={{ fontSize: 12, padding: "3px 0" }}>
              <span className={"sev-pill sev-" + (it.severity || "info")}>{it.severity}</span>{" "}
              <strong>{it.category}</strong> <span className="dim">{it.secret_preview}</span>
            </div>
          ))}
        </div>
      )}

      <div className="card" style={{ marginTop: 12 }}>
        <details>
          <summary className="card-title" style={{ cursor: "pointer" }}>Raw JSON</summary>
          <pre className="cli-block" style={{ wordBreak: "break-word", fontSize: 11 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </details>
      </div>
    </>
  );
}

const EXAMPLES = {
  full: JSON.stringify({
    host: "10.0.0.5",
    username: "deploy",
    password: "deploy-pass",
    port: 22,
    enable_loot: true,
    ai_analysis: true,
  }, null, 2),
  enum: JSON.stringify({
    host: "10.0.0.5",
    username: "deploy",
    password: "deploy-pass",
    port: 22,
  }, null, 2),
  "win-enum": JSON.stringify({
    host: "10.0.0.7",
    username: "svc_app",
    password: "Winter2026!",
    port: 22,
  }, null, 2),
  loot: JSON.stringify({
    host: "10.0.0.5",
    username: "deploy",
    password: "deploy-pass",
    port: 22,
  }, null, 2),
  linpeas: JSON.stringify({
    host: "10.0.0.5",
    username: "root",
    password: "toor",
    port: 22,
  }, null, 2),
  bloodhound: JSON.stringify({
    domain: "CORP.LOCAL",
    dc_host: "10.0.0.10",
    username: "Administrator",
    password: "Password123!",
    use_ssl: false,
  }, null, 2),
  "cred-reuse": JSON.stringify({
    credentials: [["admin", "admin"], ["root", "toor"]],
    targets: [["10.0.0.5", 22, "ssh"], ["10.0.0.6", 445, "smb"]],
  }, null, 2),
};
