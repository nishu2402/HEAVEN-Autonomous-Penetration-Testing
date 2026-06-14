// HEAVEN — System Health page (the web-UI equivalent of `heaven doctor`)
//
// Answers the new operator's question "is it broken, or just missing a tool?"
// at a glance: external tools (with install hints), optional integrations, which
// API keys are configured, Python module health, and actionable next steps.

import React, { useEffect, useState } from "react";
import { System } from "../api";
import { useToast } from "../components/Toast.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

function Dot({ ok }) {
  return (
    <span style={{
      display: "inline-block", width: 9, height: 9, borderRadius: "50%",
      background: ok ? "var(--ok, #46d39a)" : "var(--text-2)", flexShrink: 0,
    }} aria-hidden="true" />
  );
}

function Card({ title, children }) {
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div style={{ fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
                    color: "var(--text-2)", fontWeight: 600, marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

export default function Health() {
  const [h, setH] = useState(null);
  const [error, setError] = useState(null);
  const toast = useToast();

  function load() {
    System.health().then(setH).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  if (error) return <div className="page"><div className="card error">Failed to load system health: {error}</div></div>;
  if (!h) return <div className="page"><SkeletonCard lines={8} /></div>;

  const tools = h.tools || [];
  const missing = tools.filter((t) => !t.present).length;
  const llm = h.llm || {};
  const settings = h.settings?.groups || [];
  const modules = h.modules || {};
  const modulesOk = Object.values(modules).filter((v) => v === "OK").length;

  return (
    <div className="page">
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <h2 style={{ color: "var(--text-0)", margin: 0 }}>🩺 System Health</h2>
          <button className="btn" onClick={() => { setH(null); load(); toast.info?.("Refreshing…"); }}>
            Refresh
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 6 }}>
          HEAVEN {h.version} · Python {h.python}. This is the web equivalent of{" "}
          <code>heaven doctor</code> — everything optional degrades gracefully, so a
          missing tool just disables one capability, it doesn't break the app.
        </p>
      </div>

      {/* Next steps — the single most useful guidance for current state */}
      {Array.isArray(h.next_steps) && h.next_steps.length > 0 && (
        <Card title="Recommended next steps">
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.8 }}>
            {h.next_steps.map((s, i) => <li key={i}>{s}</li>)}
          </ul>
        </Card>
      )}

      {/* External tools */}
      <Card title={`External tools  ·  ${tools.length - missing}/${tools.length} available`}>
        <div style={{ display: "grid", gap: 10 }}>
          {tools.map((t) => (
            <div key={t.name} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
              <Dot ok={t.present} />
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                  <code style={{ fontSize: 13, color: "var(--text-0)" }}>{t.name}</code>
                  <span className="dim" style={{ fontSize: 12 }}>{t.purpose}</span>
                </div>
                {!t.present && t.hint && (
                  <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>
                    Install: <code>{t.hint}</code>
                  </div>
                )}
              </div>
              <span style={{ fontSize: 11, color: t.present ? "var(--ok, #46d39a)" : "var(--text-2)" }}>
                {t.present ? "found" : "missing"}
              </span>
            </div>
          ))}
        </div>
      </Card>

      {/* API keys & integrations — which are configured (links to Settings) */}
      <Card title="API keys & integrations">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 10 }}>
          {settings.map((g) => {
            const set = g.settings.filter((s) => s.is_set).length;
            return (
              <div key={g.name} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                <Dot ok={set > 0} />
                <div>
                  <div style={{ fontSize: 13, color: "var(--text-0)" }}>{g.name}</div>
                  <div className="dim" style={{ fontSize: 11.5 }}>{set}/{g.settings.length} configured</div>
                </div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 12, fontSize: 12 }}>
          <span className="dim">LLM: </span>
          <span style={{ color: llm.available ? "var(--ok, #46d39a)" : "var(--text-2)" }}>
            {llm.available ? `✓ ${llm.provider} (${llm.model})` : "not configured (deterministic fallback in use)"}
          </span>
          {"  ·  "}
          <a href="#/settings" onClick={(e) => { e.preventDefault(); window.location.hash = "#/settings"; }}
             style={{ color: "var(--brand)" }}>Manage keys in Settings →</a>
        </div>
      </Card>

      {/* Module health */}
      <Card title={`Python modules  ·  ${modulesOk}/${Object.keys(modules).length} OK`}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 8 }}>
          {Object.entries(modules).map(([name, state]) => (
            <div key={name} style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <Dot ok={state === "OK"} />
              <code style={{ fontSize: 12, color: "var(--text-0)" }}>{name}</code>
              {state !== "OK" && <span className="dim" style={{ fontSize: 11 }}>{state}</span>}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
