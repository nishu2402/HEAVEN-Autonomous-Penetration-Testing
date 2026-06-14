// HEAVEN — Settings page (API keys & integrations)
//
// The friendly home for every API key HEAVEN understands. Enter a key here and
// it's persisted to .env + the running server (GET/POST /api/settings), so it
// takes effect immediately, survives a restart, and the CLI sees it too — the
// exact same keys `heaven config` and `heaven init` manage. Secrets are never
// sent back to the browser in full; we only show a masked preview + "is it set".

import React, { useEffect, useMemo, useState } from "react";
import { Settings as SettingsApi } from "../api";
import { useToast } from "../components/Toast.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

export default function Settings() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);
  const [draft, setDraft] = useState({});       // key -> new value (only touched keys)
  const [reveal, setReveal] = useState({});      // key -> bool (show secret input)
  const [saving, setSaving] = useState(false);
  const [llm, setLlm] = useState(null);          // test-llm result
  const [testing, setTesting] = useState(false);
  const toast = useToast();

  function load() {
    SettingsApi.get().then(setStatus).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  const dirtyKeys = useMemo(() => Object.keys(draft), [draft]);

  function setVal(key, value) {
    setDraft((d) => ({ ...d, [key]: value }));
  }
  function discardField(key) {
    setDraft((d) => { const n = { ...d }; delete n[key]; return n; });
  }

  async function save() {
    if (dirtyKeys.length === 0) return;
    setSaving(true);
    try {
      const res = await SettingsApi.update(draft);
      setStatus(res.status);
      setDraft({});
      setReveal({});
      const n = res.changed?.length || 0;
      toast.success(n ? `Saved ${n} setting${n > 1 ? "s" : ""}` : "No changes");
    } catch (e) {
      toast.error(e.message || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function testLlm() {
    setTesting(true);
    setLlm(null);
    try {
      setLlm(await SettingsApi.testLlm());
    } catch (e) {
      setLlm({ available: false, reason: e.message });
    } finally {
      setTesting(false);
    }
  }

  if (error) {
    return (
      <div className="page">
        <div className="card error">Failed to load settings: {error}</div>
      </div>
    );
  }
  if (!status) {
    return <div className="page"><SkeletonCard lines={8} /></div>;
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>⚙ Settings — API keys & integrations</h2>
        <p className="dim" style={{ fontSize: 12, lineHeight: 1.6 }}>
          Everything here is <strong style={{ color: "var(--text-0)" }}>optional</strong> — HEAVEN
          scans, reports and the ML risk scoring all work with no keys. Add a key to unlock its
          feature (an LLM key turns on autonomous mode &amp; AI attack plans). Saved values are
          written to <code>.env</code> and applied to the running server immediately, so they
          persist across restarts and the <code>heaven</code> CLI picks them up too.
        </p>
        <p className="dim" style={{ fontSize: 11 }}>
          Secrets are stored encrypted-at-rest server-side and only ever shown here as a masked
          preview. Source of truth: <code>{status.env_path}</code>
        </p>
      </div>

      {status.groups.map((group) => (
        <div className="card" key={group.name} style={{ marginTop: 12 }}>
          <div style={{
            fontSize: 10.5, letterSpacing: "0.1em", textTransform: "uppercase",
            color: "var(--text-2)", fontWeight: 600, marginBottom: 12,
          }}>
            {group.name}
          </div>

          <div style={{ display: "grid", gap: 16 }}>
            {group.settings.map((s) => {
              const touched = s.key in draft;
              const showInput = !s.secret || reveal[s.key] || touched;
              return (
                <div key={s.key} style={{ display: "grid", gap: 5 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <label htmlFor={s.key} style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text-0)" }}>
                      {s.label}
                    </label>
                    {s.is_set ? (
                      <span style={{
                        fontSize: 10, fontWeight: 600, color: "var(--ok, #46d39a)",
                        border: "1px solid var(--border)", borderRadius: 99, padding: "1px 8px",
                      }}>
                        ✓ set{s.secret && s.masked ? ` · ${s.masked}` : ""}
                      </span>
                    ) : (
                      <span style={{ fontSize: 10, color: "var(--text-2)" }}>not set</span>
                    )}
                    <code style={{ fontSize: 10.5, color: "var(--text-2)", marginLeft: "auto" }}>{s.key}</code>
                  </div>

                  <div className="dim" style={{ fontSize: 11.5 }}>
                    {s.help}
                    {s.url ? (
                      <> {" "}
                        <a href={s.url} target="_blank" rel="noopener noreferrer"
                           style={{ color: "var(--brand)" }}>
                          How to get it →
                        </a>
                      </>
                    ) : null}
                  </div>

                  {/* Choice (dropdown) vs free text */}
                  {s.choices && s.choices.length ? (
                    <select
                      id={s.key}
                      value={touched ? draft[s.key] : (s.value || "")}
                      onChange={(e) => setVal(s.key, e.target.value)}
                      style={inputStyle}
                    >
                      {s.choices.map((c) => (
                        <option key={c} value={c}>{c === "" ? "(auto-detect)" : c}</option>
                      ))}
                    </select>
                  ) : showInput ? (
                    <div style={{ display: "flex", gap: 8 }}>
                      <input
                        id={s.key}
                        type={s.secret && !reveal[s.key] ? "password" : "text"}
                        value={touched ? draft[s.key] : (s.secret ? "" : (s.value || ""))}
                        placeholder={s.secret && s.is_set ? "Enter a new value to replace the current one" : s.placeholder}
                        autoComplete="off"
                        spellCheck={false}
                        onChange={(e) => setVal(s.key, e.target.value)}
                        style={{ ...inputStyle, flex: 1, fontFamily: "var(--font-mono, monospace)" }}
                      />
                      {s.secret ? (
                        <button type="button" className="btn-ghost" onClick={() =>
                          setReveal((r) => ({ ...r, [s.key]: !r[s.key] }))} style={smallBtn}>
                          {reveal[s.key] ? "Hide" : "Show"}
                        </button>
                      ) : null}
                      {s.is_set ? (
                        <button type="button" className="btn-ghost" onClick={() => setVal(s.key, "")}
                                style={smallBtn} title="Clear this key on save">
                          Clear
                        </button>
                      ) : null}
                    </div>
                  ) : (
                    <button type="button" onClick={() => setReveal((r) => ({ ...r, [s.key]: true }))}
                            style={{ ...smallBtn, alignSelf: "flex-start" }}>
                      {s.is_set ? "Replace" : "Add"} {s.label.toLowerCase()}
                    </button>
                  )}

                  {touched ? (
                    <button type="button" onClick={() => discardField(s.key)}
                            style={{ ...linkBtn, alignSelf: "flex-start" }}>
                      ↺ discard change
                    </button>
                  ) : null}
                </div>
              );
            })}
          </div>

          {/* LLM connection test lives in the AI group */}
          {group.name === "AI / LLM" ? (
            <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
              <button type="button" onClick={testLlm} disabled={testing} style={smallBtn}>
                {testing ? "Testing…" : "Test LLM connection"}
              </button>
              {llm ? (
                <span style={{ marginLeft: 10, fontSize: 12,
                               color: llm.available ? "var(--ok, #46d39a)" : "var(--crit)" }}>
                  {llm.available ? "✓" : "✗"} {llm.provider ? `${llm.provider}` : "no provider"}
                  {llm.model ? ` (${llm.model})` : ""} — {llm.reason}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      ))}

      {/* Sticky save bar */}
      <div style={{
        position: "sticky", bottom: 0, marginTop: 14, padding: "12px 16px",
        background: "var(--surface-1, rgba(20,22,30,0.92))",
        border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        backdropFilter: "blur(8px)",
      }}>
        <span className="dim" style={{ fontSize: 12 }}>
          {dirtyKeys.length === 0
            ? "No unsaved changes"
            : `${dirtyKeys.length} unsaved change${dirtyKeys.length > 1 ? "s" : ""}`}
        </span>
        <div style={{ display: "flex", gap: 8 }}>
          {dirtyKeys.length > 0 ? (
            <button type="button" className="btn-ghost" onClick={() => { setDraft({}); setReveal({}); }}
                    style={smallBtn}>
              Discard all
            </button>
          ) : null}
          <button type="button" onClick={save} disabled={saving || dirtyKeys.length === 0}
                  style={{ ...primaryBtn, opacity: (saving || dirtyKeys.length === 0) ? 0.5 : 1 }}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

const inputStyle = {
  padding: "9px 12px", background: "rgba(255,255,255,0.02)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  color: "var(--text-0)", fontSize: 13, fontFamily: "var(--font-ui)", outline: "none",
};
const smallBtn = {
  padding: "8px 12px", background: "rgba(255,255,255,0.03)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  color: "var(--text-0)", fontSize: 12, cursor: "pointer", fontFamily: "var(--font-ui)",
};
const primaryBtn = {
  ...smallBtn, background: "var(--brand)", borderColor: "var(--brand)", color: "#0b0b12",
  fontWeight: 600,
};
const linkBtn = {
  background: "none", border: "none", color: "var(--text-2)", fontSize: 11,
  cursor: "pointer", padding: 0, textDecoration: "underline",
};
