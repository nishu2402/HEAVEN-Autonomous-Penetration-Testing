// HEAVEN — AI model picker (provider-aware).
//
// Replaces the free-text HEAVEN_LLM_MODEL box on the Settings page. The old box
// meant an operator had to know a model id to type — so "I can't select the
// model." This is a real chooser: a dropdown of the current provider's known
// models (with a one-line note each), a "provider default" option, and a
// "Custom…" escape hatch that reveals a text field for any id. It reacts to the
// provider chosen above it and writes the plain model string into the same
// Settings draft/save pipeline (onChange), so nothing else in the save flow
// changes. Theme-aware via CSS variables; identical in light & dark.

import React, { useEffect, useMemo, useState } from "react";
import { Settings as SettingsApi } from "../api";

const inputStyle = {
  padding: "9px 12px", background: "rgba(255,255,255,0.02)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  color: "var(--text-0)", fontSize: 13, fontFamily: "var(--font-ui)", outline: "none",
};

const CUSTOM = "__custom__";
const DEFAULT_OPT = "__default__";

export default function AIModelPicker({ provider, value, onChange }) {
  const [catalog, setCatalog] = useState(null);
  const prov = (provider || "").toLowerCase();

  useEffect(() => {
    let alive = true;
    SettingsApi.aiModels()
      .then((d) => { if (alive) setCatalog(d); })
      .catch(() => { if (alive) setCatalog({ providers: {} }); });
    return () => { alive = false; };
  }, []);

  const providersMap = catalog?.providers || {};
  const pinfo = providersMap[prov] || null;
  const providerDefault = pinfo?.default || "";
  const activeModel = catalog?.model || "";

  // What to show:
  //  - a chosen cloud provider → its curated model list
  //  - blank / auto-detect     → every provider's models, grouped (so a model is
  //    ALWAYS selectable even before a provider is picked)
  //  - 'local' (or a provider with no curated list) → free-text id
  const grouped = !prov;
  const flatModels = useMemo(() => {
    if (grouped) {
      return _PROVIDER_ORDER.flatMap(
        (p) => (providersMap[p]?.models || []).map((m) => ({ ...m, _p: p })));
    }
    return (pinfo?.models || []).map((m) => ({ ...m, _p: prov }));
  }, [grouped, pinfo, providersMap, prov]);

  const isKnown = useMemo(
    () => !!value && flatModels.some((m) => m.id === value),
    [value, flatModels],
  );
  const [customMode, setCustomMode] = useState(false);
  useEffect(() => {
    // Enter custom mode automatically if the saved value is a custom id.
    if (value && !isKnown && flatModels.length) setCustomMode(true);
  }, [value, isKnown, flatModels.length]);

  // Generic 'local' endpoint has no catalog — always free-text.
  const freeTextOnly = prov === "local" || (!!catalog && !grouped && flatModels.length === 0);

  function selectValue() {
    if (customMode || (value && !isKnown && flatModels.length)) return CUSTOM;
    if (!value) return DEFAULT_OPT;
    return value;
  }

  function onSelect(e) {
    const v = e.target.value;
    if (v === CUSTOM) { setCustomMode(true); return; }
    setCustomMode(false);
    onChange(v === DEFAULT_OPT ? "" : v);
  }

  if (!catalog) {
    return <div className="dim" style={{ fontSize: 12 }}>Loading models…</div>;
  }

  const effective = value || providerDefault || (prov ? "(provider default)" : "auto-detected");
  const groupsToShow = _PROVIDER_ORDER.filter((p) => (providersMap[p]?.models || []).length);

  return (
    <div style={{ display: "grid", gap: 8 }}>
      {freeTextOnly ? (
        <input
          type="text"
          value={value || ""}
          placeholder={prov === "local"
            ? "Your served model id (required for a local endpoint)"
            : "Model id"}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
          style={{ ...inputStyle, fontFamily: "var(--font-mono, monospace)" }}
        />
      ) : (
        <>
          <select value={selectValue()} onChange={onSelect} style={inputStyle}>
            <option value={DEFAULT_OPT}>
              {grouped
                ? "Provider default (auto-detect)"
                : `Provider default${providerDefault ? `, ${providerDefault}` : ""}`}
            </option>
            {grouped
              ? groupsToShow.map((p) => (
                  <optgroup key={p} label={_PROVIDER_LABELS[p] || p}>
                    {providersMap[p].models.map((m) => (
                      <option key={p + m.id} value={m.id}>
                        {m.label || m.id}{m.note ? `, ${m.note}` : ""}
                      </option>
                    ))}
                  </optgroup>
                ))
              : flatModels.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label || m.id}{m.note ? `, ${m.note}` : ""}
                  </option>
                ))}
            <option value={CUSTOM}>Custom model id…</option>
          </select>
          {(customMode || (value && !isKnown)) && (
            <input
              type="text"
              value={value || ""}
              placeholder="Enter any model id (e.g. claude-opus-5 / gpt-4o / a pinned version)"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => onChange(e.target.value)}
              style={{ ...inputStyle, fontFamily: "var(--font-mono, monospace)" }}
            />
          )}
        </>
      )}

      <div className="dim" style={{ fontSize: 11.5, display: "flex", gap: 10, flexWrap: "wrap",
                                    alignItems: "center" }}>
        {grouped && (
          <span>Tip: pick a provider above to narrow the list.</span>
        )}
        <span>Will use: <code style={{ color: "var(--text-1)" }}>{effective}</code></span>
        {activeModel && activeModel !== value && (
          <span>· Active: <code>{activeModel}</code></span>
        )}
        {!freeTextOnly && providerDefault && value && value !== providerDefault && (
          <button type="button" onClick={() => { setCustomMode(false); onChange(""); }}
            style={{ background: "none", border: "none", color: "var(--brand)", cursor: "pointer",
                     fontSize: 11.5, padding: 0, textDecoration: "underline" }}>
            use recommended default
          </button>
        )}
      </div>
    </div>
  );
}

const _PROVIDER_ORDER = ["anthropic", "openai", "gemini", "ollama"];
const _PROVIDER_LABELS = {
  anthropic: "Anthropic (Claude)", openai: "OpenAI (GPT)",
  gemini: "Google Gemini", ollama: "Ollama (local)",
};
