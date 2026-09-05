// HEAVEN — AI model picker (provider-aware, dynamic).
//
// Replaces the free-text HEAVEN_LLM_MODEL box on the Settings page. The old box
// meant an operator had to know a model id to type — so "I can't select the
// model." This is a real chooser: a dropdown of the provider's models (with a
// one-line note each), a "provider default" option, and a "Custom…" escape hatch
// that reveals a text field for any id.
//
// The list is DYNAMIC, not static. The backend discovers each provider's models
// live from its own API (every current Claude / GPT / Gemini / DeepSeek model,
// and every locally-pulled Ollama tag) and merges them with a curated,
// recommended short-list. With no key yet it falls back to a broader offline
// catalog (still comprehensive, not just a few basics). A "Refresh" button
// re-queries on demand, and the footer shows the source: live, catalog, or curated.
//
// It reacts to the provider chosen above it and writes the plain model string
// into the same Settings draft/save pipeline (onChange), so nothing else in the
// save flow changes. Theme-aware via CSS variables; identical in light & dark.

import React, { useEffect, useMemo, useState } from "react";
import { Settings as SettingsApi } from "../api";

// Use backgroundColor (not the `background` shorthand): a bare <select> now gets
// appearance:none + a custom chevron via background-image from index.css, and a
// `background` shorthand here would reset that image and leave the arrow gone.
const inputStyle = {
  padding: "9px 12px", backgroundColor: "var(--bg-1)",
  border: "1px solid var(--border)", borderRadius: "var(--radius-md)",
  color: "var(--text-0)", fontSize: 13, fontFamily: "var(--font-ui)", outline: "none",
};

const linkBtnStyle = {
  background: "none", border: "none", color: "var(--brand)", cursor: "pointer",
  fontSize: 11.5, padding: 0, textDecoration: "underline",
};

const CUSTOM = "__custom__";
const DEFAULT_OPT = "__default__";

// A recommended model is prefixed so the operator can spot the curated pick among
// a long live roster; the note is appended after a comma.
const optLabel = (m) =>
  `${m.recommended ? "★ " : ""}${m.label || m.id}${m.note ? `, ${m.note}` : ""}`;

export default function AIModelPicker({ provider, value, onChange }) {
  const [catalog, setCatalog] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const prov = (provider || "").toLowerCase();

  useEffect(() => {
    let alive = true;
    SettingsApi.aiModels()
      .then((d) => { if (alive) setCatalog(d); })
      .catch(() => { if (alive) setCatalog({ providers: {} }); });
    return () => { alive = false; };
  }, []);

  // Re-query every provider's live roster, bypassing the server's short cache.
  function refresh() {
    setRefreshing(true);
    SettingsApi.aiModels(true)
      .then((d) => { if (d) setCatalog(d); })
      .catch(() => { /* keep the last-good catalog on a failed refresh */ })
      .finally(() => setRefreshing(false));
  }

  const providersMap = catalog?.providers || {};
  const pinfo = providersMap[prov] || null;
  const providerDefault = pinfo?.default || "";
  const activeModel = catalog?.model || "";

  // Provider order for the grouped view: the curated order first, then any extra
  // provider the backend returned that we don't hard-code (so a new provider is
  // never silently dropped).
  const orderedProviders = useMemo(() => [
    ..._PROVIDER_ORDER,
    ...Object.keys(providersMap).filter((p) => !_PROVIDER_ORDER.includes(p)),
  ], [providersMap]);

  // What to show:
  //  - a chosen cloud provider → its (live + curated) model list
  //  - blank / auto-detect     → every provider's models, grouped (so a model is
  //    ALWAYS selectable even before a provider is picked)
  //  - 'local' (or a provider with no models at all) → free-text id
  const grouped = !prov;
  const flatModels = useMemo(() => {
    if (grouped) {
      return orderedProviders.flatMap(
        (p) => (providersMap[p]?.models || []).map((m) => ({ ...m, _p: p })));
    }
    return (pinfo?.models || []).map((m) => ({ ...m, _p: prov }));
  }, [grouped, pinfo, providersMap, prov, orderedProviders]);

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
  const groupsToShow = orderedProviders.filter((p) => (providersMap[p]?.models || []).length);

  // Count + provenance for the footer: how many models are on offer for the
  // current scope, and whether they were discovered live or are the curated set.
  const shownCount = grouped
    ? groupsToShow.reduce((n, p) => n + (providersMap[p]?.models?.length || 0), 0)
    : (pinfo?.models?.length || 0);
  const source = grouped ? null : pinfo?.source;
  const liveCount = grouped ? 0 : (pinfo?.live_count || 0);

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
          <select value={selectValue()} onChange={onSelect} style={{ ...inputStyle, paddingRight: 34, cursor: "pointer" }}>
            <option value={DEFAULT_OPT}>
              {grouped
                ? "Provider default (auto-detect)"
                : `Provider default${providerDefault ? `, ${providerDefault}` : ""}`}
            </option>
            {grouped
              ? groupsToShow.map((p) => (
                  <optgroup key={p} label={_PROVIDER_LABELS[p] || p}>
                    {providersMap[p].models.map((m) => (
                      <option key={p + m.id} value={m.id}>{optLabel(m)}</option>
                    ))}
                  </optgroup>
                ))
              : flatModels.map((m) => (
                  <option key={m.id} value={m.id}>{optLabel(m)}</option>
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
        {!freeTextOnly && (
          <span>
            {shownCount} model{shownCount === 1 ? "" : "s"}
            {source === "live"
              ? ` · live (${liveCount})`
              : source === "catalog" ? " · catalog"
              : source === "curated" ? " · curated" : ""}
          </span>
        )}
        {source === "catalog" && !grouped && (
          <span>Add this provider's API key above for its live roster.</span>
        )}
        <span>Will use: <code style={{ color: "var(--text-1)" }}>{effective}</code></span>
        {activeModel && activeModel !== value && (
          <span>· Active: <code>{activeModel}</code></span>
        )}
        <button type="button" onClick={refresh} disabled={refreshing} style={linkBtnStyle}>
          {refreshing ? "Refreshing…" : "Refresh models"}
        </button>
        {!freeTextOnly && providerDefault && value && value !== providerDefault && (
          <button type="button" onClick={() => { setCustomMode(false); onChange(""); }}
            style={linkBtnStyle}>
            use recommended default
          </button>
        )}
      </div>
    </div>
  );
}

const _PROVIDER_ORDER = ["anthropic", "openai", "gemini", "deepseek", "ollama"];
const _PROVIDER_LABELS = {
  anthropic: "Anthropic (Claude)", openai: "OpenAI (GPT)",
  gemini: "Google Gemini", deepseek: "DeepSeek", ollama: "Ollama (local)",
  local: "Local (OpenAI-compatible)",
};
