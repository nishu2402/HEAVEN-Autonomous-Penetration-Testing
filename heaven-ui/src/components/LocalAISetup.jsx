// HEAVEN — Local AI setup wizard (Settings → AI / LLM).
//
// Turns "run `heaven ai setup` in a terminal" into a point-and-click flow: check
// Ollama, pull a model with a live progress bar (streamed over a WebSocket from
// Ollama's native /api/pull), then one click to point HEAVEN at it and live-test.
// The only steps a browser genuinely can't do — installing Ollama or starting a
// stopped server — degrade to a copy-paste one-liner, never a dead end.
//
// Props: { status, onChanged, toast }
//   status    — result of Settings.aiLocalStatus() (installed/reachable/models…)
//   onChanged — async () => refresh status (called after pull / configure)
//   toast     — useToast() handle for success/error notices

import React, { useEffect, useRef, useState } from "react";
import { Settings as SettingsApi, openLocalPullStream } from "../api";

export default function LocalAISetup({ status, onChanged, toast }) {
  const initialTab = status?.provider === "local" ? "local" : "ollama";
  const [tab, setTab] = useState(initialTab);
  const [customModel, setCustomModel] = useState("");
  const [pull, setPull] = useState(null);        // { model, percent, status } while pulling
  const [configuring, setConfiguring] = useState(null); // model id being applied
  const [result, setResult] = useState(null);    // { available, reason, model } after configure
  const [busyRefresh, setBusyRefresh] = useState(false);
  // Generic OpenAI-compatible endpoint form.
  const [baseUrl, setBaseUrl] = useState(status?.provider === "local" ? (status.host || "") : "");
  const [localModel, setLocalModel] = useState("");
  const wsRef = useRef(null);

  // Tear down any live pull socket if the card unmounts mid-download.
  useEffect(() => () => { try { wsRef.current?.close(); } catch { /* noop */ } }, []);

  if (!status) return null;

  const installed = status.installed;
  const reachable = status.reachable;
  const models = status.models || [];
  const recommended = status.recommended || [];
  const defaultModel = status.default_model || "qwen2.5:7b";
  const hasModel = (m) =>
    models.some((x) => x === m || x.split(":")[0] === String(m).split(":")[0]);

  async function refresh() {
    setBusyRefresh(true);
    try { await onChanged?.(); } finally { setBusyRefresh(false); }
  }

  function copy(text) {
    try {
      navigator.clipboard?.writeText(text);
      toast?.success?.("Copied to clipboard");
    } catch { toast?.error?.("Could not copy: select and copy manually"); }
  }

  function startPull(model) {
    const m = String(model || "").trim();
    if (!m) { toast?.error?.("Enter a model to pull"); return; }
    if (pull) return; // one at a time
    setResult(null);
    setPull({ model: m, percent: null, status: "starting…" });
    const ws = openLocalPullStream(m, (frame) => {
      if (frame.type === "progress") {
        setPull({ model: m, percent: frame.percent, status: frame.status || "downloading…" });
      } else if (frame.type === "error") {
        toast?.error?.(frame.error || "Pull failed");
        setPull(null);
        try { wsRef.current?.close(); } catch { /* noop */ }
      } else if (frame.type === "done") {
        setPull(null);
        if (frame.ok) {
          toast?.success?.(`Pulled ${m}`);
          refresh().then(() => useModel(m));
        } else {
          toast?.error?.(`Could not pull ${m}`);
          refresh();
        }
      }
    });
    if (!ws) { toast?.error?.("Not authenticated"); setPull(null); return; }
    wsRef.current = ws;
    ws.onerror = () => { toast?.error?.("Connection to server lost"); setPull(null); };
  }

  async function useModel(model) {
    const m = String(model || "").trim();
    if (!m) return;
    setConfiguring(m);
    setResult(null);
    try {
      const r = await SettingsApi.aiLocalConfigure({ provider: "ollama", model: m });
      setResult({ ...r.test, model: m });
      if (r.test?.available) toast?.success?.(`Local AI is live: ${m}`);
      else toast?.error?.(r.test?.reason || "Saved, but the test call failed");
      await onChanged?.();
    } catch (e) {
      toast?.error?.(e.message || "Could not apply local model");
    } finally {
      setConfiguring(null);
    }
  }

  async function connectLocalEndpoint() {
    const url = baseUrl.trim();
    const m = localModel.trim();
    if (!url) { toast?.error?.("Enter the endpoint base URL (e.g. http://localhost:1234/v1)"); return; }
    if (!m) { toast?.error?.("Enter the served model id"); return; }
    setConfiguring("__local__");
    setResult(null);
    try {
      const r = await SettingsApi.aiLocalConfigure({ provider: "local", base_url: url, model: m });
      setResult({ ...r.test, model: m });
      if (r.test?.available) toast?.success?.(`Connected: ${m}`);
      else toast?.error?.(r.test?.reason || "Saved, but the test call failed");
      await onChanged?.();
    } catch (e) {
      toast?.error?.(e.message || "Could not connect to endpoint");
    } finally {
      setConfiguring(null);
    }
  }

  const installCmds = {
    mac: "brew install ollama",
    linux: "curl -fsSL https://ollama.com/install.sh | sh",
    win: "winget install Ollama.Ollama",
  };

  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <div style={{ fontWeight: 700, fontSize: 14 }}>🖥️ Local AI, no key, no rate limits</div>
        <span style={{ flex: 1 }} />
        <div style={tabRow}>
          <button type="button" onClick={() => setTab("ollama")}
                  style={tab === "ollama" ? tabActive : tabBtn}>Ollama (recommended)</button>
          <button type="button" onClick={() => setTab("local")}
                  style={tab === "local" ? tabActive : tabBtn}>Other endpoint</button>
        </div>
      </div>

      <p style={hint}>
        Run HEAVEN's AI privately on your own machine, findings never leave the box,
        and there are no API keys or rate limits. Set it up right here.
      </p>

      {tab === "ollama" ? (
        <>
          {/* Status pills */}
          <div style={pillRow}>
            <Pill ok={installed} label={installed ? "Ollama installed" : "Ollama not installed"} />
            <Pill ok={reachable} label={reachable ? "server running" : "server not running"} />
            <Pill ok={models.length > 0}
                  label={models.length ? `${models.length} model${models.length > 1 ? "s" : ""} ready` : "no models yet"} />
            <button type="button" onClick={refresh} disabled={busyRefresh} style={ghostBtn}>
              {busyRefresh ? "Checking…" : "↻ Refresh"}
            </button>
          </div>

          {/* Step 1 — install (only if missing) */}
          {!installed ? (
            <Step n={1} title="Install Ollama (one time)">
              <p style={hint}>Ollama is the local model runtime. Install it, then click Refresh.</p>
              <CmdRow label="macOS" cmd={installCmds.mac} onCopy={copy} />
              <CmdRow label="Linux" cmd={installCmds.linux} onCopy={copy} />
              <CmdRow label="Windows" cmd={installCmds.win} onCopy={copy} />
              <a href="https://ollama.com/download" target="_blank" rel="noreferrer" style={link}>
                …or download the installer →
              </a>
            </Step>
          ) : null}

          {/* Step 2 — start server (installed but down) */}
          {installed && !reachable ? (
            <Step n={2} title="Start the Ollama server">
              <p style={hint}>
                Ollama is installed but not running. Open the Ollama app, or run this, then Refresh:
              </p>
              <CmdRow label="" cmd="ollama serve" onCopy={copy} />
            </Step>
          ) : null}

          {/* Step 3 — pick / pull a model */}
          {installed && reachable ? (
            <Step n={installed ? 3 : 2} title="Pick a model">
              <p style={hint}>
                Pull a model once (a few hundred MB, GB). {defaultModel} is the balanced default.
              </p>
              <div style={{ display: "grid", gap: 8 }}>
                {recommended.map((rec) => {
                  const ready = hasModel(rec.model);
                  const isPulling = pull?.model === rec.model;
                  const isDefault = rec.model === defaultModel;
                  return (
                    <div key={rec.model} style={modelRow}>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>
                          {rec.model}{isDefault ? <span style={badge}>default</span> : null}
                          {ready ? <span style={{ ...badge, background: "var(--brand)", color: "#08110d" }}>ready ✓</span> : null}
                        </div>
                        <div style={{ fontSize: 11, color: "var(--text-2)" }}>{rec.tier} · {rec.note}</div>
                      </div>
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        {ready ? (
                          <button type="button" style={primaryBtn} disabled={configuring === rec.model}
                                  onClick={() => useModel(rec.model)}>
                            {configuring === rec.model ? "Applying…" : "Use"}
                          </button>
                        ) : (
                          <button type="button" style={ghostBtn} disabled={!!pull}
                                  onClick={() => startPull(rec.model)}>
                            {isPulling ? "Pulling…" : "Pull"}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Live pull progress */}
              {pull ? (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 12, color: "var(--text-1)", marginBottom: 4 }}>
                    Pulling <b>{pull.model}</b>, {pull.status}
                    {pull.percent != null ? ` · ${pull.percent}%` : ""}
                  </div>
                  <div style={barTrack}>
                    <div style={{
                      ...barFill,
                      width: pull.percent != null ? `${pull.percent}%` : "40%",
                      opacity: pull.percent != null ? 1 : 0.6,
                    }} />
                  </div>
                </div>
              ) : null}

              {/* Custom model */}
              <div style={{ display: "flex", gap: 6, marginTop: 12, flexWrap: "wrap" }}>
                <input value={customModel} onChange={(e) => setCustomModel(e.target.value)}
                       placeholder="or pull another tag, e.g. llama3.1:8b" style={{ ...input, flex: 1, minWidth: 180 }} />
                <button type="button" style={ghostBtn} disabled={!!pull}
                        onClick={() => startPull(customModel)}>Pull</button>
              </div>
            </Step>
          ) : null}

          {result ? <ResultBanner result={result} /> : null}
        </>
      ) : (
        /* ── Generic OpenAI-compatible endpoint (LM Studio / llama.cpp / vLLM) ── */
        <Step n={1} title="Connect an OpenAI-compatible endpoint">
          <p style={hint}>
            Point HEAVEN at any local server that speaks the OpenAI API (LM Studio,
            llama.cpp, vLLM, LocalAI). No key needed unless your server requires one.
          </p>
          <div style={{ display: "grid", gap: 8 }}>
            <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                   placeholder="Base URL: e.g. http://localhost:1234/v1" style={input} />
            <input value={localModel} onChange={(e) => setLocalModel(e.target.value)}
                   placeholder="Served model id: e.g. your-model" style={input} />
            <div>
              <button type="button" style={primaryBtn} disabled={configuring === "__local__"}
                      onClick={connectLocalEndpoint}>
                {configuring === "__local__" ? "Connecting…" : "Connect & test"}
              </button>
            </div>
          </div>
          {result ? <ResultBanner result={result} /> : null}
        </Step>
      )}
    </div>
  );
}

function Pill({ ok, label }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5,
      padding: "3px 9px", borderRadius: 999, border: "1px solid var(--border)",
      color: ok ? "var(--brand)" : "var(--text-2)",
      background: ok ? "rgba(52,229,163,0.08)" : "transparent",
    }}>
      <span>{ok ? "✓" : "○"}</span>{label}
    </span>
  );
}

function Step({ n, title, children }) {
  return (
    <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px dashed var(--border)" }}>
      <div style={{ fontWeight: 600, fontSize: 12.5, marginBottom: 6 }}>
        <span style={{
          display: "inline-flex", width: 18, height: 18, borderRadius: 999, marginRight: 7,
          alignItems: "center", justifyContent: "center", fontSize: 11,
          background: "var(--accent)", color: "#fff",
        }}>{n}</span>{title}
      </div>
      {children}
    </div>
  );
}

function CmdRow({ label, cmd, onCopy }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "4px 0" }}>
      {label ? <span style={{ fontSize: 11, color: "var(--text-2)", width: 58 }}>{label}</span> : null}
      <code style={{
        flex: 1, minWidth: 0, overflowX: "auto", whiteSpace: "nowrap",
        padding: "6px 10px", borderRadius: "var(--radius-sm)", fontSize: 12,
        background: "rgba(0,0,0,0.25)", border: "1px solid var(--border)", color: "var(--text-0)",
      }}>{cmd}</code>
      <button type="button" style={ghostBtn} onClick={() => onCopy(cmd)}>Copy</button>
    </div>
  );
}

function ResultBanner({ result }) {
  const ok = !!result.available;
  return (
    <div style={{
      marginTop: 12, padding: "9px 12px", borderRadius: "var(--radius-md)", fontSize: 12.5,
      border: `1px solid ${ok ? "var(--brand)" : "var(--crit)"}`,
      background: ok ? "rgba(52,229,163,0.08)" : "rgba(255,107,107,0.08)",
      color: ok ? "var(--brand)" : "var(--crit)",
    }}>
      {ok ? "✓ Local AI is live" : "✗ Not ready"}, {result.model ? <b>{result.model}</b> : null}{" "}
      {result.reason ? <span style={{ color: "var(--text-1)" }}>· {result.reason}</span> : null}
    </div>
  );
}

// ── styles ──
const card = {
  marginTop: 12, padding: "14px 16px", borderRadius: "var(--radius-md)",
  background: "var(--bg-2, rgba(255,255,255,0.03))", border: "1px solid var(--border)",
};
const hint = { fontSize: 12, color: "var(--text-1)", margin: "6px 0" };
const pillRow = { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 8 };
const modelRow = {
  display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8,
  padding: "8px 10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
  background: "rgba(255,255,255,0.02)",
};
const badge = {
  marginLeft: 7, fontSize: 10, padding: "1px 6px", borderRadius: 999,
  background: "var(--accent)", color: "#fff", verticalAlign: "middle",
};
const input = {
  padding: "8px 11px", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)",
  borderRadius: "var(--radius-md)", color: "var(--text-0)", fontSize: 12.5,
  fontFamily: "var(--font-ui)", outline: "none",
};
const smallBtn = {
  padding: "7px 12px", borderRadius: "var(--radius-md)", fontSize: 12, cursor: "pointer",
  fontFamily: "var(--font-ui)", border: "1px solid var(--border)",
};
const ghostBtn = { ...smallBtn, background: "rgba(255,255,255,0.04)", color: "var(--text-0)" };
const primaryBtn = { ...smallBtn, background: "var(--brand)", borderColor: "var(--brand)",
  color: "#08110d", fontWeight: 600 };
const tabRow = { display: "flex", gap: 4, background: "rgba(255,255,255,0.03)", padding: 3,
  borderRadius: 999, border: "1px solid var(--border)" };
const tabBtn = { border: "none", background: "transparent", color: "var(--text-2)", fontSize: 11.5,
  padding: "4px 12px", borderRadius: 999, cursor: "pointer", fontFamily: "var(--font-ui)" };
const tabActive = { ...tabBtn, background: "var(--accent)", color: "#fff", fontWeight: 600 };
const barTrack = { height: 8, borderRadius: 999, background: "rgba(255,255,255,0.08)",
  overflow: "hidden", border: "1px solid var(--border)" };
const barFill = { height: "100%", background: "var(--brand-grad, var(--brand))",
  transition: "width 0.3s ease" };
const link = { display: "inline-block", marginTop: 6, fontSize: 11.5, color: "var(--accent)" };
