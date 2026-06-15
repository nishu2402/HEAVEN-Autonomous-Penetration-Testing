// HEAVEN — guided product tour
//
// A short, skippable walkthrough that orients a first-time operator: what each
// area does and how to explore with sample data. Auto-opens once per browser
// (localStorage gate) and can be re-launched anytime from the command palette
// ("Take the tour") via the `heaven:start-tour` window event.
//
// Uses design tokens throughout, so it renders correctly in light and dark.

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Demo } from "../api";
import { useToast } from "./Toast.jsx";

const SEEN_KEY = "heaven.tour.v1";

const STEPS = [
  { icon: "☠", title: "Welcome to HEAVEN",
    body: "An autonomous pen-testing platform: recon → vulnerability detection → verified exploitation → risk-scored reporting. You can explore everything with sample data — no setup required." },
  { icon: "▣", title: "Dashboard", to: "/",
    body: "Your severity overview and MITRE heat-map, plus a “Fix this first” list that ranks findings by risk and shows a one-line remediation for each." },
  { icon: "⚡", title: "Scans", to: "/scans",
    body: "Launch real scans — targets are validated live and gated behind an authorization confirmation — or click “Run demo scan” to watch the full loop with no target." },
  { icon: "⚠", title: "Findings & Reports", to: "/findings",
    body: "Triage findings with full evidence and a copy-paste curl repro, then export a deliverable in 8 formats (PDF, HTML, SARIF, Burp XML …)." },
  { icon: "⚙", title: "Settings", to: "/settings",
    body: "Add API keys (Gemini / Anthropic / OpenAI, Shodan, NVD, Jira …) anytime — saved to .env and live across the CLI, API and web UI. All optional." },
  { icon: "🩺", title: "System Health", to: "/health",
    body: "See which external tools and keys are active — the browser equivalent of “heaven doctor”. A missing tool just disables one capability; it never breaks the app." },
];

export default function Tour() {
  const [open, setOpen] = useState(false);
  const [i, setI] = useState(0);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  useEffect(() => {
    try { if (!localStorage.getItem(SEEN_KEY)) setOpen(true); } catch { /* no storage */ }
    const onStart = () => { setI(0); setOpen(true); };
    window.addEventListener("heaven:start-tour", onStart);
    return () => window.removeEventListener("heaven:start-tour", onStart);
  }, []);

  function finish() {
    setOpen(false);
    try { localStorage.setItem(SEEN_KEY, "1"); } catch { /* no storage */ }
  }

  async function loadSampleAndExplore() {
    setBusy(true);
    try {
      const r = await Demo.seed();
      toast.success(`Loaded ${r.findings} sample findings — explore away`);
      finish();
      navigate("/");
    } catch (e) {
      toast.error(e.message || "Could not load sample data");
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;
  const step = STEPS[i];
  const last = i === STEPS.length - 1;

  return (
    <div
      onClick={finish}
      style={{
        position: "fixed", inset: 0, zIndex: 9000, display: "flex",
        alignItems: "center", justifyContent: "center", padding: 20,
        background: "rgba(3,5,10,0.62)", backdropFilter: "blur(3px)",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        role="dialog" aria-modal="true" aria-label="HEAVEN product tour"
        style={{
          width: "100%", maxWidth: 460, background: "var(--bg-2)",
          border: "1px solid var(--border-strong)", borderRadius: "var(--radius-lg)",
          boxShadow: "var(--shadow-lg)", padding: "22px 24px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase",
                         color: "var(--text-2)", fontWeight: 600 }}>
            Tour · {i + 1}/{STEPS.length}
          </span>
          <button type="button" onClick={finish} aria-label="Skip tour"
                  style={{ background: "none", border: "none", color: "var(--text-2)",
                           fontSize: 13, cursor: "pointer" }}>
            Skip ✕
          </button>
        </div>

        <div style={{ fontSize: 34, marginTop: 10 }} aria-hidden="true">{step.icon}</div>
        <h2 style={{ color: "var(--text-0)", fontSize: 20, margin: "6px 0 8px" }}>{step.title}</h2>
        <p style={{ color: "var(--text-1)", fontSize: 13.5, lineHeight: 1.6, margin: 0 }}>{step.body}</p>

        {/* progress dots */}
        <div style={{ display: "flex", gap: 6, margin: "18px 0 16px" }}>
          {STEPS.map((_, idx) => (
            <span key={idx} style={{
              width: idx === i ? 18 : 7, height: 7, borderRadius: 99,
              background: idx === i ? "var(--brand)" : "var(--border-strong)",
              transition: "width .2s ease",
            }} />
          ))}
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
          <button type="button" onClick={() => setI((n) => Math.max(0, n - 1))}
                  disabled={i === 0}
                  style={{ ...btn, opacity: i === 0 ? 0.4 : 1 }}>
            ← Back
          </button>
          <div style={{ display: "flex", gap: 8 }}>
            {last ? (
              <>
                <button type="button" onClick={finish} style={btn}>Done</button>
                <button type="button" onClick={loadSampleAndExplore} disabled={busy} style={primary}>
                  {busy ? "Loading…" : "Load sample data →"}
                </button>
              </>
            ) : (
              <button type="button" onClick={() => setI((n) => Math.min(STEPS.length - 1, n + 1))}
                      style={primary}>
                Next →
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

const btn = {
  padding: "8px 14px", background: "transparent", border: "1px solid var(--border-strong)",
  borderRadius: "var(--radius-md)", color: "var(--text-0)", fontSize: 13, cursor: "pointer",
  fontFamily: "var(--font-ui)",
};
const primary = {
  ...btn, background: "var(--brand)", borderColor: "var(--brand)", color: "#06121a", fontWeight: 600,
};
