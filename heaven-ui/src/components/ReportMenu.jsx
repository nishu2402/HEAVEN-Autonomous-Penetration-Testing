import React, { useState, useRef, useEffect } from "react";
import { downloadReport, Compliance } from "../api";
import { useToast } from "./Toast.jsx";

// Every standard a pentest deliverable might be asked for.
const FORMATS = [
  { id: "pdf", label: "PDF report", hint: "Client deliverable" },
  { id: "html", label: "HTML report", hint: "Compliance-mapped, shareable" },
  { id: "markdown", label: "Markdown", hint: "Wiki / Git" },
  { id: "csv", label: "CSV", hint: "Spreadsheet / triage" },
  { id: "json", label: "JSON", hint: "Automation / re-import" },
  { id: "sarif", label: "SARIF", hint: "GitHub code scanning" },
  { id: "burp", label: "Burp XML", hint: "Burp Suite import" },
  { id: "proxy-jsonl", label: "Proxy JSONL", hint: "Replay / pipelines" },
];

export default function ReportMenu({ engagement }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState("");
  const [frameworks, setFrameworks] = useState([]);
  const [fw, setFw] = useState("hipaa");
  const ref = useRef(null);
  const toast = useToast();

  useEffect(() => {
    function onDoc(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Load the compliance frameworks once the menu is first opened.
  useEffect(() => {
    if (!open || frameworks.length) return;
    Compliance.frameworks()
      .then((r) => {
        const list = r?.frameworks || [];
        setFrameworks(list);
        if (list.length) setFw((c) => (list.some((f) => f.id === c) ? c : list[0].id));
      })
      .catch(() => { /* compliance picker is optional */ });
  }, [open, frameworks.length]);

  async function pick(fmt, extra = {}) {
    const tag = extra.framework ? `compliance-${fmt}` : fmt;
    setBusy(tag);
    try {
      const name = await downloadReport(fmt, { ...(engagement ? { engagement } : {}), ...extra });
      toast.success(`Downloaded ${name}`);
      setOpen(false);
    } catch (e) {
      toast.error(e.message || "Export failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div style={{ position: "relative" }} ref={ref}>
      <button className="btn btn-primary" onClick={() => setOpen((v) => !v)}>
        ↓ Download report
      </button>
      {open && (
        <div
          className="card-glass"
          style={{
            position: "absolute", right: 0, top: "calc(100% + 8px)", zIndex: 50,
            width: 290, padding: 8, borderRadius: "var(--radius-lg)",
            boxShadow: "var(--shadow-lg)",
          }}
        >
          <div style={{ padding: "6px 10px", fontSize: 10.5, letterSpacing: "0.1em",
                        textTransform: "uppercase", color: "var(--text-2)", fontWeight: 600 }}>
            Export format
          </div>
          {FORMATS.map((f) => (
            <button
              key={f.id}
              onClick={() => pick(f.id)}
              disabled={!!busy}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                width: "100%", textAlign: "left", gap: 10, padding: "9px 10px",
                background: "none", border: "none", borderRadius: "var(--radius-sm)",
                color: "var(--text-0)", cursor: busy ? "wait" : "pointer", fontFamily: "var(--font-ui)",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(109,124,255,0.12)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "none")}
            >
              <span>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{f.label}</div>
                <div style={{ fontSize: 11, color: "var(--text-2)" }}>{f.hint}</div>
              </span>
              <span style={{ fontSize: 11, color: "var(--text-2)" }}>
                {busy === f.id ? "…" : f.id}
              </span>
            </button>
          ))}

          {/* Compliance-mapped report — pick a framework, download HTML/PDF. */}
          {frameworks.length > 0 && (
            <div style={{ borderTop: "1px solid var(--border)", marginTop: 6, paddingTop: 8 }}>
              <div style={{ padding: "0 10px 6px", fontSize: 10.5, letterSpacing: "0.1em",
                            textTransform: "uppercase", color: "var(--text-2)", fontWeight: 600 }}>
                Compliance mapping
              </div>
              <select value={fw} onChange={(e) => setFw(e.target.value)}
                className="form-select"
                style={{ width: "calc(100% - 20px)", margin: "0 10px 8px", fontSize: 12 }}>
                {frameworks.map((f) => (
                  <option key={f.id} value={f.id}>{f.title}</option>
                ))}
              </select>
              <div style={{ display: "flex", gap: 6, padding: "0 10px 4px" }}>
                {["html", "pdf"].map((f) => (
                  <button key={f} onClick={() => pick(f, { framework: fw })} disabled={!!busy}
                    style={{
                      flex: 1, padding: "8px 10px", fontSize: 12, fontWeight: 600,
                      background: "rgba(109,124,255,0.10)", color: "var(--text-0)",
                      border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
                      cursor: busy ? "wait" : "pointer", fontFamily: "var(--font-ui)",
                    }}>
                    {busy === `compliance-${f}` ? "…" : `⬇ ${f.toUpperCase()}`}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
