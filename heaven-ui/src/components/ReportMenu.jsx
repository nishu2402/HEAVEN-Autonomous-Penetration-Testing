import React, { useState, useRef, useEffect } from "react";
import { downloadReport } from "../api";
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
  const ref = useRef(null);
  const toast = useToast();

  useEffect(() => {
    function onDoc(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false); }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  async function pick(fmt) {
    setBusy(fmt);
    try {
      const name = await downloadReport(fmt, engagement ? { engagement } : {});
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
        </div>
      )}
    </div>
  );
}
