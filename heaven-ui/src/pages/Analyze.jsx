// HEAVEN — Offline Artifact Analysis (pcap / binary / firmware / apk / image / hashes)
// Wraps POST /api/analyze/run (base64 file), /api/analyze/decode (string), and
// /api/analyze/report (downloadable Markdown/HTML/JSON report).

import React, { useState } from "react";
import { useSearchParams } from "react-router";
import { Analyze, getUser } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

const KINDS = ["", "binary", "firmware", "pcap", "stego", "apk", "ipa",
  "document", "archive", "crypto"];
// Client-side guard. The file streams to the server as multipart (no base64 in
// memory), so this can be generous; the server is the real authority and its cap
// is HEAVEN_ANALYZE_MAX_MB (default 512 MB).
const MAX_MB = 512;
const MAX_BYTES = MAX_MB * 1024 * 1024;

// Friendly section titles mirroring the server-side report renderer.
const SECTION_TITLES = {
  protocol_breakdown: "Protocol breakdown",
  application_protocols: "Application protocols",
  top_talkers: "Top talkers",
  conversations: "Conversations (top by bytes)",
  dns_queries: "DNS queries",
  dns_answers: "DNS answers",
  tls_sessions: "TLS sessions",
  http_transactions: "HTTP transactions",
  cleartext_credentials: "Cleartext credentials",
  ntlm_hashes: "Captured NTLM hashes",
  snmp_communities: "SNMP community strings",
  arp_table: "ARP table",
  cleartext_protocols: "Cleartext protocols",
  payload_secrets: "Secrets seen on the wire",
  suspicious_user_agents: "Suspicious user-agents",
  software_versions: "Software / version inventory",
  embedded_accounts: "Embedded accounts",
  interesting_strings: "Strings of interest",
  imports_flagged: "Dangerous imports",
  dangerous_permissions: "Dangerous permissions",
  native_libraries: "Native libraries (ABIs)",
  png_text_chunks: "PNG text chunks",
  jpeg_comments: "JPEG comments",
  lsb_statistics: "LSB statistics",
  secrets: "Embedded secrets",
  carved: "Carved objects",
  permissions: "Permissions",
  image: "Image metadata",
  // Shared per-file enrichment
  file_overview: "File overview (hashes · entropy · type)",
  // Documents (PDF / OOXML / OLE / RTF)
  active_content: "Active content markers",
  javascript_snippets: "JavaScript snippets",
  embedded_files: "Embedded files",
  embedded_secrets: "Embedded secrets",
  uris: "URLs referenced",
  metadata: "Document metadata",
  document_metadata: "Document metadata",
  macros: "VBA macros",
  vba_modules: "VBA modules",
  macro_keywords: "Suspicious macro calls",
  macro_source_excerpt: "Macro source (excerpt)",
  external_relationships: "External relationships",
  dde_fields: "DDE fields",
  embedded_objects: "Embedded OLE objects",
  object_classes: "OLE object classes",
  remote_templates: "Remote templates",
  streams: "Compound-file streams",
  // Archives
  executables: "Executable / script members",
  unsafe_paths: "Path-traversal members",
  links: "Symbolic / hard links",
  inner_type: "Inner content type",
  compression_ratio: "Compression ratio",
};
const titleFor = (k) =>
  SECTION_TITLES[k] || k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());

// Decode a base64 string to a Uint8Array (for binary downloads like PDF).
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

// Trigger a browser download. `content` is a string for text reports, or a
// base64 string when `encoding === "base64"` (binary formats such as PDF).
function triggerDownload(content, filename, mimetype, encoding) {
  const payload =
    encoding === "base64" ? base64ToBytes(content) : content;
  const blob = new Blob([payload], { type: mimetype || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function AnalyzePage() {
  const [searchParams] = useSearchParams();
  const [file, setFile] = useState(null);
  const requestedKind = searchParams.get("kind");
  const [kind, setKind] = useState(KINDS.includes(requestedKind) ? requestedKind : "");
  const [decodeText, setDecodeText] = useState("");
  const { loading, result, error, start, clear } = useJob("analyze");
  const [formError, setFormError] = useState(null);
  const user = getUser();
  const isAdmin = user?.role === "admin";

  async function runFile() {
    setFormError(null);
    if (!file) {
      setFormError("Choose a file to analyze.");
      return;
    }
    if (file.size > MAX_BYTES) {
      setFormError(`File too large (limit ${MAX_MB} MB).`);
      return;
    }
    start(
      { label: `Analyze · ${file.name}`, kind: "analyze", path: "/analyze" },
      () => Analyze.runUpload(file, kind),
    );
  }

  function runDecode() {
    setFormError(null);
    if (!decodeText.trim()) {
      setFormError("Enter a string to decode.");
      return;
    }
    start(
      { label: "Analyze · decode", kind: "analyze", path: "/analyze" },
      () => Analyze.decode(decodeText.trim()),
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ marginTop: 0 }}>🔎 Offline Artifact Analysis</h2>
        <p className="page-lead">
          Analyze a file you are authorized to examine: a packet capture,
          firmware image, binary, mobile app (Android APK or iOS IPA), office
          document (PDF, Word, Excel, PowerPoint, RTF), archive (zip, tar, gz,
          7z), image (steganography), or hash file. Get real, detailed
          findings with no live target. Every file is fingerprinted (SHA-256,
          entropy, YARA) and analyzed in a private temp path, then deleted;
          nothing is persisted.
        </p>

        {isAdmin ? (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14 }}>
              <label className="form-group">
                <span className="form-label">Artifact file</span>
                <input className="form-input" type="file"
                       onChange={(e) => setFile(e.target.files?.[0] || null)} />
              </label>
              <label className="form-group">
                <span className="form-label">Type (auto-detect if blank)</span>
                <select className="form-input" value={kind}
                        onChange={(e) => setKind(e.target.value)}>
                  {KINDS.map((k) => (
                    <option key={k} value={k}>{k || "auto-detect"}</option>
                  ))}
                </select>
              </label>
            </div>
            <button className="btn" disabled={loading || !file} onClick={runFile}>
              {loading ? "Analyzing…" : "Analyze file"}
            </button>
          </>
        ) : (
          <div className="dim" style={{ fontSize: 13, marginBottom: 8 }}>
            File analysis is admin-only. The string decoder below is available to you.
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">Quick decoder</div>
        <p className="dim" style={{ fontSize: 12, marginTop: 0, marginBottom: 12 }}>
          Auto-decodes across base64/base64url/base32/hex/ascii85, URL &amp; HTML
          entities, gzip/zlib/bzip2, ROT13/ROT47, binary/decimal, Morse and JWT,
          unwrapping nested layers and identifying the result.
        </p>
        <label className="form-group">
          <textarea className="form-input mono-input" rows={3} value={decodeText}
                    placeholder="YWRtaW46c2VjcmV0"
                    onChange={(e) => setDecodeText(e.target.value)} />
        </label>
        <button className="btn-small" disabled={loading} onClick={runDecode}>Decode</button>
      </div>

      {(formError || error) && (
        <div className="error" style={{ marginTop: 12 }}>{formError || error}</div>
      )}
      {loading && <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>}
      {result && <AnalyzeResult result={result} onClear={clear} />}
    </div>
  );
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function AnalyzeResult({ result, onClear }) {
  const [dl, setDl] = useState(null);
  const [dlError, setDlError] = useState(null);
  const findings = [...(result.findings || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5),
  );
  const report = result.report || {};
  const decodings = report.decodings || [];
  const jwt = report.jwt || null;

  const counts = {};
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  async function download(fmt) {
    setDl(fmt);
    setDlError(null);
    try {
      if (fmt === "json") {
        const name = `heaven-${result.detected_kind || result.kind || "artifact"}.json`;
        triggerDownload(JSON.stringify(result, null, 2), name, "application/json");
      } else {
        const r = await Analyze.report(result, fmt);
        triggerDownload(r.content, r.filename, r.mimetype, r.encoding);
      }
    } catch (e) {
      // PDF is binary and has no client-side fallback; surface the real error.
      if (fmt === "pdf") {
        setDlError(e?.message || "PDF export failed");
      } else {
        // Fall back to a client-side JSON download if the endpoint is unavailable.
        const name = `heaven-${result.detected_kind || result.kind || "artifact"}.json`;
        triggerDownload(JSON.stringify(result, null, 2), name, "application/json");
      }
    } finally {
      setDl(null);
    }
  }

  const isDecodeOnly = decodings.length > 0 || jwt;

  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
          <span>
            Result
            {result.detected_kind ? <span className="dim"> · {result.detected_kind}</span> : null}
            {result.filename ? <span className="dim"> · {result.filename}</span> : null}
          </span>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {!isDecodeOnly && (
              <>
                <span className="dim" style={{ fontSize: 11 }}>Download:</span>
                <button className="btn-small" disabled={dl} onClick={() => download("pdf")}>
                  {dl === "pdf" ? "…" : "PDF"}
                </button>
                <button className="btn-small" disabled={dl} onClick={() => download("html")}>
                  {dl === "html" ? "…" : "HTML"}
                </button>
                <button className="btn-small" disabled={dl} onClick={() => download("md")}>
                  {dl === "md" ? "…" : "Markdown"}
                </button>
                <button className="btn-small" disabled={dl} onClick={() => download("json")}>
                  {dl === "json" ? "…" : "JSON"}
                </button>
              </>
            )}
            <button className="btn-small" onClick={onClear}>Clear</button>
          </div>
        </div>
        {dlError && (
          <div className="error" style={{ marginTop: 6, fontSize: 12 }}>{dlError}</div>
        )}
        {result.summary && <div className="dim" style={{ fontSize: 13 }}>{result.summary}</div>}
        {Object.keys(counts).length > 0 && (
          <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
            {["critical", "high", "medium", "low", "info"].filter((s) => counts[s]).map((s) => (
              <span key={s} className={"sev-pill sev-" + s}>{counts[s]} {s}</span>
            ))}
          </div>
        )}

        {result.error && <div className="error" style={{ marginTop: 8 }}>{result.error}</div>}

        {jwt && <JwtView jwt={jwt} />}

        {decodings.length > 0 && <Decodings decodings={decodings} best={report.best} />}

        {findings.length > 0 ? (
          <div style={{ marginTop: 10 }}>
            {findings.map((f, i) => <Finding key={i} f={f} />)}
          </div>
        ) : (
          !isDecodeOnly && !result.error && (
            <div style={{ marginTop: 8, color: "var(--ok)" }}>
              No security findings. The full artifact breakdown is below.
            </div>
          )
        )}
      </div>

      {!isDecodeOnly && <ReportSections report={report} />}

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

function Finding({ f }) {
  const [open, setOpen] = useState(false);
  const meta = [];
  if (f.cwe) meta.push(f.cwe);
  if (f.confidence != null) meta.push(`confidence ${Math.round(f.confidence * 100)}%`);
  if (f.owasp_mobile) meta.push(f.owasp_mobile);
  return (
    <div style={{ padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
      <span className={"sev-pill sev-" + (f.severity || "info")}>{f.severity}</span>{" "}
      <strong style={{ fontSize: 13 }}>{f.title}</strong>
      {meta.length > 0 && (
        <span className="dim" style={{ fontSize: 11 }}> · {meta.join(" · ")}</span>
      )}
      {f.description && (
        <div className="dim" style={{ fontSize: 12, marginTop: 2 }}>{f.description}</div>
      )}
      {f.remediation && (
        <div style={{ fontSize: 12, marginTop: 3, color: "var(--accent, #7ee787)" }}>
          Remediation: {f.remediation}
        </div>
      )}
      {f.evidence && (
        <div style={{ marginTop: 4 }}>
          <button
            onClick={() => setOpen(!open)}
            style={{ fontSize: 11, background: "none", border: "none", padding: 0,
                     color: "var(--brand)", cursor: "pointer", textDecoration: "underline" }}>
            {open ? "Hide evidence" : "Show evidence"}
          </button>
          {open && (
            <pre className="cli-block" style={{ fontSize: 11, marginTop: 4 }}>
              {JSON.stringify(f.evidence, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function JwtView({ jwt }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div className="card-title" style={{ fontSize: 13 }}>
        JWT decoded {jwt.alg ? <span className="dim">· alg: {jwt.alg}</span> : null}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginTop: 6 }}>
        <div>
          <div className="dim" style={{ fontSize: 11 }}>Header</div>
          <pre className="cli-block" style={{ fontSize: 11 }}>{JSON.stringify(jwt.header, null, 2)}</pre>
        </div>
        <div>
          <div className="dim" style={{ fontSize: 11 }}>Payload</div>
          <pre className="cli-block" style={{ fontSize: 11 }}>{JSON.stringify(jwt.payload, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}

function Decodings({ decodings, best }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div className="card-title" style={{ fontSize: 13 }}>
        Decodings
        {best ? <span className="dim"> · best: {best.scheme} ({Math.round(best.confidence * 100)}%)</span> : null}
      </div>
      <table className="data-table" style={{ fontSize: 12, marginTop: 6 }}>
        <thead>
          <tr><th>Scheme</th><th>Confidence</th><th>Decoded</th><th>Type</th></tr>
        </thead>
        <tbody>
          {decodings.map((d, i) => (
            <tr key={i}>
              <td className="mono">
                {d.scheme}
                {d.chain && (
                  <div className="dim" style={{ fontSize: 10 }}>
                    chain: {d.chain.map((c) => c.scheme).join(" → ")}
                  </div>
                )}
              </td>
              <td>{d.confidence != null ? Math.round(d.confidence * 100) + "%" : "—"}</td>
              <td className="mono" style={{ wordBreak: "break-word", maxWidth: 420 }}>{d.decoded}</td>
              <td className="dim">{d.identified_type || ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReportSections({ report }) {
  const entries = Object.entries(report).filter(([k, v]) => {
    if (["input", "decodings", "jwt", "best"].includes(k)) return false;
    if (v == null || v === "") return false;
    if (Array.isArray(v) && v.length === 0) return false;
    if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0) return false;
    return true;
  });
  if (!entries.length) return null;
  // Show larger/structured sections first, scalars last.
  const scalars = entries.filter(([, v]) => typeof v !== "object");
  const structured = entries.filter(([, v]) => typeof v === "object");
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="card-title">Detailed report</div>
      {scalars.length > 0 && (
        <table className="data-table" style={{ fontSize: 12, marginBottom: 8 }}>
          <tbody>
            {scalars.map(([k, v]) => (
              <tr key={k}><td className="dim" style={{ width: 200 }}>{titleFor(k)}</td>
                <td className="mono">{String(v)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {structured.map(([k, v]) => <Section key={k} title={titleFor(k)} value={v} />)}
    </div>
  );
}

function Section({ title, value }) {
  const isArrObjs = Array.isArray(value) && value.length > 0 && value.every((x) => x && typeof x === "object" && !Array.isArray(x));
  const isArrScalars = Array.isArray(value) && !isArrObjs;
  const isObj = !Array.isArray(value) && typeof value === "object";
  const big = (Array.isArray(value) ? value.length : Object.keys(value).length) > 8;
  return (
    <details open={!big} style={{ marginTop: 8 }}>
      <summary style={{ cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
        {title} <span className="dim" style={{ fontWeight: 400 }}>
          ({Array.isArray(value) ? value.length : Object.keys(value).length})
        </span>
      </summary>
      {isArrObjs && <ObjTable rows={value} />}
      {isArrScalars && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
          {value.slice(0, 200).map((x, i) => (
            <span key={i} className="mono" style={{ fontSize: 11, background: "var(--surface-1, rgba(127,127,127,.12))", padding: "2px 6px", borderRadius: 4 }}>
              {typeof x === "object" ? JSON.stringify(x) : String(x)}
            </span>
          ))}
        </div>
      )}
      {isObj && (
        <table className="data-table" style={{ fontSize: 12, marginTop: 6 }}>
          <tbody>
            {Object.entries(value).slice(0, 200).map(([k, v]) => (
              <tr key={k}><td className="dim" style={{ width: 200 }}>{k}</td>
                <td className="mono" style={{ wordBreak: "break-word" }}>
                  {typeof v === "object" ? JSON.stringify(v) : String(v)}
                </td></tr>
            ))}
          </tbody>
        </table>
      )}
    </details>
  );
}

function ObjTable({ rows }) {
  const cols = [];
  rows.slice(0, 200).forEach((r) => Object.keys(r).forEach((k) => {
    if (!cols.includes(k) && !k.startsWith("_")) cols.push(k);
  }));
  const shown = cols.slice(0, 9);
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="data-table" style={{ fontSize: 11.5, marginTop: 6 }}>
        <thead><tr>{shown.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>
          {rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              {shown.map((c) => (
                <td key={c} className="mono" style={{ wordBreak: "break-word", maxWidth: 320 }}>
                  {r[c] == null ? "" : typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 200 && <div className="dim" style={{ fontSize: 11 }}>…and {rows.length - 200} more</div>}
    </div>
  );
}
