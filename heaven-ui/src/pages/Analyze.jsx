// HEAVEN — Offline Artifact Analysis (pcap / binary / firmware / apk / image / hashes)
// Wraps POST /api/analyze/run (base64 file) and /api/analyze/decode (string).

import React, { useState } from "react";
import { useSearchParams } from "react-router";
import { Analyze, getUser } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

const KINDS = ["", "binary", "firmware", "pcap", "stego", "apk", "ipa", "crypto"];
const MAX_BYTES = 40 * 1024 * 1024;

// Encode file bytes to base64 in chunks (avoids a call-stack overflow on large
// Uint8Arrays passed to String.fromCharCode).
function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export default function AnalyzePage() {
  const [searchParams] = useSearchParams();
  const [file, setFile] = useState(null);
  // A ?kind= query param (from a launcher tile, e.g. the Mobile tool) preselects
  // the artifact type; anything unrecognized falls back to auto-detect.
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
      setFormError("File too large (limit 40 MB).");
      return;
    }
    const buf = await file.arrayBuffer();
    const content_b64 = bytesToBase64(new Uint8Array(buf));
    start(
      { label: `Analyze · ${file.name}`, kind: "analyze", path: "/analyze" },
      () => Analyze.run({ filename: file.name, content_b64, kind }),
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
          Analyze a file you are authorized to examine, a packet capture,
          firmware image, binary, mobile app (Android APK or iOS IPA), image
          (steganography), or hash file, and get real findings, no live target
          needed. Files are analyzed in a private temp path and deleted; nothing
          is persisted.
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
        <p className="dim" style={{ fontSize: 12, marginTop: 0 }}>
          Decode a base64 / hex / base32 / rot13 string.
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

function AnalyzeResult({ result, onClear }) {
  const findings = result.findings || [];
  const decodings = result.report?.decodings || [];

  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title" style={{ display: "flex", justifyContent: "space-between" }}>
          <span>
            Result
            {result.detected_kind ? <span className="dim"> · {result.detected_kind}</span> : null}
            {result.filename ? <span className="dim"> · {result.filename}</span> : null}
          </span>
          <button className="btn-small" onClick={onClear}>Clear</button>
        </div>
        {result.summary && <div className="dim" style={{ fontSize: 13 }}>{result.summary}</div>}

        {decodings.length > 0 && (
          <table className="data-table" style={{ fontSize: 12, marginTop: 8 }}>
            <thead><tr><th>Scheme</th><th>Decoded</th></tr></thead>
            <tbody>
              {decodings.map((d, i) => (
                <tr key={i}><td>{d.scheme}</td><td className="mono">{d.decoded}</td></tr>
              ))}
            </tbody>
          </table>
        )}

        {findings.length > 0 ? (
          <div style={{ marginTop: 8 }}>
            {findings.map((f, i) => (
              <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                <span className={"sev-pill sev-" + (f.severity || "info")}>
                  {f.severity}
                </span>{" "}
                <strong style={{ fontSize: 13 }}>{f.title}</strong>
                {f.description && (
                  <div className="dim" style={{ fontSize: 12 }}>{f.description}</div>
                )}
              </div>
            ))}
          </div>
        ) : (
          decodings.length === 0 && (
            <div style={{ marginTop: 8, color: "var(--ok)" }}>No findings.</div>
          )
        )}
      </div>

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
