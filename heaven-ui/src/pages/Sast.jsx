// HEAVEN — SAST (Semgrep) launcher + results viewer
// Mirrors `heaven sast scan` from the CLI.

import React, { useEffect, useState } from "react";
import { SAST, Engagement } from "../api";

const SEV_COLOR = {
  critical: "#FF073A", high: "#FF6F00", medium: "#FFB800",
  low: "#00D4FF", info: "#888",
};

export default function SastPage() {
  const [path, setPath] = useState("");
  const [engagement, setEngagement] = useState("");
  const [extraConfigs, setExtraConfigs] = useState("");
  const [noBuiltin, setNoBuiltin] = useState(false);
  const [timeout, setTimeoutS] = useState(300);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState(null);

  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
    SAST.rules().then(setRules).catch(() => setRules(null));
  }, []);

  async function run() {
    setError(null);
    setResult(null);
    if (!path.trim()) {
      setError("Source path is required.");
      return;
    }
    if (rules && rules.semgrep_installed === false) {
      setError("Semgrep is not installed on the server. Run: pip install semgrep");
      return;
    }
    const body = {
      path: path.trim(),
      engagement: engagement || undefined,
      extra_configs: extraConfigs.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
      no_builtin: noBuiltin,
      timeout,
    };
    setLoading(true);
    try {
      const r = await SAST.scan(body);
      setResult(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#7B2FBE", marginTop: 0 }}>🔬 SAST (Semgrep)</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Static source-code analysis. Uses HEAVEN's curated rule pack
          (Python/JS/Go) + any extra Semgrep registry packs you list.
          Findings land in the engagement DB alongside DAST findings so
          one report shows source + runtime side.
        </p>

        {rules && rules.semgrep_installed === false && (
          <div className="error" style={{ marginBottom: 12 }}>
            Semgrep is not installed on the server.
            Run <code>pip install semgrep</code> and restart the API.
          </div>
        )}

        <label className="form-label">Source path (on server)</label>
        <input type="text" value={path} onChange={(e) => setPath(e.target.value)}
               placeholder="/path/to/source-code"
               style={{ width: "100%", fontSize: 12, marginBottom: 10 }} />

        <label className="form-label">Engagement (optional, persists findings)</label>
        <input type="text" value={engagement} onChange={(e) => setEngagement(e.target.value)}
               placeholder="active engagement name"
               style={{ width: "100%", fontSize: 12, marginBottom: 10 }} />

        <label className="form-label">Extra Semgrep configs (one per line or comma-sep)</label>
        <textarea rows={3} value={extraConfigs}
                  onChange={(e) => setExtraConfigs(e.target.value)}
                  placeholder={"p/owasp-top-ten\np/python\np/javascript"}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }} />

        <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 10, marginBottom: 12 }}>
          <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <input type="checkbox" checked={noBuiltin}
                   onChange={(e) => setNoBuiltin(e.target.checked)} />
            Skip HEAVEN built-in rules
          </label>
          <label style={{ fontSize: 12 }}>
            Timeout (s)
            <input type="number" value={timeout} min={30} max={1800}
                   onChange={(e) => setTimeoutS(parseInt(e.target.value, 10))}
                   style={{ width: 80, marginLeft: 6, fontSize: 12 }} />
          </label>
        </div>

        <button className="btn" disabled={loading} onClick={run}>
          {loading ? "Scanning…" : "Run SAST"}
        </button>

        {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
      </div>

      {rules && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">Built-in rule pack</div>
          <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
            Loaded from <code>{rules.rules_dir}</code>
          </div>
          <ul style={{ paddingLeft: 18, fontSize: 12 }}>
            {(rules.files || []).map((f) => (
              <li key={f.name}><code>{f.name}.yml</code> · {f.size_bytes} bytes</li>
            ))}
          </ul>
        </div>
      )}

      {result && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">
              SAST results — {result.files_scanned} file(s) scanned in {result.duration_s}s
              {result.engagement_scan_id && (
                <span className="dim" style={{ marginLeft: 8 }}>
                  · persisted as <code>{result.engagement_scan_id}</code>
                </span>
              )}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8 }}>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <SevTile key={s} sev={s}
                         count={result.severity_breakdown?.[s] || 0} />
              ))}
            </div>
          </div>

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">Findings ({result.findings_count})</div>
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead><tr style={{ color: "#00D4FF" }}>
                <th align="left">Sev</th>
                <th align="left">Rule</th>
                <th align="left">File</th>
                <th align="right">Line</th>
                <th align="left">Message</th>
              </tr></thead>
              <tbody>
                {(result.findings || []).map((f, i) => (
                  <tr key={i}>
                    <td style={{ color: SEV_COLOR[f.severity] || "#888" }}>{f.severity}</td>
                    <td><code>{f.rule_id?.split(".").slice(-1)[0]}</code></td>
                    <td>{f.file_path}</td>
                    <td align="right">{f.line}</td>
                    <td className="dim" style={{ fontSize: 11 }}>
                      {(f.title || "").slice(0, 100)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function SevTile({ sev, count }) {
  const color = SEV_COLOR[sev];
  return (
    <div style={{
      padding: 10, background: "rgba(0,0,0,0.3)",
      border: `1px solid ${color}33`,
    }}>
      <div className="dim" style={{ fontSize: 10, textTransform: "uppercase" }}>{sev}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{count}</div>
    </div>
  );
}
