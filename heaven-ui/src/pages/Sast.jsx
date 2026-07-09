// HEAVEN — SAST (Semgrep) launcher + results viewer
// Mirrors `heaven sast scan` from the CLI.

import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { SAST, Engagement } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import { sevColor } from "../theme";

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
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>🔬 SAST (Semgrep)</h2>
        <p className="page-lead">
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

        <label className="form-group" style={{ marginBottom: 12 }}>
          <span className="form-label">Source path (on server)</span>
          <input className="form-input mono-input" type="text" value={path}
                 onChange={(e) => setPath(e.target.value)}
                 placeholder="/path/to/source-code" />
        </label>

        <label className="form-group" style={{ marginBottom: 12 }}>
          <span className="form-label">Engagement (optional, persists findings)</span>
          <input className="form-input" type="text" value={engagement}
                 onChange={(e) => setEngagement(e.target.value)}
                 placeholder="active engagement name" />
        </label>

        <label className="form-group" style={{ marginBottom: 12 }}>
          <span className="form-label">Extra Semgrep configs (one per line or comma-sep)</span>
          <textarea className="form-input mono-input" rows={3} value={extraConfigs}
                    onChange={(e) => setExtraConfigs(e.target.value)}
                    placeholder={"p/owasp-top-ten\np/python\np/javascript"} />
        </label>

        <div style={{ display: "flex", gap: 18, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
          <label className="consent-row" style={{ margin: 0 }}>
            <input type="checkbox" checked={noBuiltin}
                   onChange={(e) => setNoBuiltin(e.target.checked)} />
            <span>Skip HEAVEN built-in rules</span>
          </label>
          <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 8, color: "var(--text-1)" }}>
            Timeout (s)
            <input className="form-input" type="number" value={timeout} min={30} max={1800}
                   onChange={(e) => setTimeoutS(parseInt(e.target.value, 10))}
                   style={{ width: 90 }} />
          </label>
        </div>

        <button className="btn btn-primary" disabled={loading} onClick={run}>
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

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={5} /></div>
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
            <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(5, 1fr)" }}>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <div key={s} className="mini-stat">
                  <div className="mini-stat-label" style={{ textTransform: "uppercase" }}>{s}</div>
                  <div className="mini-stat-value" style={{ color: sevColor(s) }}>
                    {result.severity_breakdown?.[s] || 0}
                  </div>
                </div>
              ))}
            </div>
            {result.engagement_scan_id && (
              <Link to="/findings" className="btn-small" style={{ marginTop: 14 }}>
                View persisted findings in triage →
              </Link>
            )}
          </div>

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">Findings ({result.findings_count})</div>
            <table className="data-table">
              <thead><tr>
                <th>Sev</th>
                <th>Rule</th>
                <th>File</th>
                <th className="num">Line</th>
                <th>Message</th>
              </tr></thead>
              <tbody>
                {(result.findings || []).map((f, i) => (
                  <tr key={i}>
                    <td style={{ color: sevColor(f.severity), fontWeight: 600 }}>{f.severity}</td>
                    <td><code>{f.rule_id?.split(".").slice(-1)[0]}</code></td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{f.file_path}</td>
                    <td className="num">{f.line}</td>
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
