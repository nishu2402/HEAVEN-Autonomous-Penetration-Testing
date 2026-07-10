// HEAVEN — SCA (Software Composition Analysis) launcher + results viewer
// Mirrors `heaven sca` from the CLI. Audits dependency manifests against OSV.dev.

import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { SCA, Engagement } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";
import { sevColor } from "../theme";

export default function ScaPage() {
  const [path, setPath] = useState("");
  const [engagement, setEngagement] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
  }, []);

  async function run() {
    setError(null);
    setResult(null);
    if (!path.trim()) {
      setError("Source path is required.");
      return;
    }
    setLoading(true);
    try {
      const r = await SCA.scan({
        path: path.trim(),
        engagement: engagement || undefined,
      });
      if (r.error) setError(r.error);
      setResult(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const findings = result?.findings || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>📦 SCA · Dependency Audit</h2>
        <p className="page-lead">
          Software Composition Analysis. Parses dependency manifests
          (<code>requirements.txt</code>, <code>package-lock.json</code>,{" "}
          <code>go.sum</code>, <code>pom.xml</code>, …) and cross-references every
          pinned package against the OSV.dev advisory database — the feed that
          covers known-vulnerable dependencies NVD's CPE search cannot.
        </p>

        <label className="form-group" style={{ marginBottom: 12 }}>
          <span className="form-label">Source path (on server)</span>
          <input className="form-input mono-input" type="text" value={path}
                 onChange={(e) => setPath(e.target.value)}
                 placeholder="/path/to/project  or  /path/to/requirements.txt" />
        </label>

        <label className="form-group" style={{ marginBottom: 12 }}>
          <span className="form-label">Engagement (optional, persists findings)</span>
          <input className="form-input" type="text" value={engagement}
                 onChange={(e) => setEngagement(e.target.value)}
                 placeholder="active engagement name" />
        </label>

        <button className="btn btn-primary" disabled={loading} onClick={run}>
          {loading ? "Auditing…" : "Run SCA"}
        </button>

        {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={5} /></div>
      )}

      {result && !result.error && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">
              Dependency audit — {result.packages} package(s) across{" "}
              {(result.manifests || []).length} manifest(s)
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
                    {counts[s] || 0}
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
            <div className="card-title">Vulnerable dependencies ({findings.length})</div>
            {findings.length === 0 ? (
              <div className="dim" style={{ padding: 8 }}>
                No known-vulnerable dependencies found. 🎉
              </div>
            ) : (
              <table className="data-table">
                <thead><tr>
                  <th>Sev</th>
                  <th className="num">CVSS</th>
                  <th>Package</th>
                  <th>Advisory</th>
                  <th>Fixed in</th>
                </tr></thead>
                <tbody>
                  {findings.map((f, i) => {
                    const e = f.evidence || {};
                    return (
                      <tr key={i}>
                        <td style={{ color: sevColor(f.severity), fontWeight: 600 }}>{f.severity}</td>
                        <td className="num">{f.cvss || "—"}</td>
                        <td className="mono" style={{ fontSize: 11.5 }}>
                          {e.package}@{e.installed_version}
                        </td>
                        <td className="mono" style={{ fontSize: 11 }}>
                          {f.cve_id || e.osv_id}
                        </td>
                        <td className="mono" style={{ fontSize: 11 }}>
                          {e.fixed_version || "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
