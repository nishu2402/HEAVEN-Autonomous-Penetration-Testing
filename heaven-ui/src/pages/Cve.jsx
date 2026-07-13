// HEAVEN — Dynamic live CVE lookup (NVD + CIRCL)
// Mirrors `heaven cve <product> [version]` from the CLI. Answers the
// "the vulnerability is not in my local DB" question: any product/version is
// looked up live against NVD + CIRCL, merged/de-duped, and version-confirmed.

import React, { useState } from "react";
import { Cve } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";
import { sevColor } from "../theme";

export default function CvePage() {
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [vendor, setVendor] = useState("");
  const [cpe, setCpe] = useState("");
  const [limit, setLimit] = useState(25);
  // Tracked globally so a live NVD/CIRCL lookup survives page navigation.
  const { loading, result, error, start } = useJob("cve");
  const [formError, setFormError] = useState(null);

  function run() {
    setFormError(null);
    if (!product.trim() && !cpe.trim()) {
      setFormError("Enter a product name (or an exact CPE).");
      return;
    }
    start(
      { label: "CVE lookup", kind: "cve", path: "/cve" },
      () => Cve.lookup({
        product: product.trim(),
        version: version.trim() || undefined,
        vendor: vendor.trim() || undefined,
        cpe: cpe.trim() || undefined,
        limit: Number(limit) || 25,
      }),
    );
  }

  function onKey(e) {
    if (e.key === "Enter") run();
  }

  const cves = result?.cves || [];

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>🧾 CVE Lookup · Live Feed</h2>
        <p className="page-lead">
          Dynamic CVE discovery for products <strong>not</strong> in HEAVEN's curated
          offline DB. Queries authoritative live feeds — <strong>NVD</strong> (CPE-matched,
          KEV-aware) and <strong>CIRCL CVE-Search</strong> (keyless fallback) — then merges,
          de-duplicates, enriches with <strong>EPSS</strong> (exploitation probability) and{" "}
          <strong>Exploit-DB</strong> (public PoC availability), and marks which CVEs a concrete
          version is actually confirmed to be affected by. Results are disk-cached, so repeats
          are instant and work offline.
        </p>

        <div className="form-row" style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12 }}>
          <label className="form-group">
            <span className="form-label">Product *</span>
            <input className="form-input mono-input" type="text" value={product}
                   onChange={(e) => setProduct(e.target.value)} onKeyDown={onKey}
                   placeholder="openssh · nginx · log4j · apache …" />
          </label>
          <label className="form-group">
            <span className="form-label">Version (optional — enables version-confirm)</span>
            <input className="form-input mono-input" type="text" value={version}
                   onChange={(e) => setVersion(e.target.value)} onKeyDown={onKey}
                   placeholder="9.5" />
          </label>
        </div>

        <div className="form-row" style={{ display: "grid", gridTemplateColumns: "1fr 2fr 80px", gap: 12 }}>
          <label className="form-group">
            <span className="form-label">Vendor (optional)</span>
            <input className="form-input mono-input" type="text" value={vendor}
                   onChange={(e) => setVendor(e.target.value)} onKeyDown={onKey}
                   placeholder="openbsd" />
          </label>
          <label className="form-group">
            <span className="form-label">Exact CPE 2.3 (optional — overrides product/version)</span>
            <input className="form-input mono-input" type="text" value={cpe}
                   onChange={(e) => setCpe(e.target.value)} onKeyDown={onKey}
                   placeholder="cpe:2.3:a:openbsd:openssh:9.5:*:*:*:*:*:*:*" />
          </label>
          <label className="form-group">
            <span className="form-label">Limit</span>
            <input className="form-input" type="number" min={1} max={100} value={limit}
                   onChange={(e) => setLimit(e.target.value)} onKeyDown={onKey} />
          </label>
        </div>

        <button className="btn btn-primary" disabled={loading} onClick={run}>
          {loading ? "Querying NVD + CIRCL…" : "Look up CVEs"}
        </button>

        {(formError || error) && (
          <div className="error" style={{ marginTop: 10 }}>{formError || error}</div>
        )}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={6} /></div>
      )}

      {result && (
        <>
          {result.available === false && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="dim" style={{ padding: 8 }}>
                ⚠ Live lookup unavailable on the server (missing <code>httpx</code>). Only
                cached results are returned. Install the <code>[recon]</code> extra to enable
                live queries.
              </div>
            </div>
          )}

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">
              {result.total} CVE(s) for{" "}
              <code>{result.product || cpe}{result.version ? ` ${result.version}` : ""}</code>
              <span className="dim" style={{ marginLeft: 8 }}>· sources: NVD + CIRCL</span>
            </div>

            {cves.length === 0 ? (
              <div className="dim" style={{ padding: 8 }}>
                No CVEs returned by the live feeds (or offline / not indexed).
              </div>
            ) : (
              <table className="data-table">
                <thead><tr>
                  <th>Sev</th>
                  <th className="num">CVSS</th>
                  <th className="num">EPSS</th>
                  <th>CVE</th>
                  <th>Status</th>
                  <th>CWE</th>
                  <th>Title</th>
                  <th>Src</th>
                </tr></thead>
                <tbody>
                  {cves.map((c, i) => {
                    const ref = (c.references || [])[0];
                    return (
                      <tr key={i}>
                        <td style={{ color: sevColor(c.severity), fontWeight: 600 }}>
                          {c.severity}
                        </td>
                        <td className="num">{c.cvss || "—"}</td>
                        <td className="num" style={{ fontSize: 11 }}>
                          {c.epss ? `${Math.round(c.epss * 100)}%` : "—"}
                        </td>
                        <td className="mono" style={{ fontSize: 11.5 }}>
                          {ref ? (
                            <a href={ref} target="_blank" rel="noopener noreferrer"
                               style={{ color: "var(--accent-2)" }}>{c.cve_id}</a>
                          ) : c.cve_id}
                          {c.in_kev && (
                            <span className="badge" style={{
                              marginLeft: 6, background: "var(--danger, #c0392b)",
                              color: "#fff", fontSize: 9, padding: "1px 5px", borderRadius: 4,
                            }}>KEV</span>
                          )}
                          {c.exploit_available && (
                            c.exploit_url ? (
                              <a href={c.exploit_url} target="_blank" rel="noopener noreferrer"
                                 className="badge" style={{
                                   marginLeft: 6, background: "#7b2ff7", color: "#fff",
                                   fontSize: 9, padding: "1px 5px", borderRadius: 4,
                                   textDecoration: "none",
                                 }}>PoC</a>
                            ) : (
                              <span className="badge" style={{
                                marginLeft: 6, background: "#7b2ff7", color: "#fff",
                                fontSize: 9, padding: "1px 5px", borderRadius: 4,
                              }}>PoC</span>
                            )
                          )}
                        </td>
                        <td style={{ fontSize: 11 }}>
                          {c.version_confirmed ? (
                            <span style={{ color: sevColor("high") }}>✓ confirmed</span>
                          ) : (
                            <span className="dim">version-unverified</span>
                          )}
                        </td>
                        <td className="mono" style={{ fontSize: 11 }}>{c.cwe || "—"}</td>
                        <td style={{ fontSize: 11.5, maxWidth: 380 }}>
                          {(c.title || "").slice(0, 130)}
                        </td>
                        <td className="mono dim" style={{ fontSize: 10 }}>{c.source}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
            <p className="dim" style={{ marginTop: 10, fontSize: 11 }}>
              <strong>✓ confirmed</strong> = a machine-readable version range matched the
              version you entered. Unmarked CVEs are candidates that still need a manual
              version check (the feed didn't expose a range).
            </p>
          </div>
        </>
      )}
    </div>
  );
}
