// HEAVEN — Assets / Host & Service Inventory
// Mirrors `heaven assets`. Shows the open ports, service versions and OS the
// network scanner discovered for the active engagement — exactly as nmap
// observed them. An OS flagged "heuristic — unconfirmed" is a TTL guess, not a
// stack fingerprint, and is labelled so it's never read as a confirmed fact.

import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Assets } from "../api";
import { SkeletonCard, EmptyState } from "../components/Skeleton.jsx";

// Colour the OS chip by how much to trust it: a real nmap fingerprint is
// confident (accent), a TTL heuristic is cautionary (warn), unknown is muted.
function osStyle(host) {
  const src = host.os_source;
  if (src === "nmap") return { color: "var(--ok, #3fb950)", border: "var(--ok, #3fb950)" };
  if (src === "heuristic") return { color: "var(--warn, #d29922)", border: "var(--warn, #d29922)" };
  return { color: "var(--text-dim)", border: "var(--border)" };
}

export default function AssetsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [inventory, setInventory] = useState([]);
  const [totals, setTotals] = useState(null);

  function load() {
    setLoading(true);
    setError(null);
    Assets.list()
      .then((d) => {
        setInventory(d.assets || []);
        setTotals(d.totals || null);
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }

  // Reload when the operator switches engagements from the header chip.
  useEffect(() => {
    load();
    const onChange = () => load();
    window.addEventListener("heaven:engagement-changed", onChange);
    return () => window.removeEventListener("heaven:engagement-changed", onChange);
  }, []);

  const stat = [
    ["Hosts", totals?.hosts],
    ["Open ports", totals?.open_ports],
    ["Services", totals?.distinct_services],
    ["OS identified", totals?.os_identified],
  ];

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>🖧 Host &amp; Service Inventory</h2>
        <p className="page-lead">
          Every open port, service version and operating system the network scan
          discovered — reported exactly as observed by nmap, nothing fabricated.
          An OS shown as <em>heuristic — unconfirmed</em> was inferred from a TTL
          value, not a full stack fingerprint, and should be treated as
          indicative only. Run a network scan (<code>heaven scan -m network</code>
          {" "}or the <Link to="/scans">Scans</Link> launcher) to populate this.
        </p>

        {totals && (
          <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
            {stat.map(([label, val]) => (
              <div key={label} className="mini-stat">
                <div className="mini-stat-label" style={{ textTransform: "uppercase" }}>{label}</div>
                <div className="mini-stat-value">{val ?? 0}</div>
              </div>
            ))}
          </div>
        )}
        <button className="btn-small" style={{ marginTop: 12 }} onClick={load} disabled={loading}>
          {loading ? "Loading…" : "↻ Refresh"}
        </button>
        {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
      </div>

      {loading && <div style={{ marginTop: 12 }}><SkeletonCard lines={6} /></div>}

      {!loading && !error && inventory.length === 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <EmptyState
            icon="🖧"
            headline="No host inventory yet"
            body="Run a network scan for this engagement — discovered hosts, ports, service versions and OS appear here."
            cta="Launch a scan"
            ctaTo="/scans"
          />
        </div>
      )}

      {!loading && inventory.map((h) => {
        const os = osStyle(h);
        return (
          <div key={h.host} className="card" style={{ marginTop: 12 }}>
            <div className="card-title" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="mono">{h.host}</span>
              <span style={{
                fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 999,
                color: os.color, border: `1px solid ${os.border}`,
              }}>
                {h.os_label || "OS not determined"}
              </span>
              <span className="dim" style={{ fontSize: 12, fontWeight: 400 }}>
                {h.port_count} open port{h.port_count === 1 ? "" : "s"}
              </span>
            </div>
            {(!h.ports || h.ports.length === 0) ? (
              <div className="dim" style={{ padding: 8 }}>No open ports observed.</div>
            ) : (
              <table className="data-table">
                <thead><tr>
                  <th className="num">Port</th>
                  <th>Proto</th>
                  <th>Service</th>
                  <th>Version</th>
                  <th>CPE</th>
                </tr></thead>
                <tbody>
                  {h.ports.map((p, i) => (
                    <tr key={i}>
                      <td className="num mono">{p.port}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{p.protocol || "tcp"}</td>
                      <td>{p.service || "—"}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{p.service_version || "—"}</td>
                      <td className="mono" style={{ fontSize: 10.5 }}>{p.cpe || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {(h.honeypot_indicators || []).length > 0 && (
              <div className="dim" style={{ marginTop: 8, fontSize: 12 }}>
                ⚠ Honeypot indicators: {h.honeypot_indicators.join("; ")}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
