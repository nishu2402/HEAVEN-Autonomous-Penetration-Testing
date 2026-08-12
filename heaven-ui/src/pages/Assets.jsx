// HEAVEN — Assets / Host & Service Inventory
// Mirrors `heaven assets`. Shows the open ports, service versions and OS the
// network scanner discovered for the active engagement — exactly as nmap
// observed them. An OS flagged "heuristic — unconfirmed" is a TTL guess, not a
// stack fingerprint, and is labelled so it's never read as a confirmed fact.

import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { Assets } from "../api";
import { SkeletonCard, EmptyState } from "../components/Skeleton.jsx";

// Ascending sort key for a host row. IPv4 addresses sort numerically (so .2
// comes before .10, not lexicographically after it); anything else (hostnames,
// IPv6) falls back to a case-insensitive string compare. Returned as a tuple so
// numeric IPs always sort ahead of, and independently from, named hosts.
function hostSortKey(host) {
  const h = (host || "").trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const n = ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4];
    return [0, n, ""];
  }
  return [1, 0, h.toLowerCase()];
}

function compareHosts(a, b) {
  const ka = hostSortKey(a.host), kb = hostSortKey(b.host);
  if (ka[0] !== kb[0]) return ka[0] - kb[0];
  if (ka[1] !== kb[1]) return ka[1] - kb[1];
  return ka[2] < kb[2] ? -1 : ka[2] > kb[2] ? 1 : 0;
}

// Does a host row match the free-text search? Matches the host/IP, the OS
// label, and any port's service or version — so "mysql", "apache", "3306" or an
// IP prefix all find the right box.
function hostMatches(h, q) {
  if (!q) return true;
  const hay = [
    h.host, h.os_label,
    h.device_name, h.device_name_label, h.device_type, h.device_type_label,
    h.mac_address, h.mac_vendor,
    ...(h.ports || []).flatMap((p) => [String(p.port), p.service, p.service_version, p.cpe]),
  ].filter(Boolean).join(" ").toLowerCase();
  return hay.includes(q);
}

// Colour the OS chip by how much to trust it: a real nmap fingerprint is
// confident (accent), a TTL heuristic is cautionary (warn), unknown is muted.
function osStyle(host) {
  const src = host.os_source;
  if (src === "nmap") return { color: "var(--ok, #3fb950)", border: "var(--ok, #3fb950)" };
  if (src === "heuristic") return { color: "var(--warn, #d29922)", border: "var(--warn, #d29922)" };
  return { color: "var(--text-dim)", border: "var(--border)" };
}

// Same trust-colouring for the device-type chip: an nmap -O classification is
// confident (accent), a MAC-vendor-derived category is a maker hint (warn).
function deviceTypeStyle(host) {
  const src = host.device_type_source;
  if (src === "nmap") return { color: "var(--accent-2, #6D7CFF)", border: "var(--accent-2, #6D7CFF)" };
  if (src === "mac-vendor") return { color: "var(--warn, #d29922)", border: "var(--warn, #d29922)" };
  return { color: "var(--text-dim)", border: "var(--border)" };
}

// Short, human label for one scan in the picker:
// "target · 3 hosts · 7 ports · Jul 18 14:22". The port count lets an operator
// tell at a glance which scan actually found services vs. a dead-host scan.
function scanOptionLabel(s) {
  const when = s.when ? new Date(s.when).toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  }) : "";
  const hosts = `${s.hosts} host${s.hosts === 1 ? "" : "s"}`;
  const ports = s.ports != null
    ? `${s.ports} port${s.ports === 1 ? "" : "s"}`
    : "";
  return [s.label, hosts, ports, when].filter(Boolean).join("  ·  ");
}

export default function AssetsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [inventory, setInventory] = useState([]);
  const [totals, setTotals] = useState(null);
  const [dns, setDns] = useState([]);
  const [dnsTotals, setDnsTotals] = useState(null);
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [query, setQuery] = useState("");

  // Pass scanId=null to let the backend pick the most recent scan. The
  // inventory is scoped to ONE scan so two separate scans never blend into a
  // single host table; the picker below switches between them.
  function load(sid) {
    setLoading(true);
    setError(null);
    Assets.list(sid || undefined)
      .then((d) => {
        setInventory(d.assets || []);
        setTotals(d.totals || null);
        setDns(d.dns || []);
        setDnsTotals(d.dns_totals || null);
        setScans(d.scans || []);
        setScanId(d.scan_id || null);
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }

  // Reload when the operator switches engagements from the header chip — reset
  // to that engagement's most recent scan (don't carry a stale scan id over).
  useEffect(() => {
    load(null);
    const onChange = () => load(null);
    window.addEventListener("heaven:engagement-changed", onChange);
    return () => window.removeEventListener("heaven:engagement-changed", onChange);
  }, []);

  const stat = [
    ["Hosts", totals?.hosts],
    ["Open ports", totals?.open_ports],
    ["Services", totals?.distinct_services],
    ["OS identified", totals?.os_identified],
    ["Devices", totals?.devices_identified],
  ];

  // Sorted ascending by host/IP and filtered by the search box. The backend
  // returns hosts busiest-first (most open ports); operators asked for a
  // predictable ascending order plus a way to jump straight to one target.
  const q = query.trim().toLowerCase();
  const visibleHosts = useMemo(
    () => [...inventory].filter((h) => hostMatches(h, q)).sort(compareHosts),
    [inventory, q],
  );
  const visibleDns = useMemo(
    () => (q
      ? dns.filter((n) => (n.domain || "").toLowerCase().includes(q))
      : [...dns].sort((a, b) => (a.domain || "").localeCompare(b.domain || ""))),
    [dns, q],
  );

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>🖧 Host &amp; Service Inventory</h2>
        <p className="page-lead">
          Every open port, service version and operating system the network scan
          discovered — reported exactly as observed by nmap, nothing fabricated.
          An OS shown as <em>heuristic — unconfirmed</em> was inferred from a TTL
          value, not a full stack fingerprint, and should be treated as
          indicative only. Where the scan observed them, each host also shows its
          <strong> device name</strong>, <strong>device type</strong> and
          {" "}<strong>MAC address</strong> — a MAC only appears for a host on the
          same local network segment scanned with sufficient privileges (it is an
          ARP fact, so remote/routed hosts have none), and a device type tagged
          {" "}<em>per MAC vendor</em> is a maker hint, not a fingerprint. The
          inventory is scoped to a single scan (most recent by default) so two
          scans never blend into one host table — use the picker to switch. Run a
          network scan (<code>heaven scan -m network</code>{" "}or the{" "}
          <Link to="/scans">Scans</Link> launcher) to populate this.
        </p>

        {scans.length > 0 && (
          <label className="form-group" style={{ maxWidth: 460, marginTop: 6 }}>
            <span className="form-label">Scan{scans.length > 1 ? ` (${scans.length})` : ""}</span>
            <select
              className="form-select"
              value={scanId || ""}
              onChange={(e) => load(e.target.value)}
              disabled={loading}
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>{scanOptionLabel(s)}</option>
              ))}
            </select>
          </label>
        )}

        {(inventory.length > 0 || dns.length > 0) && (
          <label className="form-group" style={{ maxWidth: 460, marginTop: 10 }}>
            <span className="form-label">Search targets</span>
            <input
              className="form-input"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by IP, hostname, service, version or port — e.g. 10.0.0., mysql, 443"
            />
          </label>
        )}

        {totals && (
          <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(5, minmax(0, 1fr))" }}>
            {stat.map(([label, val]) => (
              <div key={label} className="mini-stat">
                <div className="mini-stat-label" style={{ textTransform: "uppercase" }}>{label}</div>
                <div className="mini-stat-value">{val ?? 0}</div>
              </div>
            ))}
          </div>
        )}
        <button className="btn-small" style={{ marginTop: 12 }} onClick={() => load(scanId)} disabled={loading}>
          {loading ? "Loading…" : "↻ Refresh"}
        </button>
        {error && <div className="error" style={{ marginTop: 10 }}>{error}</div>}
      </div>

      {loading && <div style={{ marginTop: 12 }}><SkeletonCard lines={6} /></div>}

      {!loading && !error && inventory.length === 0 && dns.length === 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <EmptyState
            icon="🖧"
            headline="No host inventory yet"
            body="Run a network or DNS scan for this engagement — discovered hosts, ports, service versions, OS and DNS records appear here."
            cta="Launch a scan"
            ctaTo="/scans"
          />
        </div>
      )}

      {!loading && !error && q && visibleHosts.length === 0 && visibleDns.length === 0 &&
        (inventory.length > 0 || dns.length > 0) && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="dim" style={{ padding: 8 }}>
            No host or domain matches “{query.trim()}”. Clear the search to see all targets.
          </div>
        </div>
      )}

      {!loading && visibleHosts.map((h) => {
        const os = osStyle(h);
        const dt = deviceTypeStyle(h);
        return (
          <div key={h.host} className="card" style={{ marginTop: 12 }}>
            <div className="card-title" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="mono">{h.host}</span>
              {h.device_name_label && (
                <span className="dim" style={{ fontSize: 12.5, fontWeight: 500 }}>
                  {h.device_name_label}
                </span>
              )}
              <span style={{
                fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 999,
                color: os.color, border: `1px solid ${os.border}`,
              }}>
                {h.os_label || "OS not determined"}
              </span>
              {h.device_type_label && (
                <span style={{
                  fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 999,
                  color: dt.color, border: `1px solid ${dt.border}`,
                }}>
                  {h.device_type_label}
                </span>
              )}
              <span className="dim" style={{ fontSize: 12, fontWeight: 400 }}>
                {h.port_count} open port{h.port_count === 1 ? "" : "s"}
              </span>
            </div>
            {h.mac_label && (
              <div className="dim mono" style={{ fontSize: 11.5, marginTop: 2 }}>
                MAC {h.mac_label}
              </div>
            )}
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

      {!loading && visibleDns.length > 0 && (
        <div className="card" style={{ marginTop: 18 }}>
          <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>🌐 DNS Enumeration</h2>
          <p className="page-lead" style={{ marginBottom: 8 }}>
            DNS records and resolvable subdomains discovered for this engagement —
            reported exactly as authoritative DNS returned them. A subdomain is
            listed only because it actually resolved; nothing is fabricated.
          </p>
          {dnsTotals && (
            <div className="mini-stat-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
              {[
                ["Domains", dnsTotals.domains],
                ["Records", dnsTotals.records],
                ["Subdomains", dnsTotals.subdomains],
                ["Mail servers", dnsTotals.mail_servers],
              ].map(([label, val]) => (
                <div key={label} className="mini-stat">
                  <div className="mini-stat-label" style={{ textTransform: "uppercase" }}>{label}</div>
                  <div className="mini-stat-value">{val ?? 0}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && visibleDns.map((n) => {
        const RT = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"];
        const recRows = RT.flatMap((rt) =>
          (n.records?.[rt] || []).map((val, i) => ({ rt, val, key: `${rt}-${i}` })),
        );
        const dnssecOk = n.dnssec?.enabled;
        return (
          <div key={n.domain} className="card" style={{ marginTop: 12 }}>
            <div className="card-title" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="mono">{n.domain}</span>
              <span style={{
                fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 999,
                color: dnssecOk ? "var(--ok, #3fb950)" : "var(--text-dim)",
                border: `1px solid ${dnssecOk ? "var(--ok, #3fb950)" : "var(--border)"}`,
              }}>
                DNSSEC {dnssecOk ? "enabled" : "not detected"}
              </span>
              {n.wildcard && (
                <span className="dim" style={{ fontSize: 12 }}>⚠ wildcard DNS present</span>
              )}
            </div>

            {recRows.length > 0 && (
              <table className="data-table">
                <thead><tr>
                  <th style={{ width: 70 }}>Type</th>
                  <th>Record</th>
                </tr></thead>
                <tbody>
                  {recRows.map(({ rt, val, key }) => (
                    <tr key={key}>
                      <td className="mono" style={{ fontSize: 11.5 }}>{rt}</td>
                      <td className="mono" style={{ fontSize: 11.5, wordBreak: "break-all" }}>{val}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {(n.subdomains || []).length > 0 && (
              <>
                <div className="card-title" style={{ marginTop: 12, fontSize: 13 }}>
                  Subdomains discovered ({n.subdomains.length})
                </div>
                <table className="data-table">
                  <thead><tr>
                    <th>Subdomain</th>
                    <th>Addresses</th>
                  </tr></thead>
                  <tbody>
                    {n.subdomains.map((s, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontSize: 11.5 }}>{s.name}</td>
                        <td className="mono" style={{ fontSize: 11 }}>
                          {(s.addresses || []).join(", ") || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
