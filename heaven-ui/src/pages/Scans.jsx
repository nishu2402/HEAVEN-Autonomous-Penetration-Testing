import React, { useEffect, useState } from "react";
import { Scans as ScansApi } from "../api";

export default function Scans() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState(null);

  function load() {
    ScansApi.list(50)
      .then((d) => { setScans(d.scans || []); setError(null); })
      .catch((e) => setError(e.message));
  }

  useEffect(() => {
    load();
    const i = setInterval(load, 10000);
    return () => clearInterval(i);
  }, []);

  return (
    <div>
      <div className="card">
        <h2>Scans</h2>
        <p className="dim">
          Scans are launched from the CLI for safety (the scope/auth gate is
          easier to enforce there). The web UI tracks status and feeds findings
          into the engagement DB.
        </p>
        <pre className="code">{`heaven scan -u https://app.example --engagement my-eng --i-have-authorization
heaven resume --engagement my-eng --i-have-authorization`}</pre>
      </div>

      {error && <div className="card error">{error}</div>}

      {scans && (
        <div className="card">
          <h3>Recent scans</h3>
          {scans.length === 0 && <p className="dim">No scans recorded yet.</p>}
          <table className="findings-table">
            <thead>
              <tr><th>ID</th><th>Mode</th><th>Status</th><th>Started</th></tr>
            </thead>
            <tbody>
              {scans.map((s, i) => (
                <tr key={s.scan_id || s.id || i}>
                  <td><code>{(s.scan_id || s.id || "").slice(0, 8)}</code></td>
                  <td>{s.mode || s.config?.scan_type || "—"}</td>
                  <td>
                    <span className={`status-pill status-${s.status}`}>{s.status}</span>
                  </td>
                  <td className="dim">{s.created || s.started_at || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
