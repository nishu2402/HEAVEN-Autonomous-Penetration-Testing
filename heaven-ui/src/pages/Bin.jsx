// HEAVEN — Recycle Bin
//
// Deleted scans and engagements land here first (the Scans "Remove" action, the
// Dashboard engagement delete, and `heaven engage delete`). From here an operator
// can restore an item to its original place or delete it permanently, so an
// accidental delete is recoverable. Items auto-purge after the server's retention
// window. Backed by GET /api/trash, POST /api/trash/{id}/restore,
// DELETE /api/trash/{id} and POST /api/trash/empty.

import React, { useCallback, useEffect, useState } from "react";
import { Trash } from "../api";
import { useToast } from "../components/Toast.jsx";
import { SkeletonTable, EmptyState } from "../components/Skeleton.jsx";

function relTime(iso) {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function plural(n, word) {
  const v = n ?? 0;
  return `${v} ${word}${v !== 1 ? "s" : ""}`;
}

export default function Bin() {
  const toast = useToast();
  const [items, setItems] = useState(null); // null = still loading
  const [retentionDays, setRetentionDays] = useState(30);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState({}); // id -> true (also "__all__" for Empty Bin)

  const load = useCallback(() => {
    Trash.list()
      .then((r) => {
        setItems(r.items || []);
        setRetentionDays(r.retention_days ?? 30);
        setError(null);
      })
      .catch((e) => { setError(e.message); setItems([]); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const setItemBusy = (id, on) =>
    setBusy((b) => {
      const n = { ...b };
      if (on) n[id] = true; else delete n[id];
      return n;
    });

  const restore = async (it) => {
    setItemBusy(it.id, true);
    try {
      const r = await Trash.restore(it.id);
      if (r.kind === "engagement") {
        toast.success(
          `Restored engagement "${r.restored}"`,
          r.renamed ? "The original name was taken, so it was restored under a new name." : undefined,
        );
      } else {
        toast.success(`Restored scan "${r.restored}"`, `Back in engagement "${r.engagement}".`);
      }
      load();
    } catch (e) {
      toast.error("Could not restore", e.message);
    } finally {
      setItemBusy(it.id, false);
    }
  };

  const purge = async (it) => {
    if (!window.confirm(`Permanently delete "${it.label}"? This cannot be undone.`)) return;
    setItemBusy(it.id, true);
    try {
      await Trash.remove(it.id);
      toast.success(`Permanently deleted "${it.label}"`);
      load();
    } catch (e) {
      toast.error("Could not delete", e.message);
    } finally {
      setItemBusy(it.id, false);
    }
  };

  const emptyBin = async () => {
    const n = (items || []).length;
    if (n === 0) return;
    if (!window.confirm(
      `Permanently delete all ${plural(n, "item")} in the Bin? This cannot be undone.`)) return;
    setItemBusy("__all__", true);
    try {
      const r = await Trash.empty();
      toast.success(`Emptied the Bin (${plural(r.purged_count, "item")})`);
      load();
    } catch (e) {
      toast.error("Could not empty the Bin", e.message);
    } finally {
      setItemBusy("__all__", false);
    }
  };

  const busyAll = !!busy.__all__;

  return (
    <div className="page">
      <div className="card">
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          gap: 12, flexWrap: "wrap",
        }}>
          <h2 style={{ marginTop: 0, marginBottom: 0 }}>🗑 Recycle Bin</h2>
          {items && items.length > 0 && (
            <button type="button" className="btn-small danger" onClick={emptyBin} disabled={busyAll}>
              {busyAll ? "…" : "Empty Bin"}
            </button>
          )}
        </div>
        <p className="page-lead">
          Deleted scans and engagements are kept here so you can review and restore them
          before they are removed for good.{" "}
          {retentionDays > 0
            ? `Items are deleted automatically after ${retentionDays} days.`
            : "Items are kept until you remove them."}
        </p>

        {error && <div className="error">{error}</div>}
        {items === null && !error && <SkeletonTable rows={4} cols={3} />}

        {items && items.length === 0 && !error && (
          <EmptyState
            icon="🗑"
            headline="The Bin is empty"
            body="Deleted scans and engagements appear here so you can restore them or remove them permanently."
          />
        )}

        {items && items.length > 0 && (
          <div className="bin-list">
            {items.map((it) => {
              const b = !!busy[it.id];
              const s = it.summary || {};
              const meta = it.kind === "engagement"
                ? `${plural(s.findings, "finding")}, ${plural(s.scans, "scan")}`
                : `engagement "${it.engagement}" · ${plural(s.findings, "finding")}` +
                  (s.mode ? ` · ${s.mode}` : "");
              return (
                <div className="bin-row" key={it.id}>
                  <span className="bin-icon" aria-hidden="true">
                    {it.kind === "engagement" ? "📁" : "🔍"}
                  </span>
                  <div className="bin-main">
                    <div className="bin-label">
                      <span>{it.label}</span>
                      <span className="bin-kind">{it.kind}</span>
                    </div>
                    <div className="bin-meta">
                      {meta} · deleted <span title={it.deleted_at}>{relTime(it.deleted_at)}</span>
                      {it.deleted_by ? ` by ${it.deleted_by}` : ""}
                    </div>
                  </div>
                  <div className="bin-actions">
                    <button
                      type="button" className="btn-small"
                      disabled={b || busyAll} onClick={() => restore(it)}
                      aria-label={`Restore ${it.label}`}
                    >
                      {b ? "…" : "↩ Restore"}
                    </button>
                    <button
                      type="button" className="btn-small danger"
                      disabled={b || busyAll} onClick={() => purge(it)}
                      aria-label={`Permanently delete ${it.label}`}
                    >
                      {b ? "…" : "🗑 Delete permanently"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
