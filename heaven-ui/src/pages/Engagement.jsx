import React, { useCallback, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { Engagement as Eng, Engagements } from "../api";
import { EmptyState } from "../components/Skeleton.jsx";
import { useToast } from "../components/Toast.jsx";

const EMPTY_NEW = { name: "", client: "", sow: "", tester: "" };

// The stored created_at is a raw ISO string with microseconds
// (2026-08-19T09:36:46.689771+00:00) — machine output, not something to show an
// operator verbatim. Render it as a readable local date, and fall back to the
// raw value only if it will not parse.
function fmtWhen(iso) {
  if (!iso) return "n/a";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function EngagementPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  // Inline edit for Client / Statement of work.
  const [editField, setEditField] = useState(null);   // "client" | "statement_of_work" | null
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  // Create-a-new-engagement form. Opened by the "New engagement" action
  // (command palette / dashboard button route here with ?new=1) or the inline
  // "＋ New engagement" button on this page.
  const [creating, setCreating] = useState(false);
  const [newForm, setNewForm] = useState(EMPTY_NEW);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState(null);

  const reload = useCallback(() => {
    Eng.summary().then(setData).catch((e) => setError(e.message));
  }, []);

  useEffect(() => { reload(); }, [reload]);

  // Open the create form when routed here with ?new=1 (command palette, the
  // dashboard "New engagement" button, the header "Manage engagements" link).
  useEffect(() => {
    if (searchParams.get("new") === "1") setCreating(true);
  }, [searchParams]);

  function openCreate() {
    setCreateError(null);
    setNewForm(EMPTY_NEW);
    setCreating(true);
  }
  function cancelCreate() {
    setCreating(false);
    setCreateError(null);
    setNewForm(EMPTY_NEW);
    if (searchParams.get("new")) setSearchParams({}, { replace: true });
  }
  async function submitCreate() {
    const name = newForm.name.trim();
    if (!name) { setCreateError("Name is required."); return; }
    setCreateBusy(true);
    setCreateError(null);
    try {
      await Engagements.create({
        name,
        client: newForm.client.trim(),
        sow: newForm.sow.trim(),
        tester: newForm.tester.trim(),
      });
      toast.success?.(`Engagement "${name}" created`);
      setCreating(false);
      setNewForm(EMPTY_NEW);
      if (searchParams.get("new")) setSearchParams({}, { replace: true });
      reload();   // the new engagement is now the active one
    } catch (e) {
      setCreateError(e.message || "Could not create engagement");
    } finally {
      setCreateBusy(false);
    }
  }

  function startEdit(field, current) {
    setEditField(field);
    setDraft(current || "");
    setSaveError(null);
  }
  function cancelEdit() {
    setEditField(null);
    setDraft("");
    setSaveError(null);
  }
  async function saveEdit(field) {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await Eng.updateDetails({ [field]: draft });
      // Fold the server's canonical (trimmed/capped) value back into view.
      setData((d) => (d && res.engagement ? { ...d, engagement: res.engagement } : d));
      setEditField(null);
      setDraft("");
      toast.success?.("Engagement details saved");
    } catch (e) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  }

  // One editable metadata row (label ↔ value with an inline pencil editor).
  function EditableRow({ label, field, value }) {
    if (editField === field) {
      return (
        <tr>
          <td>{label}</td>
          <td>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <input
                className="form-input"
                autoFocus
                value={draft}
                disabled={saving}
                maxLength={200}
                placeholder={`Add ${label.toLowerCase()}…`}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") { e.preventDefault(); saveEdit(field); }
                  if (e.key === "Escape") { e.preventDefault(); cancelEdit(); }
                }}
                style={{ flex: "1 1 240px", minWidth: 180 }}
              />
              <button className="btn-small" disabled={saving} onClick={() => saveEdit(field)}>
                {saving ? "Saving…" : "Save"}
              </button>
              <button className="btn-small" disabled={saving} onClick={cancelEdit}>Cancel</button>
            </div>
            {saveError && (
              <div className="error" style={{ marginTop: 6, fontSize: 12 }}>{saveError}</div>
            )}
          </td>
        </tr>
      );
    }
    return (
      <tr>
        <td>{label}</td>
        <td>
          <div style={{ display: "flex", gap: 10, alignItems: "center", justifyContent: "space-between" }}>
            <span className={value ? "" : "dim"}>{value || "n/a"}</span>
            <button
              className="btn-small"
              onClick={() => startEdit(field, value)}
              title={`Edit ${label.toLowerCase()}`}
              style={{ flex: "0 0 auto" }}
            >
              ✎ Edit
            </button>
          </div>
        </td>
      </tr>
    );
  }

  // The create form. Rendered at the top of every view state (loading, error,
  // empty, populated) whenever `creating` is on, so "New engagement" always
  // reaches a working form no matter which engagement (if any) is active.
  const createCard = creating ? (
    <div className="card">
      <div className="card-title">New engagement</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 520 }}>
        <label className="form-group">
          <span className="form-label">Name <span className="dim">(required)</span></span>
          <input
            className="form-input"
            autoFocus
            value={newForm.name}
            disabled={createBusy}
            maxLength={120}
            placeholder="e.g. acme-webapp-pentest"
            onChange={(e) => setNewForm((f) => ({ ...f, name: e.target.value }))}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); submitCreate(); }
              if (e.key === "Escape") { e.preventDefault(); cancelCreate(); }
            }}
          />
        </label>
        <label className="form-group">
          <span className="form-label">Client <span className="dim">(optional)</span></span>
          <input
            className="form-input"
            value={newForm.client}
            disabled={createBusy}
            maxLength={200}
            placeholder="e.g. ACME Corp"
            onChange={(e) => setNewForm((f) => ({ ...f, client: e.target.value }))}
          />
        </label>
        <label className="form-group">
          <span className="form-label">Statement of work <span className="dim">(optional)</span></span>
          <input
            className="form-input"
            value={newForm.sow}
            disabled={createBusy}
            maxLength={200}
            placeholder="e.g. SOW-2026-001"
            onChange={(e) => setNewForm((f) => ({ ...f, sow: e.target.value }))}
          />
        </label>
        <label className="form-group">
          <span className="form-label">Tester <span className="dim">(optional)</span></span>
          <input
            className="form-input"
            value={newForm.tester}
            disabled={createBusy}
            maxLength={200}
            placeholder="Who ran the assessment (shown on reports)"
            onChange={(e) => setNewForm((f) => ({ ...f, tester: e.target.value }))}
          />
        </label>
        {createError && (
          <div className="error" style={{ fontSize: 12 }}>{createError}</div>
        )}
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-primary"
            disabled={createBusy || !newForm.name.trim()}
            onClick={submitCreate}
          >
            {createBusy ? "Creating…" : "Create engagement"}
          </button>
          <button className="btn" disabled={createBusy} onClick={cancelCreate}>Cancel</button>
        </div>
        <span className="dim" style={{ fontSize: 11 }}>
          Creates an isolated SQLite store and switches the app to it. Add scope
          from the CLI, then launch a scan.
        </span>
      </div>
    </div>
  ) : null;

  if (error) {
    return (
      <div className="page">
        {createCard}
        <div className="card error">{error}</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="page">
        {createCard}
        {!creating && <div className="card"><span className="dim">Loading...</span></div>}
      </div>
    );
  }

  const { engagement, stats } = data;
  const noEng = data.no_engagement || !engagement;

  if (noEng) {
    return (
      <div className="page">
        {createCard}
        {!creating && (
          <div className="card" style={{ display: "flex", justifyContent: "flex-end" }}>
            <button className="btn btn-primary" onClick={openCreate}>＋ New engagement</button>
          </div>
        )}
        <EmptyState
          icon="◈"
          headline="No active engagement yet"
          body="HEAVEN organizes findings per engagement. Click ＋ New engagement above to start one, launch a scan with an engagement name, or use the CLI steps below."
          cta="Launch a scan →"
          ctaTo="/scans"
        />

        <div className="card">
          <div className="card-title">Or set up from the CLI</div>
          <pre className="code">{`# 1. Create an engagement
heaven engage init acme-q2 --client "ACME Corp" --sow "SOW-2026-001"

# 2. Point the server at it
export HEAVEN_ENGAGEMENT=engagements/acme-q2.db

# 3. Restart the server
heaven serve

# 4. Add scope
heaven scope add 10.0.0.0/24 --kind cidr
heaven scope add https://app.acme.example --kind url`}</pre>
        </div>

        <div className="card">
          <div className="card-title">Why per-engagement SQLite?</div>
          <div style={{ color: 'var(--text-1)', lineHeight: 1.8, fontSize: 13 }}>
            <p>Each engagement gets an isolated database file. No cross-contamination of findings,
            no shared state between clients. The file lives next to your notes, hand it to a
            colleague or archive it after the engagement ends.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      {createCard}
      {!creating && (
        <div className="card" style={{ display: "flex", justifyContent: "flex-end" }}>
          <button className="btn btn-primary" onClick={openCreate}>＋ New engagement</button>
        </div>
      )}
      <div className="card">
        <div className="card-title">Engagement Details</div>
        <table className="kv-table">
          <tbody>
            <tr><td>Name</td><td style={{ color: 'var(--text-0)', fontWeight: 700 }}>{engagement.name}</td></tr>
            <EditableRow label="Client" field="client" value={engagement.client} />
            <EditableRow label="Statement of work" field="statement_of_work" value={engagement.statement_of_work} />
            <EditableRow label="Tester" field="tester" value={engagement.tester} />
            <tr><td>Created</td><td className="dim">{fmtWhen(engagement.created_at)}</td></tr>
            <tr><td>Targets in scope</td><td>{stats.scope_targets}</td></tr>
            <tr><td>Scans run</td><td>{stats.scans_run}</td></tr>
            <tr><td>Total findings</td><td>{stats.total_findings}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Findings by severity</div>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {Object.entries(stats.by_severity || {}).map(([sev, count]) => (
            <div key={sev} style={{ textAlign: 'center', minWidth: 60 }}>
              <div style={{ fontSize: 24, fontWeight: 700 }} className={`sev-${sev}`}>{count}</div>
              <div style={{ fontSize: 10, color: 'var(--text-1)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>{sev}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-title">Manage scope from CLI</div>
        <pre className="code">{`heaven scope add api.acme.example --kind host
heaven scope add 10.0.0.0/24 --kind cidr
heaven scope import scope.txt
heaven scope list`}</pre>
        <p className="dim" style={{ marginTop: 10, fontSize: 12 }}>
          Scope changes are CLI-only. The UI is for triage, not for expanding attack surface.
        </p>
      </div>
    </div>
  );
}
