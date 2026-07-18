// HEAVEN — reusable "Save findings to engagement" picker.
//
// A dropdown of the operator's existing engagements (with finding counts) plus
// a "＋ New engagement…" option, so a run's findings always land where the
// operator explicitly chose — never a mistyped, phantom-empty engagement. Used
// by the Autonomous, SAST and SCA launchers to give them the same reliable
// destination control the pentest scan launcher has.
//
// Controlled: the parent owns the resolved destination string. `value` is the
// resolved engagement name (DB stem, "" = none/default); `onChange(name)` fires
// whenever the resolved destination changes.

import React, { useEffect, useMemo, useState } from "react";
import { Engagements } from "../api";
import HelpTip from "./HelpTip.jsx";

export default function EngagementPicker({
  value,
  onChange,
  id = "eng-picker",
  label = "Save findings to engagement",
  help = "The engagement this run's findings are saved into. Defaults to the one you're viewing — change it so a run never lands in the wrong engagement. Pick “＋ New engagement…” to start a fresh one.",
}) {
  const [engList, setEngList] = useState([]);
  const [choice, setChoice] = useState("");   // name | "__new__" | ""
  const [newEng, setNewEng] = useState("");

  // Load existing engagements once; default the selection to the active one
  // (or, if none exist yet, to creating a new engagement).
  useEffect(() => {
    let alive = true;
    Engagements.list()
      .then((r) => {
        if (!alive) return;
        const list = r?.engagements || [];
        setEngList(list);
        const active = list.find((e) => e.active) || list[0];
        const initial = (value && list.some((e) => e.name === value))
          ? value
          : (active ? active.name : "__new__");
        setChoice(initial);
        if (initial === "__new__" && value) setNewEng(value);
      })
      .catch(() => { if (alive) setChoice("__new__"); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dest = choice === "__new__" ? newEng.trim() : (choice || "").trim();

  // Report the resolved destination up to the parent whenever it changes.
  useEffect(() => { onChange?.(dest); }, [dest]); // eslint-disable-line react-hooks/exhaustive-deps

  const options = useMemo(() => engList.map((e) => (
    <option key={e.name} value={e.name}>
      {(e.display_name || e.name)}{e.active ? " — current" : ""}
      {` (${e.findings} finding${e.findings === 1 ? "" : "s"})`}
    </option>
  )), [engList]);

  return (
    <label className="form-group form-full" htmlFor={id}>
      <span className="form-label">
        {label}
        <HelpTip text={help} />
      </span>
      <select
        id={id}
        className="form-select"
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        style={{ minWidth: 0 }}
      >
        {options}
        <option value="__new__">＋ New engagement…</option>
      </select>
      {choice === "__new__" && (
        <input
          className="form-input"
          type="text"
          value={newEng}
          onChange={(e) => setNewEng(e.target.value)}
          placeholder="e.g. acme-webapp-pentest"
          style={{ marginTop: 8, minWidth: 0 }}
          autoFocus
        />
      )}
      {dest && (
        <span className="dim" style={{ fontSize: 11, marginTop: 4 }}>
          Findings will be saved to “{dest}”.
        </span>
      )}
    </label>
  );
}
