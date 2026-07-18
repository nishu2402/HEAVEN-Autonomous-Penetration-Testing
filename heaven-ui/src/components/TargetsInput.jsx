// HEAVEN — Targets tag/chip input.
//
// A textarea for "one target per line" works but feels clunky. This turns target
// entry into tactile chips: type a target and press Enter / comma / space (or
// paste a whole list) → each becomes a removable pill, colour-coded and validated
// live (URL / IP / CIDR / host, or flagged if unrecognised). Backspace on an empty
// field removes the last chip; duplicates are ignored. Click a chip's text to pull
// it back into the field and edit it (fix a typo without deleting + retyping).
//
// It is a drop-in for the old <textarea>: `value` is a newline-joined string and
// `onChange` returns the same shape, so the parent's existing split()/parse logic
// keeps working unchanged.

import React, { useMemo, useRef, useState } from "react";

const _IP = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const _URL = /^https?:\/\/[^\s/$.?#][^\s]*$/i;
const _HOST = /^([a-z0-9-]+\.)+[a-z]{2,}$/i;

// Classify a single target string → "url" | "cidr" | "ip" | "host" | null (invalid).
export function classifyTarget(t) {
  if (_URL.test(t)) return "url";
  if (_IP.test(t)) return t.includes("/") ? "cidr" : "ip";
  if (_HOST.test(t)) return "host";
  return null;
}

// Split on any whitespace, newline or comma — the delimiters an operator naturally
// uses when pasting a target list.
const SPLIT = /[\s,]+/;

// Characters that leak in when text is copied out of the chips themselves (the
// "×" remove glyph and its "✕" variant) or from rich sources
// (zero-width space/joiners U+200B–U+200D, BOM U+FEFF, non-breaking space U+00A0).
// Strip them so a copy → paste round-trip of an existing chip can't smuggle the
// chip's own decoration back into the field as junk tokens.
const JUNK = /[×✕​‌‍﻿ ]/g;

function parse(value) {
  return String(value || "")
    .replace(JUNK, " ")
    .split(SPLIT)
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function TargetsInput({ value, onChange, placeholder = "Add a target…", id }) {
  const [draft, setDraft] = useState("");
  const inputRef = useRef(null);
  const tokens = useMemo(() => parse(value), [value]);

  function setTokens(next) {
    onChange(next.join("\n"));
  }

  function commit(raw) {
    const parts = parse(raw);
    if (!parts.length) return;
    const seen = new Set(tokens);
    const merged = tokens.slice();
    for (const p of parts) {
      if (!seen.has(p)) { seen.add(p); merged.push(p); }
    }
    setTokens(merged);
    setDraft("");
  }

  function removeAt(i) {
    const next = tokens.slice();
    next.splice(i, 1);
    setTokens(next);
    inputRef.current?.focus();
  }

  // Pull chip `i` back into the editable field: commit any half-typed draft
  // first (so it isn't lost), drop the chip, and load its text for editing.
  function editAt(i) {
    const target = tokens[i];
    const next = tokens.slice();
    next.splice(i, 1);
    if (draft.trim()) {
      const seen = new Set(next);
      for (const p of parse(draft)) {
        if (!seen.has(p)) { seen.add(p); next.push(p); }
      }
    }
    setTokens(next);
    setDraft(target);
    inputRef.current?.focus();
  }

  function onKeyDown(e) {
    if (e.key === "Enter" || e.key === "," || e.key === " ") {
      // Enter would also submit the surrounding <form> — always swallow it here.
      e.preventDefault();
      if (draft.trim()) commit(draft);
    } else if (e.key === "Backspace" && !draft && tokens.length) {
      e.preventDefault();
      // Backspace on an empty field pulls the last chip back for editing rather
      // than silently discarding it — a fat-finger delete is recoverable.
      editAt(tokens.length - 1);
    }
  }

  function onPaste(e) {
    const text = e.clipboardData.getData("text");
    if (!text) return;
    e.preventDefault();
    commit(draft ? `${draft} ${text}` : text);
  }

  function onBlur() {
    if (draft.trim()) commit(draft);
  }

  return (
    <div className="tags-input" onClick={() => inputRef.current?.focus()}>
      {tokens.map((t, i) => {
        const kind = classifyTarget(t);
        return (
          <span key={`${t}-${i}`} className={"tag" + (kind ? "" : " is-invalid")}
                title={kind ? `${kind}: ${t} — click to edit` : `Unrecognised target: ${t} — click to edit`}>
            <span className="tag-kind" aria-hidden="true">{kind || "?"}</span>
            <button
              type="button" className="tag-text"
              onClick={(e) => { e.stopPropagation(); editAt(i); }}
              aria-label={`Edit ${t}`}
            >{t}</button>
            <button
              type="button" className="tag-remove" aria-label={`Remove ${t}`}
              onClick={(e) => { e.stopPropagation(); removeAt(i); }}
            >×</button>
          </span>
        );
      })}
      <input
        ref={inputRef}
        id={id}
        className="tags-input-field"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKeyDown}
        onPaste={onPaste}
        onBlur={onBlur}
        placeholder={tokens.length ? "" : placeholder}
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        aria-label="Add target"
      />
    </div>
  );
}
