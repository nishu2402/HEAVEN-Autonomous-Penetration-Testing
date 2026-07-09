// HEAVEN — Targets tag/chip input.
//
// A textarea for "one target per line" works but feels clunky. This turns target
// entry into tactile chips: type a target and press Enter / comma / space (or
// paste a whole list) → each becomes a removable pill, colour-coded and validated
// live (URL / IP / CIDR / host, or flagged if unrecognised). Backspace on an empty
// field removes the last chip; duplicates are ignored.
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

function parse(value) {
  return String(value || "").split(SPLIT).map((s) => s.trim()).filter(Boolean);
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

  function onKeyDown(e) {
    if (e.key === "Enter" || e.key === "," || e.key === " ") {
      // Enter would also submit the surrounding <form> — always swallow it here.
      e.preventDefault();
      if (draft.trim()) commit(draft);
    } else if (e.key === "Backspace" && !draft && tokens.length) {
      e.preventDefault();
      removeAt(tokens.length - 1);
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
                title={kind ? `${kind}: ${t}` : `Unrecognised target: ${t}`}>
            <span className="tag-kind">{kind || "?"}</span>
            <span className="tag-text">{t}</span>
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
