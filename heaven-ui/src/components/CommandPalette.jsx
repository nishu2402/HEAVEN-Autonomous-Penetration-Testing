// HEAVEN — Command palette (⌘K / Ctrl+K quick launcher)
//
// Why: 33 CLI commands + 19 UI pages + 42 API endpoints is too many to
// reach via mouse. Every modern pro tool (Linear, Slack, Vercel, GitHub)
// has this. Press ⌘K (mac) or Ctrl+K (Linux/Windows) anywhere → fuzzy
// search jumps to the right page or triggers the right action.

import React, {
  useCallback, useEffect, useMemo, useRef, useState,
} from "react";
import { useNavigate } from "react-router-dom";
import { useToast } from "./Toast.jsx";

// ── Catalogue ──────────────────────────────────────────────────────
// One entry per navigable destination + one entry per quick-trigger
// action. Keep grouped by category so the palette renders nicely.

const CATALOGUE = [
  // --- Navigation
  { group: "Navigate", icon: "▣",  label: "Dashboard",    hint: "g d",        nav: "/" },
  { group: "Navigate", icon: "◈",  label: "Engagement",   hint: "g e",        nav: "/engagement" },
  { group: "Navigate", icon: "⚠",  label: "Findings",     hint: "g f",        nav: "/findings" },
  { group: "Navigate", icon: "⛓",  label: "Kill Chain",   hint: "g k",        nav: "/kill-chain" },
  { group: "Navigate", icon: "⚡", label: "Scans",        hint: "g s",        nav: "/scans" },
  { group: "Navigate", icon: "🔁", label: "Watch",        hint: "g w",        nav: "/watch" },
  { group: "Navigate", icon: "↹",  label: "Scan Diff",    hint: "g D",        nav: "/diff" },
  { group: "Navigate", icon: "🔬", label: "SAST",         hint: "g S",        nav: "/sast" },
  { group: "Navigate", icon: "🧾", label: "CVE Lookup",   hint: "",           nav: "/cve" },
  { group: "Navigate", icon: "∞",  label: "Autonomous",   hint: "g a",        nav: "/autonomous" },
  { group: "Navigate", icon: "✦",  label: "AI Plans",     hint: "g p",        nav: "/ai-plans" },
  { group: "Navigate", icon: "◐",  label: "Coverage",     hint: "g c",        nav: "/coverage" },
  { group: "Navigate", icon: "☣", label: "Post-Ex",      hint: "g x",        nav: "/postex" },
  { group: "Navigate", icon: "↔",  label: "Lateral",      hint: "g l",        nav: "/lateral" },
  { group: "Navigate", icon: "🧠", label: "Knowledge",    hint: "g K",        nav: "/knowledge" },
  { group: "Navigate", icon: "🎫", label: "Tickets",      hint: "g t",        nav: "/tickets" },
  { group: "Navigate", icon: "≡",  label: "Benchmark",    hint: "g b",        nav: "/benchmark" },
  { group: "Navigate", icon: "§",  label: "Methodology",  hint: "g m",        nav: "/methodology" },
  { group: "Navigate", icon: "📄", label: "Reports",      hint: "",           nav: "/reports" },
  { group: "Navigate", icon: "🩺", label: "System Health", hint: "",           nav: "/health" },
  { group: "Navigate", icon: "⚙",  label: "Settings",     hint: "",           nav: "/settings" },

  // --- Quick actions (synthesised; wire to real handlers as needed)
  { group: "Action", icon: "+",  label: "New scan",
    hint: "n s", nav: "/scans?launch=1" },
  { group: "Action", icon: "+",  label: "New engagement",
    hint: "n e", nav: "/engagement?new=1" },
  { group: "Action", icon: "↻",  label: "Refresh dashboard",
    hint: "r",  reload: true },
  { group: "Action", icon: "?",  label: "Open API docs (/api/docs)",
    hint: "?",  external: "/api/docs" },
  { group: "Action", icon: "📐", label: "Open OWASP methodology",
    nav: "/methodology" },

  // --- Help
  { group: "Help", icon: "🧭", label: "Take the tour", tour: true },
  { group: "Help", icon: "?", label: "Keyboard shortcuts",
    hint: "?",  showShortcuts: true },
  { group: "Help", icon: "📚", label: "Quick start guide",
    external: "https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/blob/main/docs/QUICKSTART.md" },
  { group: "Help", icon: "🔒", label: "Report a security issue",
    external: "https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/blob/main/SECURITY.md" },
];


// Light-weight fuzzy match: every char of `q` must appear in `text` in
// order (case-insensitive). Returns a relevance score (lower = better).
function fuzzyScore(query, text) {
  if (!query) return 0;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return q.length / t.length;   // contiguous bonus
  let ti = 0;
  for (const c of q) {
    const next = t.indexOf(c, ti);
    if (next < 0) return Infinity;
    ti = next + 1;
  }
  return ti / t.length + 1;     // subsequence, scored worse than contiguous
}


function useGlobalHotkey(callback) {
  useEffect(() => {
    function onKey(ev) {
      const isMod = ev.metaKey || ev.ctrlKey;
      if (isMod && ev.key.toLowerCase() === "k") {
        ev.preventDefault();
        callback();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [callback]);
}


export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const toast = useToast();

  const close = useCallback(() => { setOpen(false); setQuery(""); setActive(0); }, []);
  const toggle = useCallback(() => setOpen(v => !v), []);

  useGlobalHotkey(toggle);

  // Escape to close — only when open
  useEffect(() => {
    if (!open) return;
    function onKey(ev) {
      if (ev.key === "Escape") close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, close]);

  // Auto-focus input when opening
  useEffect(() => {
    if (open && inputRef.current) inputRef.current.focus();
  }, [open]);

  // Ranked + filtered items
  const items = useMemo(() => {
    if (!query) return CATALOGUE;
    return CATALOGUE
      .map(it => ({ it, s: fuzzyScore(query, it.label) }))
      .filter(({ s }) => s < Infinity)
      .sort((a, b) => a.s - b.s)
      .map(({ it }) => it);
  }, [query]);

  // Reset active index when filtering changes
  useEffect(() => { setActive(0); }, [query]);

  function activate(item) {
    close();
    if (item.tour) {
      window.dispatchEvent(new CustomEvent("heaven:start-tour"));
      return;
    }
    if (item.reload) {
      window.location.reload();
      return;
    }
    if (item.external) {
      const path = item.external;
      if (path.startsWith("/")) {
        window.location.href = path;
      } else {
        window.open(path, "_blank", "noopener");
      }
      return;
    }
    if (item.nav) {
      navigate(item.nav);
      toast.info(`→ ${item.label}`);
    }
  }

  function onKey(ev) {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setActive(a => Math.min(a + 1, items.length - 1));
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setActive(a => Math.max(a - 1, 0));
    } else if (ev.key === "Enter" && items[active]) {
      ev.preventDefault();
      activate(items[active]);
    }
  }

  if (!open) return null;

  // Group items for rendering
  const grouped = items.reduce((acc, it) => {
    (acc[it.group] = acc[it.group] || []).push(it);
    return acc;
  }, {});

  return (
    <div className="cmd-palette-backdrop" onClick={close}>
      <div
        className="cmd-palette"
        role="dialog"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          className="cmd-palette-input"
          placeholder="Type to search pages, actions, help…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKey}
          spellCheck={false}
          autoCorrect="off"
          autoComplete="off"
        />

        <div className="cmd-palette-list">
          {items.length === 0 ? (
            <div className="cmd-palette-empty">
              No matches for <strong>{query}</strong>.
            </div>
          ) : (
            Object.entries(grouped).map(([group, groupItems]) => (
              <div key={group} className="cmd-palette-group">
                <div className="cmd-palette-group-label">{group}</div>
                {groupItems.map((it) => {
                  const idx = items.indexOf(it);
                  return (
                    <button
                      key={it.label}
                      className={"cmd-palette-item" + (idx === active ? " active" : "")}
                      onMouseEnter={() => setActive(idx)}
                      onClick={() => activate(it)}
                      type="button"
                    >
                      <span className="cmd-palette-item-icon">{it.icon}</span>
                      <span className="cmd-palette-item-label">{it.label}</span>
                      {it.hint && (
                        <span className="cmd-palette-item-hint">
                          <kbd>{it.hint}</kbd>
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="cmd-palette-footer">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> navigate <kbd>↵</kbd> select <kbd>esc</kbd> close
          </span>
          <span><kbd>⌘K</kbd> toggle</span>
        </div>
      </div>
    </div>
  );
}
