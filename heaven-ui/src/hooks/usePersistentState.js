import { useEffect, useState } from "react";

// Drop-in replacement for useState that persists to sessionStorage under `key`.
//
// Why: page-level state (e.g. the Findings filter selection) is lost when you
// navigate to a detail page and back, because the list component unmounts and
// remounts at its defaults. Backing it with sessionStorage makes the choice
// survive in-tab navigation and reloads, while still resetting when the tab is
// closed. Falls back to plain in-memory state if storage is unavailable
// (private mode / quota), so it never throws.
export default function usePersistentState(key, initial) {
  const [value, setValue] = useState(() => {
    try {
      const raw = sessionStorage.getItem(key);
      if (raw != null) return JSON.parse(raw);
    } catch { /* storage unavailable or malformed, use the default */ }
    return initial;
  });

  useEffect(() => {
    try {
      sessionStorage.setItem(key, JSON.stringify(value));
    } catch { /* storage full/unavailable, keep working in-memory */ }
  }, [key, value]);

  return [value, setValue];
}
