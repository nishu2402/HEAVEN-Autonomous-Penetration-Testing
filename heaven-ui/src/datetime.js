// Human-facing time helpers. Every timestamp HEAVEN stores is UTC; the browser
// knows where the operator actually is, so these render in the viewer's own
// timezone with zero configuration. A user in India sees IST, a user in the UK
// sees GMT or BST, automatically.

// The viewer's resolved IANA zone (e.g. "Asia/Kolkata"), or "" if unavailable.
export function localZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    return "";
  }
}

// A short, self-describing label for the viewer's zone: the abbreviation the
// platform gives ("IST", "BST") or an offset like "GMT+5:30". Empty on failure.
export function tzLabel(date = new Date()) {
  try {
    const parts = new Intl.DateTimeFormat([], { timeZoneName: "short" })
      .formatToParts(date);
    const tz = parts.find((p) => p.type === "timeZoneName");
    return tz ? tz.value : "";
  } catch {
    return "";
  }
}

// Local wall-clock time of day, e.g. "18:30:05". Replaces the old
// toISOString().slice(11,19), which always showed UTC regardless of location.
export function localClock(date = new Date()) {
  try {
    return date.toLocaleTimeString([], {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  } catch {
    return date.toISOString().slice(11, 19);
  }
}

// Local date + time for a stored UTC/ISO string, e.g. "23 Sep 2026, 18:30".
// Returns "—" for empty input and echoes an unparseable value unchanged.
export function fmtWhen(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}
