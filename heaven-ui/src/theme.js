// HEAVEN — shared UI theme helpers.
//
// Single source of truth for severity/grade colours so every page renders the
// same palette (previously each page hand-rolled its own SEV_COLOR map, and the
// "info" colour in particular drifted between #888, var(--text-2) and var(--info)).
// All values are CSS design-token references, so they follow the light/dark theme.

export const SEV_COLOR = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

// Coverage self-grading letter → colour.
export const GRADE_COLOR = {
  A: "var(--brand)",
  B: "var(--cyan)",
  C: "var(--med)",
  D: "var(--high)",
  F: "var(--crit)",
};

// Resolve a severity (case-insensitive) to its token colour, defaulting to info.
export function sevColor(severity) {
  return SEV_COLOR[String(severity || "").toLowerCase()] || SEV_COLOR.info;
}
