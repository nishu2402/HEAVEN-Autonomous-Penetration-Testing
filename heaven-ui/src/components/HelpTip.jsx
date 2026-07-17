// HEAVEN — HelpTip: a small "?" icon with an on-hover/focus/tap explanation.
//
// Demystifies the security jargon a non-expert operator hits (CVSS, EPSS,
// confidence, kill-chain phases…) without cluttering the UI. Keyboard- and
// screen-reader-accessible (focusable, aria-label carries the text).
//
// The bubble is rendered through a PORTAL to <body> with fixed positioning
// instead of being an absolutely-positioned child. That is deliberate: the
// tooltip is frequently used inside cards / stat tiles that set
// `overflow: hidden` (for their top accent bar and glow), which used to CLIP
// the bubble so the help text was cut off or bled across neighbouring tiles.
// A portal escapes every ancestor's clipping/stacking context, so the text is
// always fully visible, above everything, on every page. Tap also works, so it
// is usable on touch devices that have no hover.
//
// Usage:  <HelpTip term="cvss" />   or   <HelpTip text="custom explanation" />

import React, { useCallback, useRef, useState } from "react";
import { createPortal } from "react-dom";

// Canonical glossary — keep definitions short and operator-friendly.
export const TERMS = {
  cvss: "CVSS — Common Vulnerability Scoring System (0–10 severity). HEAVEN predicts a CVSS v3 base score for every finding with its ML model (R²=0.99).",
  epss: "EPSS — Exploit Prediction Scoring System: the probability (0–1) a vulnerability will be exploited in the wild within ~30 days.",
  kev: "CISA KEV — the Known Exploited Vulnerabilities catalog. Membership means the vuln is actively being exploited right now.",
  severity: "Severity — the impact band (critical → high → medium → low → info), derived from the CVSS score.",
  confidence: "Confidence — how sure HEAVEN is the finding is real (0–1). Results below ~0.40 are dropped by the false-positive suppression pass.",
  risk_score: "Risk score — the CVSS score adjusted by EPSS exploit-probability, CISA-KEV membership, and the target's asset-criticality multiplier.",
  killchain: "Cyber Kill Chain — Lockheed Martin's 7 attack phases (Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions). HEAVEN maps each finding to a phase.",
  mitre: "MITRE ATT&CK — a knowledge base of real-world attacker techniques. Each finding is tagged with the techniques it enables.",
  coverage: "Coverage — how much of the OWASP Top 10 / attack surface this engagement has exercised, as a graded percentage.",
  criticality: "Asset criticality — how important a target is (low → crown_jewel). It multiplies a finding's risk score so crown-jewel issues rank higher.",
};

const BUBBLE_MAX_W = 260;
const GAP = 8;

export default function HelpTip({ term, text, children }) {
  const content = text || (term && TERMS[term]) || "";
  const anchorRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0, placement: "top" });

  const place = useCallback(() => {
    const el = anchorRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    // Prefer above the icon; flip below when there isn't room near the top.
    const placement = r.top < 120 ? "bottom" : "top";
    // Centre on the icon, then clamp so a max-width bubble stays on-screen.
    const half = BUBBLE_MAX_W / 2;
    const left = Math.min(
      Math.max(r.left + r.width / 2, half + GAP),
      window.innerWidth - half - GAP,
    );
    const top = placement === "top" ? r.top - GAP : r.bottom + GAP;
    setPos({ top, left, placement });
  }, []);

  const show = useCallback(() => { place(); setOpen(true); }, [place]);
  const hide = useCallback(() => setOpen(false), []);

  if (!content) return null;

  return (
    <span
      className="helptip"
      ref={anchorRef}
      tabIndex={0}
      role="note"
      aria-label={content}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      onClick={(e) => { e.stopPropagation(); e.preventDefault(); show(); }}
    >
      <span className="helptip-icon" aria-hidden="true">{children || "?"}</span>
      {open && createPortal(
        <span
          className={`helptip-portal helptip-portal--${pos.placement}`}
          role="tooltip"
          style={{ top: pos.top, left: pos.left }}
        >
          {content}
        </span>,
        document.body,
      )}
    </span>
  );
}
