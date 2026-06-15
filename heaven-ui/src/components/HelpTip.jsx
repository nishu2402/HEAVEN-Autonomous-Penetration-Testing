// HEAVEN — HelpTip: a small "?" icon with an on-hover/focus explanation.
//
// Demystifies the security jargon a non-expert operator hits (CVSS, EPSS,
// confidence, kill-chain phases…) without cluttering the UI. Keyboard- and
// screen-reader-accessible (focusable, aria-label carries the text).
//
// Usage:  <HelpTip term="cvss" />   or   <HelpTip text="custom explanation" />

import React from "react";

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

export default function HelpTip({ term, text, children }) {
  const content = text || (term && TERMS[term]) || "";
  return (
    <span className="helptip" tabIndex={0} role="note" aria-label={content}>
      <span className="helptip-icon" aria-hidden="true">{children || "?"}</span>
      <span className="helptip-bubble" role="tooltip">{content}</span>
    </span>
  );
}
