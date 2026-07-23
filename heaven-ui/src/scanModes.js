// HEAVEN — single source of truth for the scan surfaces the UI exposes.
//
// Both the Scans launcher (the <select>) and the Dashboard quick-launch grid
// read from here, so the two can never drift apart. Every entry in SCAN_MODES
// is backed by a REAL scanner phase that runs inside build_full_scan() — the
// mode is a label naming the surface you're primarily assessing, and FULL runs
// them all. Keep this in lockstep with heaven/config.py::ScanMode.

export const SCAN_MODES = [
  { value: "full",      icon: "🛰️", short: "Full",      title: "FULL — every module (recommended)",
    desc: "Runs every scanner phase end-to-end" },
  { value: "web",       icon: "🌐", short: "Web app",   title: "WEB — web application",
    desc: "OWASP web-app assessment" },
  { value: "network",   icon: "🖧",  short: "Network",   title: "NETWORK — hosts & services",
    desc: "Hosts, ports & service CVEs" },
  { value: "wireless",  icon: "📶", short: "Wireless",  title: "WIRELESS — AP / controller config review",
    desc: "Exposed AP / router / WLAN admin panels" },
  { value: "api",       icon: "🔌", short: "API",       title: "API — REST / GraphQL security",
    desc: "REST & GraphQL endpoint testing" },
  { value: "cloud",     icon: "☁️", short: "Cloud",     title: "CLOUD — cloud assets & public buckets",
    desc: "Cloud posture & public buckets" },
  { value: "container", icon: "📦", short: "Container", title: "CONTAINER — Docker / Kubernetes",
    desc: "Docker & Kubernetes exposure" },
  { value: "iot",       icon: "📡", short: "IoT",       title: "IOT — IoT / SCADA devices",
    desc: "IoT & smart-device surface" },
  { value: "ot",        icon: "🏭", short: "OT",        title: "OT — operational technology",
    desc: "ICS / SCADA / operational tech" },
  { value: "ad",        icon: "🗝️", short: "AD",        title: "AD — Active Directory",
    desc: "Active Directory & domain" },
  { value: "email",     icon: "✉️", short: "Email",     title: "EMAIL — SPF / DMARC / DKIM posture",
    desc: "SPF / DMARC / DKIM posture" },
];

// Static-analysis tools live on their own pages (they persist into the active
// engagement like a scan, but don't take a network target). Surfaced on the
// dashboard alongside the active-scan modes so every capability is one click
// away from the landing page.
export const ANALYSIS_TOOLS = [
  { to: "/sast", icon: "🔬", short: "SAST",  desc: "Static source-code analysis (Semgrep)" },
  { to: "/sca",  icon: "📦", short: "SCA",   desc: "Dependency audit vs. OSV.dev" },
  { to: "/cve",  icon: "🛡️", short: "CVE",   desc: "Live CVE lookup (NVD + CIRCL)" },
];

// Long-form options for the launcher <select>.
export const MODE_OPTIONS = SCAN_MODES.map((m) => ({ value: m.value, label: m.title }));

// Valid mode values, for validating a ?mode= query param.
export const MODE_VALUES = new Set(SCAN_MODES.map((m) => m.value));
