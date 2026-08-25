"""
HEAVEN — Dynamic feedback engine (closed-loop scanning).

A linear scan pipeline throws away its own best leads. Later phases keep
surfacing artefacts that are *themselves* fresh attack surface:

* a JavaScript bundle names an ``/api/`` route the crawler never linked to;
* a loot harvest or a leaked config file reveals an internal host;
* a disclosed ``.env`` / backup file leaks a credential pair;
* a reflected response hands back a bearer token or JWT.

The :class:`FeedbackEngine` watches every finding and task result as it lands,
distils each into typed *leads*, and hands the orchestrator the ones it has not
seen before so the discovery is acted on **in the same run** — new hosts get
recon + web-derived, JS endpoints get injection/API-tested, credentials feed the
reuse chain. That is the "make it dynamic" behaviour: the scan reacts to what it
finds instead of only to what the operator typed.

The engine is deliberately *pure* — extraction, scoping, dedup and fan-out caps
only. It never touches the network and never registers tasks itself; the
orchestrator owns that. This keeps it fully unit-testable without a live scan.

Safety invariants:

* **Scope is never widened.** A derived host is emitted only when it is already
  authorised by the operator's targets (an in-scope domain / a subdomain of one
  / an IP inside an in-scope CIDR). A redirect or a loot reference to an
  out-of-scope host is recorded but never actioned.
* **Every lead is processed at most once** (dedup by typed identity), so a chain
  of derivations terminates the moment it stops producing *new* uniques.
* **Hard fan-out caps** on hosts and on total emitted leads are a backstop
  against runaway derivation even if dedup were somehow defeated.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from heaven.utils.logger import get_logger

logger = get_logger("feedback")


# ─────────────────────────────────────────────────────────────────────────────
# Scope guard — authorisation derived from the operator's own targets dict.
# ─────────────────────────────────────────────────────────────────────────────

class ScopeGuard:
    """Decide whether a *newly discovered* host is already in the operator's
    authorised scope. Built from the same ``targets`` dict that seeded the scan
    (``ips`` / ``urls`` / ``domains``), so it can only ever *contain* — it never
    authorises a host broader than what the operator explicitly entered.

    A candidate passes when it is:
      * an exact match of an in-scope host/domain/IP; or
      * an IP address inside an in-scope CIDR (or equal to an in-scope IP); or
      * a subdomain of an in-scope **domain**.

    Crucially, subdomain-wide scope is granted *only* when the operator named a
    domain deliberately — a target in the ``domains`` bucket, or a wildcard/dotted
    target such as ``*.example.com`` / ``.example.com``. A single host or URL
    target (``https://example.com`` / a bare ``example.com`` in the ``ips`` /
    ``urls`` buckets) authorises **exactly that host**, never its whole subdomain
    tree. This stops a one-host engagement from silently expanding into an active
    scan of every discovered subdomain — many of which resolve to third-party
    infrastructure (a mail provider, a CDN, a SaaS) the operator never authorised.
    """

    def __init__(self, targets: dict[str, Any]):
        self._domains: set[str] = set()   # subdomain-wildcard scope (deliberate)
        self._nets: list[ipaddress._BaseNetwork] = []
        self._exact: set[str] = set()     # exact host / IP scope

        def _add_host(raw: str, *, wildcard: bool) -> None:
            raw = (raw or "").strip().lower()
            if not raw:
                return
            if "://" in raw:
                raw = urlparse(raw).hostname or ""
            # An explicit wildcard/dotted target always requests subdomain-wide
            # scope, whatever bucket it arrived in.
            if raw.startswith("*."):
                raw, wildcard = raw[2:], True
            elif raw.startswith("."):
                raw, wildcard = raw[1:], True
            raw = raw.split(":", 1)[0].strip("[]")  # drop :port and IPv6 brackets
            if not raw:
                return
            self._exact.add(raw)
            try:
                self._nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                # A hostname, not an IP/CIDR. It widens scope to its whole
                # subdomain tree ONLY when the operator named it as a domain
                # (the ``domains`` bucket) or with explicit wildcard syntax —
                # never merely because a single URL/host target was entered.
                if wildcard:
                    self._domains.add(raw)

        for ip in targets.get("ips", []) or []:
            _add_host(str(ip), wildcard=False)
        for url in targets.get("urls", []) or []:
            _add_host(str(url), wildcard=False)
        for dom in targets.get("domains", []) or []:
            _add_host(str(dom), wildcard=True)

    def allows_subdomains(self, domain: str) -> bool:
        """True when *arbitrary* subdomains of ``domain`` are in authorised scope.

        This is granted only when the operator deliberately requested
        subdomain-wide scope — a target in the ``domains`` bucket, or an explicit
        ``*.example.com`` / ``.example.com`` — so a bare host / URL target
        (exact-host scope) returns ``False``. Subdomain *discovery* (CT-log +
        DNS brute-force) is gated on this so a one-host engagement never
        enumerates, counts, logs or feeds back its whole subdomain tree — most of
        which is out-of-scope third-party infrastructure the operator never named.
        """
        domain = (domain or "").strip().lower()
        if "://" in domain:
            domain = urlparse(domain).hostname or ""
        domain = domain.split(":", 1)[0].strip("[]")
        if not domain:
            return False
        for dom in self._domains:
            if domain == dom or domain.endswith("." + dom):
                return True
        return False

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower()
        if not host:
            return False
        if "://" in host:
            host = urlparse(host).hostname or ""
        host = host.split(":", 1)[0].strip("[]")
        if not host:
            return False
        if host in self._exact:
            return True
        # IP containment
        try:
            probe = ipaddress.ip_network(host, strict=False)
            for net in self._nets:
                try:
                    if probe.subnet_of(net):  # type: ignore[arg-type]
                        return True
                except TypeError:
                    continue  # mixed IPv4/IPv6 — not comparable
            return False
        except ValueError:
            pass
        # Subdomain of an in-scope domain
        for dom in self._domains:
            if host == dom or host.endswith("." + dom):
                return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Leads
# ─────────────────────────────────────────────────────────────────────────────

# Lead kinds.
HOST = "host"
URL = "url"
CRED = "cred"
TOKEN = "token"  # nosec B105 — a lead-kind label, not a hardcoded credential


@dataclass(frozen=True)
class Lead:
    """A single, deduplicated follow-on scan input distilled from a result."""
    kind: str
    value: Any            # str for host/url/token; (user, password) tuple for cred
    source: str = ""      # human label of where it came from
    generation: int = 0   # derivation depth (seed input = 0)

    @property
    def identity(self) -> tuple[str, str]:
        if self.kind == CRED and isinstance(self.value, (tuple, list)):
            return (self.kind, f"{self.value[0]}:{self.value[1]}")
        return (self.kind, str(self.value).lower())


# A JWT: three base64url segments separated by dots, first byte decodes to '{'.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
# A bearer token in an Authorization header value we captured in evidence.
_BEARER_RE = re.compile(r"[Bb]earer\s+([A-Za-z0-9._~+/=-]{12,})")


class FeedbackEngine:
    """Distil task results / findings into fresh, deduplicated, in-scope leads.

    Usage (owned by the orchestrator)::

        eng = FeedbackEngine(targets)
        eng.ingest_result(task_data, generation=0)
        eng.ingest_finding(finding, generation=0)
        for lead in eng.drain():        # only leads never returned before
            ...act on lead...

    ``drain`` is idempotent between calls: a lead is returned exactly once, so
    the orchestrator can call the ingest/drain cycle after every phase.
    """

    MAX_HOSTS = 64          # cap distinct derived hosts actioned per scan
    MAX_LEADS = 1000        # global backstop on emitted leads
    MAX_GENERATIONS = 4     # stop deriving leads-from-leads-from-… past this

    def __init__(self, targets: Optional[dict[str, Any]] = None,
                 max_generations: int = MAX_GENERATIONS):
        self.scope = ScopeGuard(targets or {})
        self._seen: set[tuple[str, str]] = set()
        self._pending: list[Lead] = []          # not yet drained
        self._host_count = 0
        self._emitted = 0
        self._max_generations = max_generations
        # Hosts already assessed this run — the operator's seed targets plus any
        # host we've since emitted a follow-up for. A host in here is NEVER
        # re-emitted as a lead: it was already deep-scanned, so re-scanning it is
        # pure waste. This is what stops the DYNAMIC_FOLLOWUP phase from queuing a
        # redundant full re-scan of the seed host (every finding carries the seed
        # as its ``target``, and the network result lists it under ``hosts``),
        # which froze scans for ~90s at ~44% while thousands of ports were
        # re-probed for zero new findings. Genuinely-new hosts (DNS subdomains,
        # loot references, redirects to *other* hosts) are not in here, so their
        # follow-up is unaffected.
        self._known_hosts: set[str] = self._collect_seed_hosts(targets or {})
        # Recorded for the scan summary / operator visibility (deduped).
        self.hosts: list[str] = []
        self.urls: list[str] = []
        self.creds: list[tuple[str, str]] = []
        self.tokens: list[str] = []
        self.out_of_scope_hosts: list[str] = []

    # ── host bookkeeping ───────────────────────────────────────────────────────

    @staticmethod
    def _norm_host(raw: str) -> str:
        """Normalise a host reference to a bare lowercase hostname/IP — drop the
        scheme, any ``:port`` and IPv6 brackets — so seed / already-scanned
        comparisons match regardless of the form a lead arrived in
        (``http://h:80`` and ``h`` must compare equal)."""
        raw = (raw or "").strip().lower()
        if "://" in raw:
            raw = urlparse(raw).hostname or ""
        return raw.split(":", 1)[0].strip("[]")

    @classmethod
    def _collect_seed_hosts(cls, targets: dict[str, Any]) -> set[str]:
        """The operator's seed hosts (from ``ips`` / ``urls`` / ``domains``),
        normalised — these were named explicitly and are scanned by the main
        pipeline, so the feedback loop must never re-queue them."""
        known: set[str] = set()
        for key in ("ips", "urls", "domains"):
            for t in targets.get(key, []) or []:
                h = cls._norm_host(str(t))
                if h:
                    known.add(h)
        return known

    # ── emission ─────────────────────────────────────────────────────────────

    def _emit(self, kind: str, value: Any, source: str, generation: int) -> Optional[Lead]:
        if generation > self._max_generations or self._emitted >= self.MAX_LEADS:
            return None
        lead = Lead(kind=kind, value=value, source=source, generation=generation)
        ident = lead.identity
        if ident in self._seen:
            return None

        if kind == HOST:
            host = self._norm_host(str(value))
            if not host:
                return None
            if not self.scope.allows(host):
                if host not in self.out_of_scope_hosts:
                    self.out_of_scope_hosts.append(host)
                    logger.debug(f"feedback: dropping out-of-scope host {host}")
                return None
            if host in self._known_hosts:
                # Already scanned this run (a seed target, or a host we've already
                # followed up) — skip it so we never re-scan an already-assessed
                # host. Without this the seed host, echoed back as every finding's
                # ``target`` and in the network result's ``hosts``, was re-queued
                # for a full DYNAMIC_FOLLOWUP re-scan (the ~90s "stuck at 44%,
                # nothing new" symptom).
                logger.debug(f"feedback: host {host} already scanned — no re-scan")
                return None
            if self._host_count >= self.MAX_HOSTS:
                return None
            self._host_count += 1
            self._known_hosts.add(host)   # so a later reference can't re-queue it
            self.hosts.append(host)
        elif kind == URL:
            self.urls.append(str(value))
        elif kind == CRED:
            self.creds.append((str(value[0]), str(value[1])))
        elif kind == TOKEN:
            self.tokens.append(str(value))

        self._seen.add(ident)
        self._pending.append(lead)
        self._emitted += 1
        return lead

    def drain(self) -> list[Lead]:
        """Return leads emitted since the last drain, then clear the buffer."""
        out = self._pending
        self._pending = []
        return out

    # ── ingest: task result dict ─────────────────────────────────────────────

    def ingest_result(self, data: Any, generation: int = 0, source: str = "") -> list[Lead]:
        """Extract leads from one task's result ``data`` dict."""
        if not isinstance(data, dict):
            return []
        out: list[Lead] = []

        # New hosts from recon / DNS / cert SANs / redirects.
        for host_obj in data.get("hosts", []) or []:
            h = host_obj.get("host") or host_obj.get("ip") if isinstance(host_obj, dict) else host_obj
            if h:
                self._maybe(out, HOST, str(h), source or "recon", generation)
        for key in ("subdomains", "hostnames", "new_hosts", "resolved_hosts"):
            for h in data.get(key, []) or []:
                name = h.get("host") if isinstance(h, dict) else h
                if name:
                    self._maybe(out, HOST, str(name), source or key, generation)

        # JS-derived + crawler endpoints → URL leads (already absolute).
        for u in data.get("js_endpoints", []) or []:
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                self._maybe(out, URL, u, source or "js_bundle", generation)
        for ep in data.get("endpoints", []) or []:
            url = ep.get("url") if isinstance(ep, dict) else ep
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                self._maybe(out, URL, url, source or "crawl", generation)

        # Credentials from disclosure / config / loot scanners.
        for cred in data.get("credentials", []) or []:
            if isinstance(cred, dict) and cred.get("username") and cred.get("password"):
                self._maybe(out, CRED, (cred["username"], cred["password"]),
                            source or "credentials", generation)
        for s in data.get("secrets_list", []) or []:
            if isinstance(s, dict) and s.get("username") and s.get("password"):
                self._maybe(out, CRED, (s["username"], s["password"]),
                            source or "secrets", generation)

        # Tokens surfaced anywhere in the structured result.
        self._scan_text_for_tokens(data, out, source or "result", generation)
        return out

    # ── ingest: a single finding dict ────────────────────────────────────────

    def ingest_finding(self, finding: Any, generation: int = 0) -> list[Lead]:
        if not isinstance(finding, dict):
            return []
        out: list[Lead] = []
        # A finding may reference a fresh host in its target/url.
        for key in ("target", "url", "host"):
            val = finding.get(key)
            if isinstance(val, str) and val:
                host = urlparse(val).hostname if "://" in val else val.split(":", 1)[0]
                if host:
                    self._maybe(out, HOST, str(host), f"finding:{finding.get('vuln_type', key)}",
                                generation)
        # Tokens leaked in evidence / description text.
        blob = " ".join(
            str(finding.get(k, "")) for k in ("evidence", "description", "detail", "proof")
        )
        self._scan_blob_for_tokens(blob, out, "finding", generation)
        return out

    # ── token helpers ────────────────────────────────────────────────────────

    def _scan_text_for_tokens(self, data: dict, out: list[Lead], source: str,
                              generation: int) -> None:
        # Walk shallow string values + common evidence containers for tokens.
        blobs: list[str] = []
        for v in data.values():
            if isinstance(v, str):
                blobs.append(v)
            elif isinstance(v, dict):
                blobs.extend(str(x) for x in v.values() if isinstance(x, (str, int)))
        self._scan_blob_for_tokens(" ".join(blobs), out, source, generation)

    def _scan_blob_for_tokens(self, blob: str, out: list[Lead], source: str,
                              generation: int) -> None:
        if not blob:
            return
        for m in _JWT_RE.findall(blob):
            self._maybe(out, TOKEN, m, f"{source}:jwt", generation)
        for m in _BEARER_RE.findall(blob):
            if not m.lower().startswith("eyj"):  # JWTs already captured above
                self._maybe(out, TOKEN, m, f"{source}:bearer", generation)

    # ── internal ─────────────────────────────────────────────────────────────

    def _maybe(self, out: list[Lead], kind: str, value: Any, source: str,
               generation: int) -> None:
        lead = self._emit(kind, value, source, generation)
        if lead is not None:
            out.append(lead)

    # ── summary ──────────────────────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        return {
            "derived_hosts": list(self.hosts),
            "derived_urls_count": len(self.urls),
            "derived_creds_count": len(self.creds),
            "derived_tokens_count": len(self.tokens),
            "out_of_scope_dropped": list(self.out_of_scope_hosts),
        }


# ─────────────────────────────────────────────────────────────────────────────
# JS bundle → absolute endpoint resolution (shared by the crawler + orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

# Reject obvious non-endpoint noise captured by the greedy regex patterns:
# jQuery event names, MIME types, template placeholders, protocol-relative CDNs.
_JS_NOISE = re.compile(r"[\s<>{}$`]|^(?:text|image|application)/|\.(?:png|jpe?g|gif|svg|css|woff2?)$")


def resolve_js_endpoint(raw: str, source_js_url: str) -> Optional[str]:
    """Resolve one raw JS-extracted endpoint string to an absolute, same-origin
    URL, or ``None`` if it isn't a plausible in-origin endpoint.

    Only same-origin results survive: an endpoint referenced by
    ``https://app.tld/static/main.js`` resolves against ``https://app.tld``.
    A path pointing at a third-party host is dropped (scope safety + noise).
    """
    raw = (raw or "").strip().strip("'\"")
    if not raw or _JS_NOISE.search(raw):
        return None
    origin = urlparse(source_js_url)
    if not origin.scheme or not origin.netloc:
        return None
    if raw.startswith(("http://", "https://")):
        target = urlparse(raw)
        if target.netloc.lower() != origin.netloc.lower():
            return None  # third-party endpoint — out of scope
        return raw.split("#", 1)[0]
    if raw.startswith("/"):
        return urljoin(f"{origin.scheme}://{origin.netloc}", raw).split("#", 1)[0]
    return None  # bare word (event name, variable) — not an endpoint
