"""HEAVEN — regression tests for two operator-reported false positives.

1. A single URL/host target must authorise ONLY that host — not its whole
   subdomain tree — so a one-host engagement never silently expands into an
   active scan of discovered subdomains (many on third-party infrastructure).
   Subdomain-wide scope requires a deliberate domain target.

2. A catch-all / soft-404 server that redirects (or 200-serves) every unknown
   path to its homepage must NOT yield "SENSITIVE_FILE" hits (dir_fuzzer) nor be
   "confirmed" as exposed (confirm.py). The classic case: ``/phpmyadmin/`` on a
   framework whose catch-all serves the homepage.
"""

from __future__ import annotations

import pytest

from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════
# Issue A — scope: a URL/host seed authorises only that exact host
# ═══════════════════════════════════════════════════════════════════════════

def test_url_seed_does_not_authorise_subdomains():
    from heaven.feedback import ScopeGuard
    g = ScopeGuard({"urls": ["https://nehemiah.co.uk"]})
    assert g.allows("nehemiah.co.uk")                 # the exact seed host
    assert not g.allows("www.nehemiah.co.uk")         # a subdomain — NOT authorised
    assert not g.allows("autodiscover.nehemiah.co.uk")  # third-party (M365) infra
    assert not g.allows("remote.nehemiah.co.uk")


def test_bare_host_in_ips_bucket_is_exact_only():
    from heaven.feedback import ScopeGuard
    g = ScopeGuard({"ips": ["example.com"]})
    assert g.allows("example.com")
    assert not g.allows("api.example.com")


def test_domains_bucket_grants_subdomain_scope():
    from heaven.feedback import ScopeGuard
    g = ScopeGuard({"domains": ["example.com"]})
    assert g.allows("example.com")
    assert g.allows("api.example.com")                # deliberate domain → subs OK
    assert not g.allows("example.org")


def test_wildcard_and_dotted_targets_grant_subdomain_scope():
    from heaven.feedback import ScopeGuard
    for tgt in ("*.example.com", ".example.com"):
        g = ScopeGuard({"urls": [tgt]})
        assert g.allows("example.com"), tgt
        assert g.allows("deep.api.example.com"), tgt


def test_feedback_drops_out_of_scope_subdomains_from_url_seed():
    from heaven.feedback import FeedbackEngine, HOST
    eng = FeedbackEngine({"urls": ["https://nehemiah.co.uk"]})
    eng.ingest_result({"subdomains": [
        {"host": "www.nehemiah.co.uk"},
        {"host": "autodiscover.nehemiah.co.uk"},
        {"host": "remote.nehemiah.co.uk"},
    ]})
    host_leads = [ld.value for ld in eng.drain() if ld.kind == HOST]
    assert host_leads == []            # nothing actively scanned
    assert "www.nehemiah.co.uk" in eng.out_of_scope_hosts
    assert "autodiscover.nehemiah.co.uk" in eng.out_of_scope_hosts


def test_feedback_follows_subdomains_only_for_domain_target():
    from heaven.feedback import FeedbackEngine, HOST
    eng = FeedbackEngine({"domains": ["example.com"]})
    eng.ingest_result({"subdomains": [{"host": "api.example.com"}]})
    host_leads = [ld.value for ld in eng.drain() if ld.kind == HOST]
    assert "api.example.com" in host_leads


# ═══════════════════════════════════════════════════════════════════════════
# Issue A — subdomain DISCOVERY (not just scanning) is gated by scope, so a
# one-host engagement never enumerates / counts / logs its whole subdomain tree.
# ═══════════════════════════════════════════════════════════════════════════

def test_allows_subdomains_only_for_deliberate_domain_scope():
    from heaven.feedback import ScopeGuard
    # A bare URL / host seed — exact-host scope — must NOT authorise the tree.
    url_seed = ScopeGuard({"urls": ["https://nehemiah.co.uk"]})
    assert not url_seed.allows_subdomains("nehemiah.co.uk")
    assert not url_seed.allows_subdomains("https://nehemiah.co.uk")
    host_seed = ScopeGuard({"ips": ["example.com"]})
    assert not host_seed.allows_subdomains("example.com")
    # A deliberate domain / wildcard target DOES authorise the tree.
    dom = ScopeGuard({"domains": ["example.com"]})
    assert dom.allows_subdomains("example.com")
    assert dom.allows_subdomains("api.example.com")       # sub of an in-scope domain
    assert not dom.allows_subdomains("example.org")
    for tgt in ("*.example.com", ".example.com"):
        assert ScopeGuard({"urls": [tgt]}).allows_subdomains("example.com"), tgt


def test_wants_subdomains_bool_and_set():
    from heaven.recon.dns_recon import _wants_subdomains
    # A plain bool applies to every domain (CLI / direct-caller behaviour).
    assert _wants_subdomains(True, "example.com") is True
    assert _wants_subdomains(False, "example.com") is False
    # A set confines the brute-force to the authorised subdomain scope.
    assert _wants_subdomains({"example.com"}, "example.com") is True
    assert _wants_subdomains({"example.com"}, "other.com") is False
    assert _wants_subdomains(set(), "example.com") is False


def test_dns_recon_targets_confines_subdomain_bruteforce_to_scope(monkeypatch):
    """Records are enumerated for every domain; the subdomain brute-force runs
    only for domains in the authorised subdomain-scope set."""
    import asyncio

    from heaven.recon import dns_recon

    seen: dict[str, bool] = {}

    async def fake_enumerate_dns(domain, *, subdomains=True, **_k):
        seen[domain] = subdomains
        return {"domain": domain, "records": {}, "subdomains": []}

    async def fake_recon(domain, **_k):
        return {"findings": []}

    monkeypatch.setattr(dns_recon, "enumerate_dns", fake_enumerate_dns)
    monkeypatch.setattr(dns_recon, "dns_recon", fake_recon)

    asyncio.run(dns_recon.dns_recon_targets(
        ["in-scope.com", "out-of-scope.com"], subdomains={"in-scope.com"}))
    assert seen["in-scope.com"] is True        # authorised → brute-forced
    assert seen["out-of-scope.com"] is False   # records only, no subdomain sweep


# ═══════════════════════════════════════════════════════════════════════════
# Issue B — dir_fuzzer: catch-all suppression + honest severity/titles
# ═══════════════════════════════════════════════════════════════════════════

class _Resp:
    def __init__(self, status, body, headers=None, url=""):
        self.status = status
        self._body = body
        self.headers = headers or {}
        self.url = urlparse(url) if url else urlparse("http://t/")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body


class _RedirectCatchAllSession:
    """Every unknown path 302-redirects to the homepage; the homepage is a big
    200. ``allow_redirects=False`` sees the 302; ``True`` sees the final 200."""
    HOME = "<html><title>Welcome</title>" + "h" * 800 + "</html>"

    def __init__(self, real: dict | None = None):
        # real: {path: (status, body)} for genuinely-existing paths (no redirect).
        self._real = real or {}

    def get(self, url, headers=None, allow_redirects=False, **kw):
        path = urlparse(url).path
        if path in ("", "/"):
            return _Resp(200, self.HOME, url="http://t/")
        if path in self._real:
            status, body = self._real[path]
            return _Resp(status, body, url=url)
        # Unknown path → catch-all redirect to home.
        if allow_redirects:
            return _Resp(200, self.HOME, url="http://t/")
        return _Resp(302, "redir", headers={"Location": "http://t/"}, url=url)


@pytest.mark.asyncio
async def test_dir_fuzzer_drops_redirect_to_home_catchall():
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fz = DirectoryFuzzer()
    session = _RedirectCatchAllSession()
    wc = await fz._detect_wildcard(session, "http://t")
    assert wc is not None
    # phpMyAdmin / adminer probes redirect to home → dropped, not a hit.
    for p in ("phpmyadmin", "phpmyadmin/", "adminer.php", "admin", "backup.zip"):
        assert await fz._probe(session, f"http://t/{p}", wc) is None, p


@pytest.mark.asyncio
async def test_dir_fuzzer_real_served_file_survives_redirect_catchall():
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fz = DirectoryFuzzer()
    # A genuinely-served .env (200 with a distinct body) on an otherwise
    # redirect-to-home catch-all must still be reported — and as critical.
    session = _RedirectCatchAllSession(real={"/.env": (200, "DB_PASSWORD=secret\nKEY=v\n")})
    wc = await fz._detect_wildcard(session, "http://t")
    r = await fz._probe(session, "http://t/.env", wc)
    assert r is not None and r["severity"] == "critical"
    assert "exposed" in r["title"].lower()


@pytest.mark.asyncio
async def test_dir_fuzzer_403_is_low_and_not_titled_exposed():
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fz = DirectoryFuzzer()
    # A 403 on .env means it is BLOCKED (secure), not exposed.
    session = _RedirectCatchAllSession(real={"/.env": (403, "Forbidden")})
    wc = await fz._detect_wildcard(session, "http://t")
    r = await fz._probe(session, "http://t/.env", wc)
    assert r is not None
    assert r["severity"] == "low"
    assert "exposed" not in r["title"].lower()
    assert "access-controlled" in r["title"].lower()


def test_severity_for_is_status_aware():
    from heaven.vulnscan.dir_fuzzer import _severity_for
    assert _severity_for("/.env", 200) == "critical"     # actually served
    assert _severity_for("/.env", 403) == "low"          # blocked
    assert _severity_for("/admin", 200) == "high"
    assert _severity_for("/admin", 302) == "info"        # redirects → discovery
    assert _severity_for("/anything", 401) == "low"


def test_gitignore_is_not_an_exposed_git_directory():
    """A served /.gitignore (or .gitattributes / .github) merely shares the
    ".git" prefix — it is NOT the VCS directory. It must not be rated critical or
    titled 'Exposed .git directory'. Only the real repo (/.git, /.git/config) is."""
    from heaven.vulnscan.dir_fuzzer import _severity_for, _path_title, _is_git_vcs_path
    assert _is_git_vcs_path("/.git") is True
    assert _is_git_vcs_path("/.git/config") is True
    assert _is_git_vcs_path("/.gitignore") is False
    assert _is_git_vcs_path("/.github/workflows/ci.yml") is False
    assert _severity_for("/.gitignore", 200) == "info"
    assert "Exposed .git directory" not in _path_title("/.gitignore", 200, served=True)
    # The real repo is still critical (regression guard, not a downgrade).
    assert _severity_for("/.git/config", 200) == "critical"
    assert _path_title("/.git", 200, served=True) == "Exposed .git directory (200)"


def test_generic_login_page_is_not_high_severity():
    """Every app has a login page; discovering /login.php is expected surface, not
    a high-severity 'sensitive path'. Real admin panels stay high via 'admin'."""
    from heaven.vulnscan.dir_fuzzer import _severity_for
    assert _severity_for("/login.php", 200) == "info"
    assert _severity_for("/user/login", 200) == "info"
    assert _severity_for("/admin", 200) == "high"          # admin panel still high
    assert _severity_for("/wp-admin", 200) == "high"


# ═══════════════════════════════════════════════════════════════════════════
# Issue B — confirm.py: catch-all / redirect-home / missing-signature → not confirmed
# ═══════════════════════════════════════════════════════════════════════════

def _patch_confirm(monkeypatch, *, real_status=200, real_body="", real_final=None,
                   junk_status=200, junk_body=""):
    from heaven.vulnscan import confirm

    def _is_junk(url: str) -> bool:
        return "heaven-" in url or url.endswith(".nope")

    async def _final(_s, _u, **_k):
        if _is_junk(_u):
            return junk_status, {}, junk_body, _u
        return real_status, {}, real_body, (real_final or _u)

    monkeypatch.setattr(confirm, "_http_get_final", _final)


@pytest.mark.asyncio
async def test_confirm_endpoint_catchall_body_not_confirmed(monkeypatch):
    from heaven.vulnscan.confirm import confirm_finding, UNCONFIRMED
    # The endpoint AND a random sibling return the same homepage body → catch-all.
    home = "<html><title>Welcome</title>" + "h" * 500 + "</html>"
    _patch_confirm(monkeypatch, real_body=home, junk_body=home)
    f = {"vuln_type": "sensitive_file", "title": "phpMyAdmin exposed",
         "target": "https://t/phpmyadmin/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False
    assert "catch-all" in out["summary"].lower() or "soft-404" in out["summary"].lower()


@pytest.mark.asyncio
async def test_confirm_endpoint_redirected_home_not_confirmed(monkeypatch):
    from heaven.vulnscan.confirm import confirm_finding, UNCONFIRMED
    # Distinct bodies, but the endpoint lands on the site root after redirects.
    _patch_confirm(monkeypatch, real_body="<html>home</html>",
                   real_final="https://t/", junk_body="nope-404")
    f = {"vuln_type": "sensitive_file", "target": "https://t/phpmyadmin", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False


@pytest.mark.asyncio
async def test_confirm_endpoint_tool_signature_required(monkeypatch):
    from heaven.vulnscan.confirm import confirm_finding, UNCONFIRMED
    # Served 200 at its own URL, distinct from junk, but the body is not phpMyAdmin.
    _patch_confirm(monkeypatch, real_body="<html>Company homepage</html>",
                   junk_body="nope-404")
    f = {"vuln_type": "sensitive_file", "target": "https://t/phpmyadmin/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False
    assert "not phpmyadmin" in out["summary"].lower() or "signature" in out["detail"].lower()


@pytest.mark.asyncio
async def test_confirm_endpoint_genuine_phpmyadmin_confirmed(monkeypatch):
    from heaven.vulnscan.confirm import confirm_finding, CONFIRMED
    body = "<html><title>phpMyAdmin</title>pma_ set_session login</html>"
    _patch_confirm(monkeypatch, real_body=body, junk_body="nope-404")
    f = {"vuln_type": "sensitive_file", "target": "https://t/phpmyadmin/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True


# ═══════════════════════════════════════════════════════════════════════════
# Issue A — deep_recon: CT-log names are liveness-verified before surfacing
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ct_log_subdomains_liveness_filtered(monkeypatch):
    import heaven.recon.deep_recon as dr

    async def _fake_ct(domain, session):
        return [f"live.{domain}", f"dead.{domain}"]

    async def _fake_wildcard(domain):
        return None

    async def _fake_resolve(fqdn, sem):
        if fqdn.startswith("live."):
            return dr.DiscoveredAsset(asset_type="subdomain", value=fqdn,
                                      source="dns_bruteforce", metadata={"ip": "1.2.3.4"})
        return None  # 'dead.*' no longer resolves

    monkeypatch.setattr(dr, "_ct_log_search", _fake_ct)
    monkeypatch.setattr(dr, "_check_wildcard_dns", _fake_wildcard)
    monkeypatch.setattr(dr, "_resolve_subdomain", _fake_resolve)

    subs = await dr.enumerate_subdomains("example.com", session=None, wordlist=[])
    values = {s.value for s in subs}
    assert "live.example.com" in values
    assert "dead.example.com" not in values     # dead CT ghost dropped
