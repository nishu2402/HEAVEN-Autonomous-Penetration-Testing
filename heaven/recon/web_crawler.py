"""
HEAVEN — Async Web Crawler
Maps endpoints, extracts JS files, identifies input vectors, and fingerprints technology.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from heaven.recon.evasion_engine import EvasionEngine, EvasionProfile, StealthLevel
from heaven.utils.logger import get_logger

logger = get_logger("recon.web")


@dataclass
class WebEndpoint:
    url: str
    status_code: int = 0
    content_type: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    input_vectors: list[dict] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


JS_ENDPOINT_PATTERNS = [
    r"""['"](/api/[^'"]+)['"]""",
    r"""fetch\(['"](/?[^'"]+)['"]""",
    r"""\.(?:get|post|put|delete)\(['"](/?[^'"]+)['"]""",
    r"""endpoint['":\s]+['"](/?[^'"]+)['"]""",
]

TECH_FINGERPRINTS = {
    "X-Powered-By": {"Express": "Express.js", "PHP": "PHP", "ASP.NET": "ASP.NET"},
    "Server": {"nginx": "Nginx", "Apache": "Apache", "Microsoft-IIS": "IIS"},
}


async def crawl_url(
    url: str, max_depth: int = 3, max_pages: int = 200,
    timeout: float = 10.0, semaphore: Optional[asyncio.Semaphore] = None,
    evasion_headers: Optional[dict] = None,
) -> list[WebEndpoint]:
    """BFS web crawler that maps endpoints and extracts input vectors."""
    import aiohttp
    from bs4 import BeautifulSoup

    sem = semaphore or asyncio.Semaphore(50)
    visited: set[str] = set()
    endpoints: list[WebEndpoint] = []
    queue: deque[tuple[str, int]] = deque([(url, 0)])
    base_domain = urlparse(url).netloc

    async with aiohttp.ClientSession(
        headers=evasion_headers or {},
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False, limit=50),
    ) as session:
        while queue and len(visited) < max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited or depth > max_depth:
                continue
            visited.add(current_url)

            async with sem:
                try:
                    async with session.get(current_url, allow_redirects=True) as resp:
                        ep = WebEndpoint(url=current_url, status_code=resp.status)
                        ep.content_type = resp.headers.get("Content-Type", "")
                        ep.server = resp.headers.get("Server", "")
                        ep.headers = dict(resp.headers)

                        # Tech fingerprinting
                        for header, sigs in TECH_FINGERPRINTS.items():
                            val = resp.headers.get(header, "")
                            for sig, tech in sigs.items():
                                if sig.lower() in val.lower():
                                    ep.technologies.append(tech)

                        if "text/html" in ep.content_type:
                            body = await resp.text(errors="replace")
                            soup = BeautifulSoup(body, "html.parser")

                            # Extract links for BFS
                            for a in soup.find_all("a", href=True):
                                link = urljoin(current_url, a["href"])
                                if urlparse(link).netloc == base_domain and link not in visited:
                                    queue.append((link, depth + 1))

                            # Extract JS files
                            for script in soup.find_all("script", src=True):
                                js = urljoin(current_url, script["src"])
                                ep.js_files.append(js)

                            # Extract forms and input vectors
                            for form in soup.find_all("form"):
                                form_data = {
                                    "action": urljoin(current_url, form.get("action", "")),
                                    "method": form.get("method", "GET").upper(),
                                    "inputs": [],
                                }
                                for inp in form.find_all(["input", "textarea", "select"]):
                                    input_info = {
                                        "name": inp.get("name", ""),
                                        "type": inp.get("type", "text"),
                                        "id": inp.get("id", ""),
                                    }
                                    form_data["inputs"].append(input_info)
                                    if inp.get("name"):
                                        ep.input_vectors.append({
                                            "type": "form_input",
                                            "url": form_data["action"],
                                            "method": form_data["method"],
                                            "param": inp.get("name"),
                                            "input_type": inp.get("type", "text"),
                                        })
                                ep.forms.append(form_data)

                            # URL params as input vectors
                            parsed = urlparse(current_url)
                            if parsed.query:
                                for param in parsed.query.split("&"):
                                    name = param.split("=")[0]
                                    ep.input_vectors.append({
                                        "type": "url_param", "url": current_url,
                                        "method": "GET", "param": name,
                                    })

                            # Meta generator
                            gen = soup.find("meta", attrs={"name": "generator"})
                            if gen and gen.get("content"):
                                ep.technologies.append(gen["content"])

                        endpoints.append(ep)

                except Exception as e:
                    logger.debug(f"Crawl error on {current_url}: {e}")

    logger.info(f"Crawled {len(endpoints)} pages on {base_domain}")
    return endpoints


async def extract_js_endpoints(js_urls: list[str], timeout: float = 10.0) -> list[str]:
    """Fetch and analyze JS files to discover API endpoints."""
    import aiohttp
    discovered = []
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False),
    ) as session:
        for js_url in js_urls[:50]:
            try:
                async with session.get(js_url) as resp:
                    if resp.status == 200:
                        content = await resp.text(errors="replace")
                        for pattern in JS_ENDPOINT_PATTERNS:
                            matches = re.findall(pattern, content)
                            discovered.extend(matches)
            except Exception as e:
                logger.debug(f"JS endpoint extraction error for {js_url}: {e}")
                continue
    return list(set(discovered))


async def discover_apis(base_url: str, timeout: float = 10.0, evasion_headers: Optional[dict] = None) -> list[WebEndpoint]:
    """Hunt for OpenAPI/Swagger specs and parse them into endpoints."""
    import aiohttp
    import json
    from urllib.parse import urljoin
    
    api_paths = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/api/v1/swagger.json", "/api/swagger.json", "/docs-json"]
    endpoints = []
    
    async with aiohttp.ClientSession(
        headers=evasion_headers or {},
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False)
    ) as session:
        for path in api_paths:
            target_url = urljoin(base_url, path)
            try:
                async with session.get(target_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        try:
                            spec = json.loads(content)
                            if "openapi" in spec or "swagger" in spec:
                                logger.info(f"Discovered OpenAPI spec at {target_url}")
                                
                                paths = spec.get("paths", {})
                                for api_path, methods in paths.items():
                                    ep_url = urljoin(base_url, api_path)
                                    ep = WebEndpoint(url=ep_url, status_code=200, server="API")
                                    
                                    for method, details in methods.items():
                                        if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                            for param in details.get("parameters", []):
                                                ep.input_vectors.append({
                                                    "type": "api_param",
                                                    "url": ep_url,
                                                    "method": method.upper(),
                                                    "param": param.get("name", ""),
                                                    "input_type": param.get("in", "query")
                                                })
                                    endpoints.append(ep)
                                return endpoints
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.debug(f"API discovery failed on {target_url}: {e}")
                
    return endpoints


async def crawl_targets(urls: list[str], stealth_level: str = "normal", **kwargs) -> dict[str, Any]:
    """Main entry point for web crawling (called by orchestrator)."""
    if not urls:
        logger.info("No URLs specified — skipping web crawl")
        return {"endpoints": [], "js_endpoints": [], "input_vectors": 0}

    stealth_map = {
        "aggressive": StealthLevel.AGGRESSIVE,
        "normal": StealthLevel.NORMAL,
        "stealth": StealthLevel.STEALTH,
        "paranoid": StealthLevel.PARANOID,
    }
    profile = EvasionProfile(stealth_level=stealth_map.get(stealth_level, StealthLevel.NORMAL))
    engine = EvasionEngine(profile)

    all_endpoints: list[WebEndpoint] = []
    all_js: list[str] = []
    sem = asyncio.Semaphore(100)

    for url in urls:
        await engine.apply_evasion_delay()
        headers = engine.get_http_headers()
        eps = await crawl_url(url, semaphore=sem, evasion_headers=headers)
        api_eps = await discover_apis(url, evasion_headers=headers)
        all_endpoints.extend(eps)
        all_endpoints.extend(api_eps)
        for ep in eps:
            all_js.extend(ep.js_files)

    js_endpoints = await extract_js_endpoints(list(set(all_js)))

    total_vectors = sum(len(ep.input_vectors) for ep in all_endpoints)
    logger.info(f"Web crawl: {len(all_endpoints)} pages, {total_vectors} input vectors, {len(js_endpoints)} JS endpoints")

    return {
        "endpoints": [
            {"url": ep.url, "status": ep.status_code, "server": ep.server,
             "technologies": ep.technologies, "forms": len(ep.forms),
             "input_vectors": ep.input_vectors, "js_files": ep.js_files}
            for ep in all_endpoints
        ],
        "js_endpoints": js_endpoints,
        "input_vectors": total_vectors,
    }
