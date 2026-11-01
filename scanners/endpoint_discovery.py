"""
API / endpoint discovery.

Builds an inventory of a target's endpoints using three complementary, bounded
techniques:

  1. OpenAPI / Swagger import   — highest signal; parses a supplied spec URL or
     auto-probes common spec locations (v2 and v3).
  2. Same-host crawl            — fetches the base page + linked same-origin JS
     and extracts endpoint-like paths (links, forms, fetch/axios/XHR strings).
  3. Common-path probe          — GETs a curated, non-destructive list of common
     API / admin / doc / exposure paths and records which exist.

Returns both findings (common schema, type "API-Discovery") and a reusable
``inventory`` list that later modules (authz / IDOR, JWT-in-context) consume.

Safety: GET-only, per-request timeout, capped request counts, same-host crawl
only, and it honours caller-supplied auth (bearer token / cookie / headers).
"""
import json
import re
from urllib.parse import urljoin, urlparse

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_TYPE = "API-Discovery"

REQUEST_TIMEOUT = 8          # seconds per request
MAX_CRAWL_PAGES = 25         # base page + linked JS files
MAX_JS_BYTES = 2_000_000     # don't parse huge bundles
USER_AGENT = "scrappy-scanner/endpoint-discovery"

# Common OpenAPI / Swagger spec locations to auto-probe.
OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/swagger-ui/index.html", "/api/openapi.json",
]

# Curated, non-destructive paths worth probing. (method, path, severity, note)
COMMON_PATHS = [
    ("/robots.txt",            "info",   "robots.txt may reveal hidden paths"),
    ("/sitemap.xml",           "info",   "sitemap may enumerate URLs"),
    ("/.well-known/security.txt", "info", "security contact disclosure"),
    ("/graphql",               "info",   "GraphQL endpoint (introspection worth testing)"),
    ("/graphiql",              "low",    "GraphQL IDE exposed"),
    ("/api",                   "info",   "API root"),
    ("/api/v1",                "info",   "versioned API root"),
    ("/api/v2",                "info",   "versioned API root"),
    ("/actuator",              "medium", "Spring Boot Actuator base"),
    ("/actuator/health",       "low",    "Actuator health endpoint"),
    ("/actuator/env",          "high",   "Actuator env may leak secrets/config"),
    ("/actuator/mappings",     "medium", "Actuator exposes route mappings"),
    ("/metrics",               "medium", "metrics endpoint (info exposure)"),
    ("/debug",                 "medium", "debug endpoint"),
    ("/console",               "medium", "admin/console endpoint"),
    ("/admin",                 "low",    "admin area"),
    ("/.env",                  "high",   ".env file may expose secrets"),
    ("/.git/config",           "high",   "exposed .git repository"),
    ("/server-status",         "medium", "Apache server-status"),
    ("/phpinfo.php",           "high",   "phpinfo discloses environment"),
    ("/swagger-ui/",           "low",    "Swagger UI exposed"),
]

_URL_IN_JS = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}:]+)['"`]""")
_HREF_SRC_ACTION = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)
_JS_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(title, severity, description, recommendation, references=None, components=None):
    return {
        "status": "in-progress",
        "data": {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "affected_components": components or [],
            "references": references or [],
            "type": MODULE_TYPE,
        },
    }


def _build_session(auth):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    auth = auth or {}
    atype = (auth.get("type") or "none").lower()
    if atype == "bearer" and auth.get("token"):
        header = (auth.get("header") or "Authorization").strip() or "Authorization"
        token = auth["token"].strip()
        value = token if re.match(r"^(bearer|basic|token)\s", token, re.I) else f"Bearer {token}"
        s.headers[header] = value
    if auth.get("cookie"):
        s.headers["Cookie"] = auth["cookie"]
    for k, v in (auth.get("headers") or {}).items():
        s.headers[k] = v
    return s


def _get(session, url):
    try:
        return session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def _same_host(base, url):
    try:
        return urlparse(base).netloc == urlparse(url).netloc
    except ValueError:
        return False


def _inv(method, url, source, status=None, params=None, note=None):
    return {"method": method, "url": url, "source": source,
            "status": status, "params": params or [], "note": note}


# ---------------------------------------------------------------------------
# 1) OpenAPI / Swagger
# ---------------------------------------------------------------------------

def _parse_openapi(spec, spec_url, base_url):
    endpoints = []
    if not isinstance(spec, dict) or "paths" not in spec:
        return endpoints

    # Resolve the server/base prefix.
    prefix = ""
    if "servers" in spec and isinstance(spec["servers"], list) and spec["servers"]:
        prefix = spec["servers"][0].get("url", "") or ""
    elif "basePath" in spec:
        prefix = spec.get("basePath", "") or ""
    if prefix.startswith("/"):
        prefix = urljoin(base_url, prefix)
    elif not prefix.startswith("http"):
        prefix = base_url.rstrip("/") + ("/" + prefix.lstrip("/") if prefix else "")

    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters", []) or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(p["name"])
            full = (prefix.rstrip("/") + "/" + path.lstrip("/")) if prefix else urljoin(base_url, path)
            endpoints.append(_inv(method.upper(), full, f"openapi:{spec_url}", params=params))
    return endpoints


def _load_spec(session, url):
    resp = _get(session, url)
    if not resp or resp.status_code >= 400 or not resp.text:
        return None
    text = resp.text
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except yaml.YAMLError:
        return None


def discover_openapi(session, base_url, openapi_url):
    findings, endpoints, used_url = [], [], None

    candidates = [openapi_url] if openapi_url else [urljoin(base_url, p) for p in OPENAPI_PATHS]
    for cand in candidates:
        if not cand:
            continue
        spec = _load_spec(session, cand)
        if spec and ("paths" in spec or "swagger" in spec or "openapi" in spec):
            eps = _parse_openapi(spec, cand, base_url)
            if eps:
                endpoints = eps
                used_url = cand
                break

    if used_url:
        findings.append(_finding(
            f"OpenAPI/Swagger specification exposed ({len(endpoints)} operations)", "low",
            f"An API specification was reachable at {used_url}, enumerating "
            f"{len(endpoints)} operations. Specs are valuable to an attacker: they "
            "reveal every route, parameter, and expected payload.",
            "Confirm the spec is meant to be public. If not, restrict it to internal "
            "networks or authenticated users. Either way, ensure every documented "
            "endpoint enforces authentication and authorization.",
            components=[used_url],
        ))
    return findings, endpoints, used_url


# ---------------------------------------------------------------------------
# 2) Crawl (HTML + same-host JS)
# ---------------------------------------------------------------------------

def crawl(session, base_url):
    endpoints = []
    resp = _get(session, base_url)
    if not resp:
        return endpoints
    html = resp.text or ""
    endpoints.append(_inv("GET", base_url, "crawl", status=resp.status_code))

    paths = set()
    for m in _HREF_SRC_ACTION.finditer(html):
        paths.add(m.group(1))

    js_urls = []
    for m in _JS_SRC.finditer(html):
        ju = urljoin(base_url, m.group(1))
        if _same_host(base_url, ju):
            js_urls.append(ju)

    for ju in js_urls[:MAX_CRAWL_PAGES]:
        jr = _get(session, ju)
        if not jr or not jr.text:
            continue
        body = jr.text[:MAX_JS_BYTES]
        for m in _URL_IN_JS.finditer(body):
            paths.add(m.group(1))

    for p in paths:
        if p.startswith(("http://", "https://")):
            full = p
        elif p.startswith("/"):
            full = urljoin(base_url, p)
        else:
            continue
        if _same_host(base_url, full):
            endpoints.append(_inv("GET", full, "crawl"))
    return endpoints


# ---------------------------------------------------------------------------
# 3) Common-path probe
# ---------------------------------------------------------------------------

def probe_common(session, base_url):
    findings, endpoints = [], []
    for path, severity, note in COMMON_PATHS:
        url = urljoin(base_url, path)
        resp = _get(session, url)
        if not resp:
            continue
        code = resp.status_code
        if code == 404:
            continue
        endpoints.append(_inv("GET", url, "probe", status=code, note=note))
        # A 200 on a sensitive path is a finding; 401/403 means it exists but is
        # protected (useful later for authz testing).
        if code < 400 and severity in ("high", "medium", "low"):
            findings.append(_finding(
                f"Exposed path: {path} (HTTP {code})", severity,
                f"{note}. Reachable at {url} returning HTTP {code}.",
                "Verify this path should be publicly reachable; restrict or remove it "
                "if it exposes internal information, configuration, or tooling.",
                components=[f"{url} -> {code}"],
            ))
    return findings, endpoints


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(target_url, auth=None, openapi_url=None, do_crawl=True, do_probe=True, progress_cb=None):
    base_url = target_url if target_url.endswith("/") else target_url + "/"
    session = _build_session(auth)

    findings, inventory = [], []

    def note(msg):
        if progress_cb:
            progress_cb(msg)

    note("Looking for OpenAPI/Swagger spec…")
    of, oeps, _ = discover_openapi(session, base_url, openapi_url)
    findings += of
    inventory += oeps

    if do_crawl:
        note("Crawling target (HTML + JS)…")
        inventory += crawl(session, base_url)

    if do_probe:
        note("Probing common paths…")
        pf, peps = probe_common(session, base_url)
        findings += pf
        inventory += peps

    # De-duplicate inventory by (method, url).
    seen, deduped = set(), []
    for e in inventory:
        key = (e["method"], e["url"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    inventory = deduped

    protected = [e for e in inventory if e.get("status") in (401, 403)]
    findings.insert(0, _finding(
        f"Endpoint discovery: {len(inventory)} endpoint(s) found", "info",
        f"Discovered {len(inventory)} unique endpoint(s) across OpenAPI, crawling, "
        f"and path probing; {len(protected)} returned 401/403 (auth-protected). "
        "The full inventory is attached as a downloadable artifact and seeds "
        "later authorization testing.",
        "Review the inventory and ensure every endpoint enforces authentication "
        "and authorization appropriate to its function.",
        components=[f"{e['method']} {e['url']}" for e in inventory[:25]] or ["(none)"],
    ))

    return {"findings": findings, "inventory": inventory}
