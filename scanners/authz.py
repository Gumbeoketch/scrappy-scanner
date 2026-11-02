"""
Authorization / access-control testing (BOLA / IDOR, privilege escalation, BFLA,
missing authentication).

These are logic flaws that active scanners cannot find: whether user A may reach
user B's object, or whether a low-privilege user may hit an admin route, depends
on the application's rules. This module replays a set of requests under multiple
identities and diffs the responses to surface *candidates* a human then confirms.

Checks
  - Missing authentication  : an anonymous session reaches an auth-looking resource.
  - BFLA / vertical priv-esc : a non-admin (or anonymous) identity reaches a
                               privileged-looking endpoint that admin also reaches.
  - BOLA / IDOR (horizontal) : identity B retrieves identity A's *owned* object
                               (precise, low false-positive: needs per-identity
                               "owned" URLs).
  - Access matrix            : per-endpoint status for every identity (artifact).

Safety: GET/HEAD/OPTIONS only by default (replaying as several users must not
mutate data); unsafe methods require explicit opt-in. Bounded request count and
per-request timeout. Authorized targets only.
"""
import difflib
import re
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_TYPE = "Access-Control"

REQUEST_TIMEOUT = 8
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SAMPLE_BYTES = 2500
SUBSTANTIVE_BYTES = 180
SIMILAR_RATIO = 0.90
USER_AGENT = "scrappy-scanner/authz"

_PRIVILEGED_PATH = re.compile(
    r"(admin|manage|management|internal|superuser|root|config|settings|"
    r"users?/\d|accounts?/\d|approve|disable|enable|delete|promote|role|privilege|audit)",
    re.IGNORECASE,
)
_AUTHY_PATH = re.compile(
    r"(account|profile|user|order|invoice|transaction|balance|statement|"
    r"message|document|card|loan|transfer|api/|/me\b|dashboard|settings)",
    re.IGNORECASE,
)
_PRIVILEGED_ROLES = {"admin", "administrator", "superadmin", "superuser", "root", "privileged"}


def _finding(title, severity, description, recommendation, components=None, references=None):
    return {
        "status": "in-progress",
        "data": {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "affected_components": components or [],
            "references": references or [
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            ],
            "type": MODULE_TYPE,
        },
    }


def _build_session(identity):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    if identity.get("token"):
        header = (identity.get("header") or "Authorization").strip() or "Authorization"
        token = identity["token"].strip()
        value = token if re.match(r"^(bearer|basic|token)\s", token, re.I) else f"Bearer {token}"
        s.headers[header] = value
    if identity.get("cookie"):
        s.headers["Cookie"] = identity["cookie"]
    for k, v in (identity.get("headers") or {}).items():
        s.headers[k] = v
    return s


def _send(session, method, url):
    try:
        r = session.request(method, url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None
    body = r.text or ""
    return {"status": r.status_code, "length": len(body), "sample": body[:SAMPLE_BYTES]}


def _is_success(r):
    return bool(r) and 200 <= r["status"] < 300


def _substantive(r):
    return bool(r) and r["length"] >= SUBSTANTIVE_BYTES


def _similar(a, b):
    if not a or not b:
        return False
    # Cheap length gate before the more expensive ratio.
    la, lb = len(a), len(b)
    if la and lb and abs(la - lb) / max(la, lb) > 0.2:
        return False
    return difflib.SequenceMatcher(None, a, b).ratio() >= SIMILAR_RATIO


def _normalise_methods(methods, allow_unsafe):
    allowed = set(SAFE_METHODS)
    if allow_unsafe and methods:
        allowed |= {m.upper() for m in methods}
    return allowed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(targets, identities, allow_unsafe=False, max_requests=150, progress_cb=None):
    """
    targets    : list of {"method": "GET", "url": "https://..."}
    identities : list of {"name","role","token"/"cookie"/"header","owned":[urls]}
                 An identity with no credentials acts as 'anonymous'.
    """
    def note(msg):
        if progress_cb:
            progress_cb(msg)

    allowed_methods = _normalise_methods(None, allow_unsafe)

    # Always include an anonymous identity for missing-auth checks.
    idents = list(identities or [])
    if not any((i.get("name") or "").lower() in ("anonymous", "anon") for i in idents):
        idents.append({"name": "anonymous", "role": "anonymous"})

    sessions = {i["name"]: _build_session(i) for i in idents}
    meta = {i["name"]: i for i in idents}

    # De-dupe targets and cap the workload.
    seen, clean_targets = set(), []
    for t in targets or []:
        url = (t.get("url") or "").strip()
        method = (t.get("method") or "GET").upper()
        if not url or method not in allowed_methods:
            continue
        key = (method, url)
        if key in seen:
            continue
        seen.add(key)
        clean_targets.append({"method": method, "url": url})
        if len(clean_targets) >= max_requests:
            break

    findings, matrix = [], []

    # --- Pass 1: replay every target under every identity, build the matrix ---
    for idx, t in enumerate(clean_targets, 1):
        note(f"Matrix {idx}/{len(clean_targets)}: {t['method']} {t['url'][:60]}")
        cells, responses = {}, {}
        for name in sessions:
            r = _send(sessions[name], t["method"], t["url"])
            responses[name] = r
            cells[name] = r["status"] if r else "ERR"
        matrix.append({"method": t["method"], "url": t["url"], "cells": cells})
        findings.extend(_analyze_target(t, responses, meta))

    # --- Pass 2: BOLA via owned-object cross-access (precise) ---
    note("Cross-checking owned objects for BOLA/IDOR…")
    findings.extend(_bola_pass(sessions, idents, meta))

    # Summary
    findings.insert(0, _finding(
        f"Authorization matrix tested: {len(clean_targets)} endpoint(s) × {len(idents)} identit(y/ies)",
        "info",
        f"Replayed {len(clean_targets)} request(s) as {', '.join(sessions.keys())} and compared "
        "responses. Review the matrix and the candidates below — authorization findings are "
        "heuristic and must be confirmed manually.",
        "Enforce object- and function-level authorization server-side on every request; never "
        "rely on the UI hiding actions.",
        components=[f"{t['method']} {t['url']}" for t in clean_targets[:25]] or ["(none)"],
    ))

    return {"findings": findings, "matrix": matrix}


def _analyze_target(t, responses, meta):
    findings = []
    url, method = t["url"], t["method"]
    anon = next((responses[n] for n in responses if meta.get(n, {}).get("role", "").lower()
                 in ("anonymous", "anon") or n.lower() in ("anonymous", "anon")), None)

    authed_ok = any(_is_success(r) for n, r in responses.items()
                    if not (meta.get(n, {}).get("role", "").lower() in ("anonymous", "anon")
                            or n.lower() in ("anonymous", "anon")))

    # Missing authentication: anonymous reaches a substantive, auth-looking resource.
    if _is_success(anon) and _substantive(anon) and _AUTHY_PATH.search(url):
        sev = "high" if _PRIVILEGED_PATH.search(url) else "medium"
        findings.append(_finding(
            f"Resource reachable without authentication: {method} {urlparse(url).path or '/'}",
            sev,
            f"An unauthenticated request to {url} returned HTTP {anon['status']} with a "
            f"substantive body ({anon['length']} bytes). The path looks like it serves "
            "user/account data, so this may be broken access control (missing authN).",
            "Require authentication on this endpoint and verify the session server-side "
            "before returning data.",
            components=[f"{method} {url} -> anon {anon['status']}"],
        ))

    # BFLA / vertical priv-esc: non-privileged identity reaches a privileged-looking endpoint.
    if _PRIVILEGED_PATH.search(url):
        for name, r in responses.items():
            role = (meta.get(name, {}).get("role") or "").lower()
            is_priv = role in _PRIVILEGED_ROLES
            is_anon = role in ("anonymous", "anon") or name.lower() in ("anonymous", "anon")
            if is_priv:
                continue
            if _is_success(r) and _substantive(r):
                who = "anonymous user" if is_anon else f"non-admin identity '{name}' (role: {role or 'unset'})"
                findings.append(_finding(
                    f"Privileged endpoint reachable by {('anonymous' if is_anon else 'low-privilege')} user: {urlparse(url).path or '/'}",
                    "high" if is_anon else "medium",
                    f"The privileged-looking endpoint {url} returned HTTP {r['status']} for "
                    f"{who}. This is a broken function-level authorization (BFLA) / privilege-"
                    "escalation candidate — confirm the response actually exposes admin data/actions.",
                    "Enforce role checks server-side on administrative endpoints; return 401/403 "
                    "for users lacking the required role.",
                    components=[f"{method} {url} -> {name} {r['status']}"],
                ))
    return findings


def _bola_pass(sessions, idents, meta):
    findings = []
    for owner in idents:
        owned = owner.get("owned") or []
        if not owned:
            continue
        oname = owner["name"]
        for u in owned:
            u = (u or "").strip()
            if not u:
                continue
            base = _send(sessions[oname], "GET", u)
            if not _is_success(base) or not _substantive(base):
                continue  # can't establish an owner baseline
            for other in idents:
                if other["name"] == oname:
                    continue
                resp = _send(sessions[other["name"]], "GET", u)
                if _is_success(resp) and _similar(base["sample"], resp["sample"]):
                    other_role = (meta.get(other["name"], {}).get("role") or "").lower()
                    is_anon = other_role in ("anonymous", "anon") or other["name"].lower() in ("anonymous", "anon")
                    accessor = "an anonymous user" if is_anon else f"identity '{other['name']}'"
                    findings.append(_finding(
                        f"BOLA/IDOR: '{other['name']}' accessed '{oname}'s object",
                        "high",
                        f"The object at {u} belongs to '{oname}', but {accessor} "
                        f"retrieved a near-identical response (HTTP {resp['status']}). This is a "
                        "Broken Object Level Authorization (IDOR) finding — one user can read "
                        "another user's object.",
                        "Enforce object ownership on every access: check that the authenticated "
                        "principal owns (or is authorized for) the requested object id server-side.",
                        components=[f"GET {u} | owner={oname} | accessed_by={other['name']} ({resp['status']})"],
                    ))
    return findings
