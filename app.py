#!/usr/bin/env python3
"""
Web Security Scanner Application
Combines ZAP scanning, AI enrichment, and SysReptor export into a unified UI
"""
import os
import json
import subprocess
import sys
import shutil
import time
import re
import hmac
import threading
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import yaml
from flask import Flask, render_template, request, jsonify, send_file, Response
import google.generativeai as genai

from scanners import jwt_scanner
from scanners import endpoint_discovery
from scanners import authz as authz_scanner

app = Flask(__name__, static_folder='images', static_url_path='/static/images')
app.config['UPLOAD_FOLDER'] = Path('scans')
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
# Cap request body size to mitigate memory-exhaustion DoS (10 MB).
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

HISTORY_FILE = Path('scan_history.json')
TRACKER_FILE = Path('vuln_tracker.json')

# Resolve reptor binary: prefer the venv running this process,
# fall back to PATH, then common install locations.
def _find_reptor():
    venv_reptor = Path(sys.executable).parent / 'reptor'
    if venv_reptor.exists():
        return str(venv_reptor)
    on_path = shutil.which('reptor')
    if on_path:
        return on_path
    for candidate in ['/usr/local/bin/reptor', '/usr/bin/reptor',
                      str(Path.home() / '.local' / 'bin' / 'reptor')]:
        if Path(candidate).exists():
            return candidate
    return None

REPTOR_BIN = _find_reptor()

# In-memory job store  { job_id: { status, progress, result, error } }
_jobs: dict = {}
_jobs_lock = threading.Lock()

# Lock for Gemini API calls (gRPC is not thread-safe on Linux)
_gemini_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def load_env():
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                if key and key not in os.environ:
                    os.environ[key] = value

load_env()


# ---------------------------------------------------------------------------
# Security: optional HTTP Basic Auth + hardening response headers
# ---------------------------------------------------------------------------

_AUTH_USER = os.getenv('APP_AUTH_USER')
_AUTH_PASS = os.getenv('APP_AUTH_PASS')
# Auth is opt-in: enforced only when both credentials are configured. Basic Auth
# is used because browsers send it transparently, so the existing fetch-based UI
# keeps working without changes once credentials are set.
AUTH_ENABLED = bool(_AUTH_USER and _AUTH_PASS)


def _auth_ok(auth):
    if not auth or auth.type != 'basic':
        return False
    # Constant-time comparison to avoid username/password timing oracles.
    user_ok = hmac.compare_digest(auth.username or '', _AUTH_USER)
    pass_ok = hmac.compare_digest(auth.password or '', _AUTH_PASS)
    return user_ok and pass_ok


@app.before_request
def _require_auth():
    if not AUTH_ENABLED:
        return None
    if _auth_ok(request.authorization):
        return None
    return Response(
        'Authentication required', 401,
        {'WWW-Authenticate': 'Basic realm="Security Scanner"'}
    )


@app.after_request
def _security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    # The UI relies on inline <style>/<script>, so 'unsafe-inline' is required;
    # everything else is locked to same-origin. frame-ancestors blocks clickjacking.
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    # Never let a shared/proxy cache store API responses (defense in depth
    # against cache-based information disclosure).
    if request.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp


# ---------------------------------------------------------------------------
# Scan history helpers
# ---------------------------------------------------------------------------

def load_history():
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {'scans': {}}


def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def normalise_url(url):
    url = url.strip().rstrip('/')
    match = re.match(r'(https?://)([^/]+)(.*)', url, re.IGNORECASE)
    if match:
        url = match.group(1).lower() + match.group(2).lower() + match.group(3)
    return url


def record_scan(target_url, findings):
    history = load_history()
    key = normalise_url(target_url)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('data', {}).get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1

    now = datetime.utcnow().isoformat() + 'Z'

    if key not in history['scans']:
        history['scans'][key] = {
            'url': target_url,
            'first_scanned': now,
            'last_scanned': now,
            'scan_count': 1,
            'latest': counts,
            'history': [{'scanned_at': now, 'counts': counts}]
        }
    else:
        entry = history['scans'][key]
        entry['last_scanned'] = now
        entry['scan_count'] += 1
        entry['latest'] = counts
        entry['history'].append({'scanned_at': now, 'counts': counts})
        entry['history'] = entry['history'][-10:]

    save_history(history)
    return history['scans'][key]


def _auto_import_to_tracker(target_url, findings):
    """
    Automatically import scan findings into the vulnerability tracker.
    Deduplicates by title + normalised URL — if the same finding already
    exists for the same URL, it updates the date but doesn't create a duplicate.
    """
    data = load_tracker()
    existing = data.get('vulnerabilities', [])
    norm_url = normalise_url(target_url)

    # Build a set of existing (title, url) for fast lookup
    existing_keys = set()
    for v in existing:
        key = (v.get('title', '').lower(), normalise_url(v.get('url', '')))
        existing_keys.add(key)

    added = 0
    today = datetime.utcnow().strftime('%Y-%m-%d')

    for f in findings:
        fd = f.get('data', {})
        title = fd.get('title', 'Untitled')
        dedup_key = (title.lower(), norm_url)

        if dedup_key in existing_keys:
            # Already tracked — update date_updated on the existing entry
            for v in existing:
                if v.get('title', '').lower() == title.lower() and normalise_url(v.get('url', '')) == norm_url:
                    v['date_updated'] = today
                    break
            continue

        vuln = {
            'id': str(uuid.uuid4())[:8],
            'title': title,
            'severity': fd.get('severity', 'info'),
            'status': 'open',
            'url': target_url,
            'team': '',
            'description': fd.get('description', '')[:500],
            'date_reported': today,
            'date_updated': today,
            'notes': ''
        }
        existing.insert(0, vuln)
        existing_keys.add(dedup_key)
        added += 1

    data['vulnerabilities'] = existing
    save_tracker(data)
    print(f"[Tracker] Imported {added} new findings for {target_url} ({len(findings) - added} duplicates skipped)")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def sanitize_url_to_filename(url):
    clean = re.sub(r'https?://', '', url)
    clean = re.sub(r'[/:?&=]', '-', clean)
    clean = re.sub(r'-+', '-', clean)
    return clean.strip('-') or 'scan'


def _has_auth_scheme(token):
    """True if the token already starts with an auth scheme (Bearer/Basic/...)."""
    return bool(re.match(r'^(bearer|basic|token|apikey)\s', token or '', re.IGNORECASE))


def _scrub_secrets(text, secrets):
    """Redact credential values from tool output before surfacing it."""
    if not text:
        return text
    for s in secrets:
        if s:
            text = text.replace(s, '***')
    return text


def _build_zap_plan(target_url, json_name, html_name, auth_type, auth,
                    active=False, ajax=False, spider_minutes=2, active_minutes=20):
    """
    Build a ZAP Automation Framework plan.

    Passive (default): passiveScan-config -> spider -> passiveScan-wait -> report.
    Active adds an `activeScan` job (sends attack payloads -> finds injection,
    XSS, and more of the OWASP Top 10). `ajax` adds a JS-rendering spider for
    SPA/JavaScript-heavy apps. For 'userpass' it embeds a form-auth context + user
    so crawl/active-scan run behind the login; bearer auth is injected via the
    replacer (request header) and needs no context changes here.
    """
    context = {
        'name': 'scan-context',
        'urls': [target_url],
        'includePaths': [],
        'excludePaths': [],
        'technology': {},
    }
    spider_params = {'context': 'scan-context', 'maxDuration': spider_minutes, 'maxDepth': 10}

    if auth_type == 'userpass':
        login_url  = auth.get('login_url') or target_url
        user_field = (auth.get('username_field') or '').strip() or 'username'
        pass_field = (auth.get('password_field') or '').strip() or 'password'
        logged_out = (auth.get('logged_out_regex')
                      or r'(?i)(log.?in|sign.?in|username|password|unauthor|session.?expir|\b401\b|\b403\b)')
        context['authentication'] = {
            'method': 'form',
            'parameters': {
                'loginPageUrl': login_url,
                'loginRequestUrl': login_url,
                'loginRequestBody': f'{user_field}={{{{username}}}}&{pass_field}={{{{password}}}}',
            },
            'verification': {
                'method': 'response',
                'loggedInRegex': r'\w',
                'loggedOutRegex': logged_out,
                'pollFrequency': 60,
                'pollUnits': 'requests',
            },
        }
        context['sessionManagement'] = {'method': 'cookie'}
        context['users'] = [{
            'name': 'scan-user',
            'credentials': {
                'username': auth.get('username', ''),
                'password': auth.get('password', ''),
            },
        }]
        spider_params['user'] = 'scan-user'

    user = 'scan-user' if auth_type == 'userpass' else None

    jobs = [
        {'type': 'passiveScan-config', 'parameters': {'maxAlertsPerRule': 10}},
        {'type': 'spider', 'parameters': spider_params},
    ]

    if ajax:
        ajax_params = {'context': 'scan-context', 'maxDuration': spider_minutes,
                       'maxCrawlDepth': 10, 'browserId': 'firefox-headless'}
        if user:
            ajax_params['user'] = user
        jobs.append({'type': 'spiderAjax', 'parameters': ajax_params})

    jobs.append({'type': 'passiveScan-wait', 'parameters': {'maxDuration': 5}})

    if active:
        active_params = {'context': 'scan-context', 'maxScanDurationInMins': active_minutes}
        if user:
            active_params['user'] = user
        jobs.append({'type': 'activeScan', 'parameters': active_params})

    jobs += [
        {'type': 'report', 'parameters': {
            'template': 'traditional-json', 'reportDir': '/zap/wrk/',
            'reportFile': json_name, 'reportTitle': 'ZAP Security Report',
            'reportDescription': ''}},
        {'type': 'report', 'parameters': {
            'template': 'traditional-html', 'reportDir': '/zap/wrk/',
            'reportFile': html_name, 'reportTitle': 'ZAP Security Report',
            'reportDescription': ''}},
    ]

    return {
        'env': {
            'contexts': [context],
            'parameters': {'failOnError': False, 'progressToStdout': True},
        },
        'jobs': jobs,
    }


def _run_zap_af_scan(target_url, output_dir, scan_prefix, scan_json, scan_html, auth_type, auth,
                     active=False, ajax=False, spider_minutes=2, active_minutes=20):
    """ZAP Automation Framework scan — used for authenticated and/or active scans."""
    plan = _build_zap_plan(target_url, scan_json.name, scan_html.name, auth_type, auth,
                           active=active, ajax=ajax,
                           spider_minutes=spider_minutes, active_minutes=active_minutes)
    plan_path = output_dir / f"{scan_prefix}_plan.yaml"
    secrets = [auth.get('token'), auth.get('password')]

    try:
        # The plan may contain credentials — write it readable only by the owner.
        with open(plan_path, 'w') as f:
            yaml.safe_dump(plan, f, sort_keys=False)
        os.chmod(plan_path, 0o600)

        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{output_dir.absolute()}:/zap/wrk:rw",
            '--user', 'root',
            'ghcr.io/zaproxy/zaproxy:stable',
            'zap.sh', '-cmd', '-autorun', f'/zap/wrk/{plan_path.name}',
        ]

        if auth_type == 'bearer':
            header = (auth.get('header') or '').strip() or 'Authorization'
            token = (auth.get('token') or '').strip()
            value = token if _has_auth_scheme(token) else f'Bearer {token}'
            # Inject the auth header into every request via ZAP's replacer add-on.
            # Passed as discrete argv entries so the space in "Bearer <token>"
            # is preserved (no shell parsing involved).
            cmd += [
                '-config', 'replacer.full_list(0).description=auth',
                '-config', 'replacer.full_list(0).enabled=true',
                '-config', 'replacer.full_list(0).matchtype=REQ_HEADER',
                '-config', f'replacer.full_list(0).matchstr={header}',
                '-config', 'replacer.full_list(0).regex=false',
                '-config', f'replacer.full_list(0).replacement={value}',
            ]

        # Active scans + AJAX spidering can run long; size the timeout to the plan.
        budget = spider_minutes + (spider_minutes if ajax else 0) + (active_minutes if active else 0) + 15
        run_timeout = max(1800, budget * 60)
        # nosemgrep
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=run_timeout)

        if not scan_json.exists():
            detail = _scrub_secrets(result.stderr or result.stdout, secrets)
            raise Exception(f"ZAP scan failed: {(detail or '')[:800]}")

        return {
            'json_path': scan_json,
            'html_path': scan_html,
            'resource_name': scan_prefix,
        }
    finally:
        # Never leave the credential-bearing plan on disk.
        try:
            plan_path.unlink()
        except OSError:
            pass


def run_zap_scan(target_url, output_dir, auth=None, active=False, ajax=False,
                 spider_minutes=2, active_minutes=20):
    resource_name = sanitize_url_to_filename(target_url)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_prefix = f"{resource_name}_{timestamp}"

    scan_json = output_dir / f"{scan_prefix}.json"
    scan_html = output_dir / f"{scan_prefix}.html"

    # Group/other-readable so the host can read files written by the (root) ZAP
    # container, without making the directory world-writable.
    output_dir.chmod(0o755)

    auth = auth or {}
    auth_type = (auth.get('type') or 'none').lower()

    # Use the Automation Framework for authenticated and/or active scans. The fast
    # passive baseline stays the default for unauthenticated passive runs.
    if active or auth_type in ('bearer', 'userpass'):
        return _run_zap_af_scan(target_url, output_dir, scan_prefix,
                                scan_json, scan_html, auth_type, auth,
                                active=active, ajax=ajax,
                                spider_minutes=spider_minutes, active_minutes=active_minutes)

    # --- Unauthenticated passive baseline scan (default) ---
    cmd = [
        'docker', 'run', '--rm',
        '-v', f"{output_dir.absolute()}:/zap/wrk:rw",
        '--user', 'root',
        'ghcr.io/zaproxy/zaproxy:stable',
        'zap-baseline.py',
        '-t', target_url,
        '-r', scan_html.name,
        '-J', scan_json.name
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

    if not scan_json.exists():
        # Filter out known non-fatal noise from stderr
        stderr = result.stderr or ''
        stdout = result.stdout or ''
        error_msg = stderr + stdout
        # Ignore gRPC epoll warnings that leak from the Gemini library
        noise_patterns = ['ev_epoll1_linux', 'Epoll1Poller']
        filtered_lines = [
            l for l in error_msg.splitlines()
            if not any(p in l for p in noise_patterns)
        ]
        raise Exception(f"ZAP scan failed: {chr(10).join(filtered_lines[:20])}")

    return {
        'json_path': scan_json,
        'html_path': scan_html,
        'resource_name': scan_prefix
    }


# ---------------------------------------------------------------------------
# Gemini AI
# ---------------------------------------------------------------------------

def initialize_gemini():
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        return None
    genai.configure(api_key=api_key)
    safety_settings = [
        {'category': 'HARM_CATEGORY_HARASSMENT',        'threshold': 'BLOCK_NONE'},
        {'category': 'HARM_CATEGORY_HATE_SPEECH',       'threshold': 'BLOCK_NONE'},
        {'category': 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold': 'BLOCK_NONE'},
        {'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_NONE'},
    ]
    return genai.GenerativeModel('gemini-flash-latest', safety_settings=safety_settings)


def enrich_finding_with_ai(model, finding_data):
    if not model:
        return finding_data

    title          = finding_data.get('title', 'Unknown')
    description    = finding_data.get('description', '')
    recommendation = finding_data.get('recommendation', '')
    severity       = finding_data.get('severity', 'low')
    affected       = finding_data.get('affected_components', [])

    prompt = f"""You are a security engineer writing a concise technical report.

Vulnerability: {title}
Severity: {severity}
Context: {description[:300]}
Affected: {', '.join(affected[:2])}

Respond with ONLY this JSON, no extra text:
{{"description": "2-3 sentences: what it is, why it's dangerous, attack vector", "recommendation": "3-5 numbered steps: specific code/config fixes a developer can action immediately"}}"""

    try:
        with _gemini_lock:
            response = model.generate_content(prompt)

        if not response.parts:
            print(f"  ⚠ Skipping '{title}': blocked by safety filter")
            return finding_data

        result_text = response.text.strip()

        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()

        start = result_text.find('{')
        end   = result_text.rfind('}')
        if start != -1 and end != -1:
            result_text = result_text[start:end + 1]

        enriched = json.loads(result_text)
        finding_data['description']    = _sanitize_for_sysreptor(enriched.get('description',    description))
        finding_data['recommendation'] = _sanitize_for_sysreptor(enriched.get('recommendation', recommendation))

        time.sleep(1)

    except Exception as e:
        print(f"Failed to enrich '{title}': {e}")

    return finding_data


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _sanitize_for_sysreptor(text):
    """
    Escape raw HTML tags that break SysReptor's Vue template compiler.
    SysReptor compiles markdown as Vue templates, so raw <script>, <style>,
    and other HTML tags in finding content cause compilation errors.

    Strategy:
    - Strip common ZAP HTML formatting tags (p, br, li, ul, ol, b, strong, etc.)
    - Wrap any remaining HTML tags (like <script>, <iframe>, <style>) in
      inline code backticks so they render as literal text, not live HTML.
    """
    import re as _re

    if not text:
        return ''

    # Strip ZAP's HTML formatting tags but keep their content
    formatting_tags = r'</?(?:p|br|div|span|ul|ol|li|b|strong|i|em|a|table|tr|td|th|thead|tbody|h[1-6]|pre|code|blockquote)(?:\s[^>]*)?\s*/?>'
    text = _re.sub(formatting_tags, '\n', text, flags=_re.IGNORECASE)

    # Replace &nbsp; and other common entities
    text = text.replace('&nbsp;', ' ')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    text = text.replace('&amp;', '&')
    text = text.replace('&quot;', '"')

    # Now escape any remaining HTML-like tags by wrapping in backticks
    # This catches <script>, <style>, <iframe>, <object>, <embed>, etc.
    def _wrap_in_code(match):
        tag = match.group(0)
        return f'`{tag}`'

    text = _re.sub(r'</?(?:script|style|iframe|object|embed|link|meta|svg|math)(?:\s[^>]*)?\s*/?>', _wrap_in_code, text, flags=_re.IGNORECASE)

    # Also escape any generic tags that look like payloads (e.g. <img onerror=...>)
    text = _re.sub(r'<(?:img|input|button|form|textarea|select)\s[^>]*>', _wrap_in_code, text, flags=_re.IGNORECASE)

    # Collapse multiple newlines
    text = _re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


def parse_zap_to_sysreptor(zap_json_path, use_ai=True, progress_cb=None):
    with open(zap_json_path) as f:
        zap_data = json.load(f)

    findings = []
    alerts = zap_data.get('alerts', [])

    if not alerts and 'site' in zap_data:
        if isinstance(zap_data['site'], list):
            for site in zap_data['site']:
                alerts.extend(site.get('alerts', []))
        elif isinstance(zap_data['site'], dict):
            alerts.extend(zap_data['site'].get('alerts', []))

    severity_map = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'info'}
    model = initialize_gemini() if use_ai else None

    for idx, alert in enumerate(alerts, 1):
        title          = alert.get('alert', 'Untitled Finding')
        riskdesc       = alert.get('riskdesc', 'Low (Default)')
        severity       = severity_map.get(riskdesc.split(' ')[0], 'low')
        description    = _sanitize_for_sysreptor(alert.get('desc', ''))
        recommendation = _sanitize_for_sysreptor(alert.get('solution', ''))

        references = []
        ref_str = alert.get('reference', '')
        if ref_str:
            refs = ref_str.replace('<p>', '').replace('</p>', '\n').split('\n')
            references = [r.strip() for r in refs if r.strip()]

        affected_components = []
        for instance in alert.get('instances', []):
            uri   = instance.get('uri')
            param = instance.get('param')
            if uri:
                affected_components.append(uri + (f" [Param: {param}]" if param else ''))

        finding_data = {
            'title': title,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'affected_components': affected_components or ['General Application'],
            'references': references,
            'type': 'Web-Application'
        }

        if model:
            if progress_cb:
                progress_cb(f'AI enrichment: {idx}/{len(alerts)} — {title[:50]}…')
            finding_data = enrich_finding_with_ai(model, finding_data)

        findings.append({'status': 'in-progress', 'data': finding_data})

    return {'findings': findings}


# ---------------------------------------------------------------------------
# SysReptor export
# ---------------------------------------------------------------------------

def export_to_sysreptor(findings_data, project_name):
    reptor_server      = os.getenv('REPTOR_SERVER')
    reptor_api_key     = os.getenv('REPTOR_API_KEY')
    reptor_design_id   = os.getenv('REPTOR_DESIGN_ID')
    reptor_template_id = os.getenv('REPTOR_TEMPLATE_ID')

    if not REPTOR_BIN:
        raise Exception('reptor is not installed. Run: pip install reptor (then restart the app)')

    if not all([reptor_server, reptor_api_key, reptor_design_id]):
        raise Exception('Missing SysReptor configuration (REPTOR_SERVER, REPTOR_API_KEY, REPTOR_DESIGN_ID)')

    cmd = [REPTOR_BIN, '--server', reptor_server, '--token', reptor_api_key,
           'createproject', '--name', project_name, '-d', reptor_design_id]

    if reptor_template_id:
        cmd.extend(['--template', reptor_template_id])

    # Suppress gRPC fork warnings that pollute stderr
    env = os.environ.copy()
    env['GRPC_VERBOSITY'] = 'ERROR'
    env['GRPC_POLL_STRATEGY'] = 'poll'

    # Safe: list-form argv (no shell=True), so values like project_name cannot be
    # interpreted as shell syntax. No command injection is possible here.
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)  # nosemgrep

    # Filter gRPC noise from stderr before checking for real errors
    real_stderr = '\n'.join(
        l for l in (result.stderr or '').splitlines()
        if 'ev_poll_posix' not in l and 'ev_epoll' not in l and 'FD from fork' not in l
    ).strip()

    if result.returncode != 0:
        raise Exception(f'Failed to create project: {real_stderr or result.stderr}')

    combined = result.stdout + result.stderr

    project_id_match = re.search(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        combined
    )
    if not project_id_match:
        project_id_match = re.search(r'"id"\s*:\s*"([0-9a-fA-F-]{36})"', combined)
    if not project_id_match:
        try:
            jm = re.search(r'\{.*\}', combined, re.DOTALL)
            if jm:
                obj = json.loads(jm.group(0))
                pid = obj.get('id') or obj.get('project_id')
                if pid:
                    project_id_match = type('m', (), {'group': lambda self, n: pid})()
        except Exception:
            pass
    if not project_id_match:
        print(f"DEBUG stdout: {result.stdout}")
        print(f"DEBUG stderr: {result.stderr}")
        raise Exception(f'Could not extract project ID. Output: {combined[:500]}')

    project_id = project_id_match.group(0)
    os.environ['REPTOR_PROJECT_ID'] = project_id

    # Safe: list-form argv (no shell=True); arguments are passed directly to the
    # binary and are not evaluated by a shell, so command injection is not possible.
    push = subprocess.run(
        [REPTOR_BIN, '--server', reptor_server, '--token', reptor_api_key, 'pushproject'],  # nosemgrep
        input=json.dumps(findings_data),
        capture_output=True,
        text=True,
        env=env
    )

    push_stderr = '\n'.join(
        l for l in (push.stderr or '').splitlines()
        if 'ev_poll_posix' not in l and 'ev_epoll' not in l and 'FD from fork' not in l
    ).strip()

    if push.returncode != 0:
        raise Exception(f'Failed to push findings: {push_stderr or push.stderr}')

    return {'project_id': project_id, 'project_name': project_name}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


def _run_scan_job(job_id, target_url, use_ai, export_reptor, project_name, auth=None,
                  active=False, ajax=False, spider_minutes=2, active_minutes=20):
    def update(status, progress, message):
        with _jobs_lock:
            _jobs[job_id].update(status=status, progress=progress, message=message)

    try:
        output_dir = app.config['UPLOAD_FOLDER']

        auth_type = (auth or {}).get('type', 'none')
        if active:
            start_msg = 'Starting active ZAP scan (full — this can take a while)…'
        elif auth_type in ('bearer', 'userpass'):
            start_msg = 'Starting authenticated ZAP scan…'
        else:
            start_msg = 'Starting ZAP Docker container…'
        update('running', 10, start_msg)
        scan_result = run_zap_scan(target_url, output_dir, auth=auth,
                                   active=active, ajax=ajax,
                                   spider_minutes=spider_minutes, active_minutes=active_minutes)

        update('running', 60, 'Parsing ZAP findings…')
        findings_data = parse_zap_to_sysreptor(
            scan_result['json_path'],
            use_ai=use_ai,
            progress_cb=lambda msg: update('running', 70, msg)
        )

        parsed_json_path = output_dir / f"{scan_result['resource_name']}_parsed.json"
        with open(parsed_json_path, 'w') as f:
            json.dump(findings_data, f, indent=2)

        update('running', 90, 'Recording to dashboard…')
        history_entry = record_scan(target_url, findings_data['findings'])

        # Auto-import findings into the vulnerability tracker (deduped)
        _auto_import_to_tracker(target_url, findings_data['findings'])

        result = {
            'success': True,
            'target_url': target_url,
            'scan_files': {
                'json':   str(scan_result['json_path']),
                'html':   str(scan_result['html_path']),
                'parsed': str(parsed_json_path)
            },
            'findings_count': len(findings_data['findings']),
            'findings':       findings_data['findings'],
            'history_entry':  history_entry
        }

        if export_reptor:
            update('running', 95, 'Exporting to SysReptor…')
            result['sysreptor'] = export_to_sysreptor(findings_data, project_name)

        with _jobs_lock:
            _jobs[job_id].update(status='done', progress=100,
                                 message='Scan complete', result=result)

    except subprocess.TimeoutExpired:
        with _jobs_lock:
            _jobs[job_id].update(status='error',
                                 message='Scan timeout — target took too long to respond')
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id].update(status='error', message=str(e))


@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    data          = request.get_json(silent=True) or {}
    target_url    = (data.get('url') or '').strip()
    use_ai        = data.get('use_ai', True)
    export_reptor = data.get('export_to_sysreptor', False)
    project_name  = data.get('project_name',
                              f"Security Scan - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    auth          = data.get('auth') or {}
    auth_type     = (auth.get('type') or 'none').lower()
    active        = bool(data.get('active', False))
    ajax          = bool(data.get('ajax', False))
    try:
        active_minutes = int(data.get('active_minutes') or 20)
    except (TypeError, ValueError):
        active_minutes = 20
    try:
        spider_minutes = int(data.get('spider_minutes') or 2)
    except (TypeError, ValueError):
        spider_minutes = 2
    active_minutes = max(1, min(active_minutes, 120))
    spider_minutes = max(1, min(spider_minutes, 15))

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    # Validate authentication parameters
    if auth_type not in ('none', 'bearer', 'userpass'):
        return jsonify({'error': 'Invalid auth type'}), 400
    if auth_type == 'bearer' and not (auth.get('token') or '').strip():
        return jsonify({'error': 'A bearer token is required for bearer authentication'}), 400
    if auth_type == 'userpass':
        if not ((auth.get('username') or '').strip() and (auth.get('password') or '')):
            return jsonify({'error': 'Username and password are required for login authentication'}), 400
        login_url = (auth.get('login_url') or '').strip()
        if login_url and not login_url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Login URL must start with http:// or https://'}), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            'status':   'running',
            'progress': 0,
            'message':  'Queued…',
            'result':   None,
            'error':    None
        }

    threading.Thread(
        target=_run_scan_job,
        args=(job_id, target_url, use_ai, export_reptor, project_name, auth,
              active, ajax, spider_minutes, active_minutes),
        daemon=True
    ).start()

    return jsonify({'job_id': job_id})


@app.route('/api/scan/status/<job_id>', methods=['GET'])
def scan_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job)


def _run_discover_job(job_id, target_url, auth, openapi_url, do_crawl, do_probe):
    def update(status, progress, message):
        with _jobs_lock:
            _jobs[job_id].update(status=status, progress=progress, message=message)

    try:
        output_dir = app.config['UPLOAD_FOLDER']
        output_dir.chmod(0o755)

        update('running', 15, 'Starting endpoint discovery…')
        res = endpoint_discovery.run(
            target_url, auth=auth, openapi_url=openapi_url,
            do_crawl=do_crawl, do_probe=do_probe,
            progress_cb=lambda msg: update('running', 50, msg),
        )
        findings = res['findings']
        inventory = res['inventory']

        # Persist the reusable endpoint inventory artifact.
        resource = sanitize_url_to_filename(target_url)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        inv_path = output_dir / f"{resource}_{ts}_endpoints.json"
        with open(inv_path, 'w') as f:
            json.dump({'target': target_url, 'count': len(inventory),
                       'endpoints': inventory}, f, indent=2)

        update('running', 90, 'Recording to dashboard…')
        history_entry = record_scan(target_url, findings)
        _auto_import_to_tracker(target_url, findings)

        result = {
            'success': True,
            'target_url': target_url,
            'scan_type': 'discovery',
            'findings_count': len(findings),
            'findings': findings,
            'inventory_count': len(inventory),
            'inventory': inventory[:500],
            'scan_files': {'inventory': str(inv_path)},
            'history_entry': history_entry,
        }
        with _jobs_lock:
            _jobs[job_id].update(status='done', progress=100,
                                 message='Discovery complete', result=result)
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id].update(status='error', message=str(e))


@app.route('/api/discover', methods=['POST'])
def discover_endpoint():
    data = request.get_json(silent=True) or {}
    target_url = (data.get('url') or '').strip()
    openapi_url = (data.get('openapi_url') or '').strip() or None
    do_crawl = bool(data.get('crawl', True))
    do_probe = bool(data.get('probe', True))

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    if openapi_url and not openapi_url.startswith(('http://', 'https://')):
        return jsonify({'error': 'OpenAPI URL must start with http:// or https://'}), 400

    # Lightweight auth passthrough for authenticated discovery.
    auth = {
        'type':   (data.get('auth_type') or 'none').lower(),
        'token':  data.get('token') or '',
        'header': data.get('header') or '',
        'cookie': data.get('cookie') or '',
    }
    if auth['type'] == 'bearer' and not auth['token'].strip():
        return jsonify({'error': 'A bearer token is required for bearer authentication'}), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {'status': 'running', 'progress': 0,
                         'message': 'Queued…', 'result': None, 'error': None}

    threading.Thread(
        target=_run_discover_job,
        args=(job_id, target_url, auth, openapi_url, do_crawl, do_probe),
        daemon=True,
    ).start()

    return jsonify({'job_id': job_id})


def _run_authz_job(job_id, targets, identities, allow_unsafe, max_requests):
    def update(status, progress, message):
        with _jobs_lock:
            _jobs[job_id].update(status=status, progress=progress, message=message)

    try:
        output_dir = app.config['UPLOAD_FOLDER']
        output_dir.chmod(0o755)

        update('running', 15, 'Starting authorization matrix…')
        res = authz_scanner.run(
            targets, identities, allow_unsafe=allow_unsafe, max_requests=max_requests,
            progress_cb=lambda msg: update('running', 55, msg),
        )
        findings = res['findings']
        matrix = res['matrix']

        # Persist the matrix artifact (no credentials are included in it).
        host = ''
        if targets:
            try:
                host = urlparse(targets[0]['url']).netloc
            except ValueError:
                host = 'authz'
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        mx_path = output_dir / f"{sanitize_url_to_filename(host or 'authz')}_{ts}_authz.json"
        with open(mx_path, 'w') as f:
            json.dump({'matrix': matrix, 'findings': findings}, f, indent=2)

        update('running', 90, 'Recording to tracker…')
        _auto_import_to_tracker(f"authz:{host or 'targets'}", findings)

        result = {
            'success': True,
            'scan_type': 'authz',
            'findings_count': len(findings),
            'findings': findings,
            'matrix': matrix[:500],
            'scan_files': {'matrix': str(mx_path)},
        }
        with _jobs_lock:
            _jobs[job_id].update(status='done', progress=100,
                                 message='Authorization test complete', result=result)
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id].update(status='error', message=str(e))


@app.route('/api/authz', methods=['POST'])
def authz_endpoint():
    data = request.get_json(silent=True) or {}

    # Targets: accept an explicit {method,url} list, or a newline/array of URLs (GET).
    targets = []
    for t in (data.get('targets') or []):
        url = (t.get('url') or '').strip()
        if url.startswith(('http://', 'https://')):
            targets.append({'method': (t.get('method') or 'GET').upper(), 'url': url})
    raw_urls = data.get('urls') or []
    if isinstance(raw_urls, str):
        raw_urls = raw_urls.splitlines()
    for u in raw_urls:
        u = (u or '').strip()
        if u.startswith(('http://', 'https://')):
            targets.append({'method': 'GET', 'url': u})

    if not targets:
        return jsonify({'error': 'At least one target URL (http:// or https://) is required'}), 400

    # Identities: normalise owned URLs; the module adds an anonymous identity itself.
    identities = []
    for i in (data.get('identities') or []):
        name = (i.get('name') or '').strip()
        if not name:
            continue
        owned = i.get('owned') or []
        if isinstance(owned, str):
            owned = re.split(r'[\s,]+', owned)
        owned = [o.strip() for o in owned if o and o.strip().startswith(('http://', 'https://'))]
        identities.append({
            'name': name,
            'role': (i.get('role') or '').strip(),
            'token': (i.get('token') or '').strip(),
            'header': (i.get('header') or '').strip(),
            'cookie': (i.get('cookie') or '').strip(),
            'owned': owned,
        })

    allow_unsafe = bool(data.get('allow_unsafe', False))
    try:
        max_requests = int(data.get('max_requests') or 150)
    except (TypeError, ValueError):
        max_requests = 150
    max_requests = max(1, min(max_requests, 500))

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {'status': 'running', 'progress': 0,
                         'message': 'Queued…', 'result': None, 'error': None}
    threading.Thread(
        target=_run_authz_job,
        args=(job_id, targets, identities, allow_unsafe, max_requests),
        daemon=True,
    ).start()
    return jsonify({'job_id': job_id})


@app.route('/api/jwt-scan', methods=['POST'])
def jwt_scan_endpoint():
    """Analyse a JWT with local-only checks (no third-party calls)."""
    data = request.get_json(silent=True) or {}
    token = (data.get('token') or '').strip()
    wordlist = data.get('wordlist')
    public_key = data.get('public_key')
    import_tracker = bool(data.get('import_to_tracker', False))

    if not token:
        return jsonify({'error': 'A JWT is required'}), 400

    findings = jwt_scanner.run(token, hmac_wordlist=wordlist, public_key=public_key)

    # Best-effort, non-sensitive label for grouping (issuer or key id).
    label = 'JWT token'
    try:
        header, payload, *_ = jwt_scanner.decode_jwt(token)
        label = str(payload.get('iss') or header.get('kid') or 'JWT token')[:80]
    except Exception:
        pass

    if import_tracker:
        _auto_import_to_tracker(f"jwt:{label}", findings)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('data', {}).get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1

    return jsonify({
        'findings': findings,
        'findings_count': len(findings),
        'counts': counts,
        'target': label,
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'has_gemini_key':    bool(os.getenv('GEMINI_API_KEY')),
        'has_reptor_config': all([os.getenv('REPTOR_SERVER'),
                                  os.getenv('REPTOR_API_KEY'),
                                  os.getenv('REPTOR_DESIGN_ID')]),
        'docker_available':  subprocess.run(
            ['docker', '--version'], capture_output=True).returncode == 0
    })


@app.route('/api/dashboard', methods=['GET'])
def dashboard_endpoint():
    history = load_history()
    scans   = list(history.get('scans', {}).values())
    totals  = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for s in scans:
        for sev, n in s.get('latest', {}).items():
            totals[sev] = totals.get(sev, 0) + n
    return jsonify({
        'total_urls':  len(scans),
        'total_scans': sum(s.get('scan_count', 1) for s in scans),
        'totals':      totals,
        'urls':        sorted(scans, key=lambda x: x.get('last_scanned', ''), reverse=True)
    })


@app.route('/api/dashboard/delete/<path:url_key>', methods=['DELETE'])
def delete_dashboard_entry(url_key):
    history = load_history()
    key = normalise_url(url_key)
    if key in history.get('scans', {}):
        del history['scans'][key]
        save_history(history)
        return jsonify({'success': True})
    return jsonify({'error': 'Entry not found'}), 404


@app.route('/api/download/<path:filename>')
def download_file(filename):
    base = app.config['UPLOAD_FOLDER'].resolve()
    try:
        target = (base / filename).resolve()
    except (OSError, ValueError):
        return jsonify({'error': 'Invalid filename'}), 400
    # Prevent path traversal / absolute-path escape: the resolved path must stay
    # within the scans directory. Rejects inputs like '../../etc/passwd' or '/etc/passwd'.
    if base != target and base not in target.parents:
        return jsonify({'error': 'Invalid filename'}), 400
    if target.is_file():
        return send_file(target, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404


# ---------------------------------------------------------------------------
# Vulnerability Tracker
# ---------------------------------------------------------------------------

def load_tracker():
    if TRACKER_FILE.exists():
        try:
            with open(TRACKER_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {'vulnerabilities': []}


def save_tracker(data):
    with open(TRACKER_FILE, 'w') as f:
        json.dump(data, f, indent=2)


@app.route('/api/tracker', methods=['GET'])
def tracker_list():
    """List all tracked vulnerabilities with optional filters."""
    data = load_tracker()
    vulns = data.get('vulnerabilities', [])

    # Optional query filters
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')

    if status_filter:
        vulns = [v for v in vulns if v.get('status') == status_filter]
    if severity_filter:
        vulns = [v for v in vulns if v.get('severity') == severity_filter]

    # Compute stats
    all_vulns = data.get('vulnerabilities', [])
    stats = {
        'total': len(all_vulns),
        'open': sum(1 for v in all_vulns if v.get('status') == 'open'),
        'closed': sum(1 for v in all_vulns if v.get('status') == 'closed'),
        'blocked': sum(1 for v in all_vulns if v.get('status') == 'blocked'),
        'risk_accepted': sum(1 for v in all_vulns if v.get('status') == 'risk_accepted'),
    }

    return jsonify({'vulnerabilities': vulns, 'stats': stats})


@app.route('/api/tracker', methods=['POST'])
def tracker_add():
    """Add a new vulnerability to the tracker."""
    entry = request.get_json(force=True, silent=True) or {}
    data = load_tracker()

    vuln = {
        'id': str(uuid.uuid4())[:8],
        'title': entry.get('title', 'Untitled'),
        'severity': entry.get('severity', 'medium'),
        'status': entry.get('status', 'open'),
        'url': entry.get('url', ''),
        'team': entry.get('team', ''),
        'description': entry.get('description', ''),
        'date_reported': entry.get('date_reported', datetime.utcnow().strftime('%Y-%m-%d')),
        'date_updated': datetime.utcnow().strftime('%Y-%m-%d'),
        'notes': entry.get('notes', '')
    }

    data['vulnerabilities'].insert(0, vuln)
    save_tracker(data)
    return jsonify(vuln), 201


@app.route('/api/tracker/<vuln_id>', methods=['PATCH'])
def tracker_update(vuln_id):
    """Update a tracked vulnerability (status, team, notes, etc.)."""
    updates = request.get_json(silent=True) or {}
    data = load_tracker()

    for v in data['vulnerabilities']:
        if v['id'] == vuln_id:
            for key in ['status', 'team', 'notes', 'severity', 'title', 'description']:
                if key in updates:
                    v[key] = updates[key]
            v['date_updated'] = datetime.utcnow().strftime('%Y-%m-%d')
            save_tracker(data)
            return jsonify(v)

    return jsonify({'error': 'Vulnerability not found'}), 404


@app.route('/api/tracker/<vuln_id>', methods=['DELETE'])
def tracker_delete(vuln_id):
    """Delete a tracked vulnerability."""
    data = load_tracker()
    original_len = len(data['vulnerabilities'])
    data['vulnerabilities'] = [v for v in data['vulnerabilities'] if v['id'] != vuln_id]
    if len(data['vulnerabilities']) < original_len:
        save_tracker(data)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/tracker/import', methods=['POST'])
def tracker_import_from_scan():
    """Import findings from a completed scan into the tracker."""
    body = request.get_json(silent=True) or {}
    findings = body.get('findings', [])
    url = body.get('url', '')
    team = body.get('team', '')

    data = load_tracker()
    added = 0

    for f in findings:
        fd = f.get('data', {})
        vuln = {
            'id': str(uuid.uuid4())[:8],
            'title': fd.get('title', 'Untitled'),
            'severity': fd.get('severity', 'info'),
            'status': 'open',
            'url': url,
            'team': team,
            'description': fd.get('description', '')[:500],
            'date_reported': datetime.utcnow().strftime('%Y-%m-%d'),
            'date_updated': datetime.utcnow().strftime('%Y-%m-%d'),
            'notes': ''
        }
        data['vulnerabilities'].insert(0, vuln)
        added += 1

    save_tracker(data)
    return jsonify({'imported': added})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Security: never hardcode debug/host. Debug enables the Werkzeug debugger
    # (remote code execution) and leaks tracebacks, so it must be opt-in and
    # default off. Bind to loopback by default; expose externally only when the
    # operator explicitly sets HOST (e.g. HOST=0.0.0.0 in the systemd unit).
    host = os.getenv('HOST') or '127.0.0.1'
    port = int(os.getenv('PORT') or 8000)
    debug = os.getenv('FLASK_DEBUG', '').strip().lower() in ('1', 'true', 'yes', 'on')

    print("\n" + "="*60)
    print("  Security Scanner")
    print("="*60)
    print(f"\n  Starting server at http://{host}:{port}")
    print(f"\n  Configuration:")
    print(f"    - Gemini AI: {'✓ Enabled' if os.getenv('GEMINI_API_KEY') else '✗ Disabled'}")
    print(f"    - SysReptor: {'✓ Configured' if all([os.getenv('REPTOR_SERVER'), os.getenv('REPTOR_API_KEY')]) else '✗ Not configured'}")
    print(f"    - reptor CLI: {'✓ ' + REPTOR_BIN if REPTOR_BIN else '✗ Not found (run: pip install reptor)'}")
    print(f"    - Debug mode: {'⚠ ON' if debug else 'off'}")
    print(f"    - Auth: {'✓ Basic Auth enabled' if AUTH_ENABLED else '✗ Disabled'}")
    if host == '0.0.0.0' and not AUTH_ENABLED:
        print("\n  ⚠ WARNING: listening on all interfaces with no authentication.")
        print("    Set APP_AUTH_USER and APP_AUTH_PASS, or restrict network access.")
    print(f"\n  Press Ctrl+C to stop\n")
    print("="*60 + "\n")

    app.run(debug=debug, host=host, port=port)
