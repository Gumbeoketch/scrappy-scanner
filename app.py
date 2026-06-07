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
import threading
import uuid
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
import google.generativeai as genai

app = Flask(__name__, static_folder='images', static_url_path='/static/images')
app.config['UPLOAD_FOLDER'] = Path('scans')
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

HISTORY_FILE = Path('scan_history.json')

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


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def sanitize_url_to_filename(url):
    clean = re.sub(r'https?://', '', url)
    clean = re.sub(r'[/:?&=]', '-', clean)
    clean = re.sub(r'-+', '-', clean)
    return clean.strip('-') or 'scan'


def run_zap_scan(target_url, output_dir):
    resource_name = sanitize_url_to_filename(target_url)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_prefix = f"{resource_name}_{timestamp}"

    scan_json = output_dir / f"{scan_prefix}.json"
    scan_html = output_dir / f"{scan_prefix}.html"

    # Ensure world-writable so the ZAP container can write output files
    output_dir.chmod(0o777)

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

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if not scan_json.exists():
        raise Exception(f"ZAP scan failed: {result.stderr or result.stdout}")

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
        finding_data['description']    = enriched.get('description',    description)
        finding_data['recommendation'] = enriched.get('recommendation', recommendation)

        time.sleep(1)

    except Exception as e:
        print(f"Failed to enrich '{title}': {e}")

    return finding_data


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

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
        description    = alert.get('desc', '')
        recommendation = alert.get('solution', '')

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

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception(f'Failed to create project: {result.stderr}')

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

    push = subprocess.run(
        [REPTOR_BIN, '--server', reptor_server, '--token', reptor_api_key, 'pushproject'],
        input=json.dumps(findings_data),
        capture_output=True,
        text=True
    )

    if push.returncode != 0:
        raise Exception(f'Failed to push findings: {push.stderr}')

    return {'project_id': project_id, 'project_name': project_name}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


def _run_scan_job(job_id, target_url, use_ai, export_reptor, project_name):
    def update(status, progress, message):
        with _jobs_lock:
            _jobs[job_id].update(status=status, progress=progress, message=message)

    try:
        output_dir = app.config['UPLOAD_FOLDER']

        update('running', 10, 'Starting ZAP Docker container…')
        scan_result = run_zap_scan(target_url, output_dir)

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
    data          = request.get_json()
    target_url    = (data.get('url') or '').strip()
    use_ai        = data.get('use_ai', True)
    export_reptor = data.get('export_to_sysreptor', False)
    project_name  = data.get('project_name',
                              f"Security Scan - {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

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
        args=(job_id, target_url, use_ai, export_reptor, project_name),
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
    file_path = app.config['UPLOAD_FOLDER'] / filename
    if file_path.exists():
        return send_file(file_path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Letshego Group Security Scanner")
    print("="*60)
    print(f"\n  Starting server at http://localhost:5000")
    print(f"\n  Configuration:")
    print(f"    - Gemini AI: {'✓ Enabled' if os.getenv('GEMINI_API_KEY') else '✗ Disabled'}")
    print(f"    - SysReptor: {'✓ Configured' if all([os.getenv('REPTOR_SERVER'), os.getenv('REPTOR_API_KEY')]) else '✗ Not configured'}")
    print(f"    - reptor CLI: {'✓ ' + REPTOR_BIN if REPTOR_BIN else '✗ Not found (run: pip install reptor)'}")
    print(f"\n  Press Ctrl+C to stop\n")
    print("="*60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
