# Letshego Group Security Scanner

A unified web application for automated security scanning with ZAP, AI-powered finding enrichment, SysReptor integration, and vulnerability tracking across your organization.

![Architecture](./docs/architecture.svg)

---

## Features

- **🔍 Automated Scanning** — Run OWASP ZAP baseline scans directly from a web UI
- **🤖 AI Enrichment** — Leverage Google Gemini to generate developer-focused descriptions and actionable remediation steps
- **📤 SysReptor Integration** — Automatically create projects and push findings to your SysReptor instance
- **📊 Dashboard** — Track vulnerabilities across all scanned URLs with deduplication and historical tracking
- **🎨 Letshego Branding** — Professionally styled UI with Letshego Africa Holdings Limited brand colors and logo

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         User Browser (Web UI)                            │
│                    http://localhost:5000                                  │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
                                ├─ Scanner Tab
                                │  • Enter target URL
                                │  • Configure AI enrichment & SysReptor export
                                │  • View scan results & download reports
                                │
                                └─ Dashboard Tab
                                   • Organization-wide vulnerability totals
                                   • Per-URL scan history & metrics
                                   • Remove unwanted entries
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          Flask Backend (app.py)                           │
│                                                                          │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────────┐    │
│  │  Scan Engine   │  │  AI Module   │  │   History Tracker        │    │
│  │  run_zap_scan  │  │  enrich_*    │  │   record_scan            │    │
│  │                │  │              │  │   scan_history.json      │    │
│  └────────┬───────┘  └──────┬───────┘  └──────────────────────────┘    │
│           │                  │                                           │
└───────────┼──────────────────┼───────────────────────────────────────────┘
            │                  │
            ▼                  ▼
  ┌──────────────────┐   ┌──────────────────┐
  │  Docker          │   │  Google Gemini   │
  │  ZAP Container   │   │  API             │
  │                  │   │  gemini-flash    │
  │  • Baseline scan │   │  • Enrichment    │
  │  • JSON output   │   │  • Summaries     │
  └──────────────────┘   └──────────────────┘

            │
            ▼
  ┌──────────────────────────────────────┐
  │  SysReptor API (optional)            │
  │  • Create projects                   │
  │  • Push findings                     │
  └──────────────────────────────────────┘

            │
            ▼
  ┌──────────────────────────────────────┐
  │  Local Storage                       │
  │  • scans/             (ZAP outputs)  │
  │  • scan_history.json  (dashboard)    │
  └──────────────────────────────────────┘
```

---

## Prerequisites

- **Docker** — ZAP runs in a container ([install Docker](https://docs.docker.com/get-docker/))
- **Python 3.9+** — Flask backend runtime
- **Google Gemini API Key** (optional) — for AI enrichment ([get key](https://aistudio.google.com))
- **SysReptor instance** (optional) — for report export ([SysReptor docs](https://docs.sysreptor.com/))

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Gumbeoketch/scrappy-scanner.git
cd scrappy-scanner
```

### 2. Set up Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Google Gemini API key (optional — enables AI enrichment)
GEMINI_API_KEY=your-gemini-api-key-here

# SysReptor configuration (optional — enables report export)
REPTOR_API_KEY=your-reptor-api-key-here
REPTOR_SERVER=https://sysreptor.yourcompany.com/
REPTOR_DESIGN_ID=your-design-template-id-here
```

---

## Usage

### Start the application

```bash
source .venv/bin/activate
python3 app.py
```

The server will start at **http://localhost:5000**

### Scanner Tab

1. Enter a target URL (e.g., `https://example.com`)
2. Optionally enable:
   - **AI enrichment** — generates concise technical descriptions and remediation steps
   - **SysReptor export** — creates a project and pushes findings automatically
3. Click **Start Scan**
4. Wait for ZAP to complete (usually 2–10 minutes)
5. View results, filter by severity, and download reports

### Dashboard Tab

- **Organization totals** — cumulative High/Medium/Low/Info counts across all unique URLs
- **Scanned URLs table** — scan count, latest severity breakdown, timestamps
- **Remove entries** — clean up URLs you no longer want to track

---

## Deployment (EC2 / Linux Server)

### Run as a systemd service

A `scanner.service` file is included for persistent deployment:

```bash
sudo cp scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable scanner
sudo systemctl start scanner
```

Manage the service:

```bash
sudo systemctl status scanner       # check status
sudo journalctl -u scanner -f       # live logs
sudo systemctl restart scanner      # after code changes
sudo systemctl stop scanner         # stop
```

The service:
- Starts automatically on boot
- Restarts on crash (5-second delay)
- Runs as `ec2-user` from `/home/ec2-user/scrappy-scanner`

---

## File Structure

```
scrappy-scanner/
├── app.py                 # Flask backend (scanner, parser, exporter, dashboard)
├── templates/
│   └── index.html         # Web UI (tabs, forms, results rendering)
├── images/
│   └── LHL-Logo.png       # Letshego Group branding logo
├── docs/
│   └── architecture.svg   # Architecture diagram
├── scans/                 # ZAP scan outputs (gitignored)
├── scan_history.json      # Dashboard persistence (gitignored)
├── scanner.service        # systemd unit file for EC2 deployment
├── requirements.txt       # Python dependencies
├── .env                   # Environment secrets (gitignored)
├── .env.example           # Template for .env
├── .gitignore
└── README.md
```

---

## Requirements

### Python Dependencies (`requirements.txt`)

| Package              | Version   | Purpose                              |
|----------------------|-----------|--------------------------------------|
| `flask`              | 3.1.1     | Web framework                       |
| `google-generativeai`| ≥ 0.8.5   | Google Gemini API client            |
| `werkzeug`           | 3.1.8     | WSGI utilities (Flask dependency)   |
| `reptor`             | ≥ 0.34    | SysReptor CLI for report export     |

### System Dependencies

| Dependency | Required | Purpose                     |
|------------|----------|-----------------------------|
| Docker     | Yes      | Runs ZAP scanner container  |
| Python 3.9+| Yes      | Application runtime         |

---

## Configuration

### Environment Variables

| Variable             | Required | Description                                              |
|----------------------|----------|----------------------------------------------------------|
| `GEMINI_API_KEY`     | No       | Google Gemini API key for AI enrichment                  |
| `REPTOR_SERVER`      | No       | SysReptor instance URL                                   |
| `REPTOR_API_KEY`     | No       | SysReptor API token                                      |
| `REPTOR_DESIGN_ID`   | No       | SysReptor report design/template ID                      |
| `REPTOR_TEMPLATE_ID` | No       | Optional SysReptor template override                     |

### Docker Image

```
ghcr.io/zaproxy/zaproxy:stable
```

The app auto-checks Docker availability and reports status in the UI.

---

## API Endpoints

| Endpoint                        | Method | Description                          |
|---------------------------------|--------|--------------------------------------|
| `/`                             | GET    | Main UI                              |
| `/api/config`                   | GET    | Check Docker/Gemini/SysReptor status |
| `/api/scan`                     | POST   | Start a ZAP scan (returns job ID)    |
| `/api/scan/status/<job_id>`     | GET    | Poll scan job progress               |
| `/api/dashboard`                | GET    | Dashboard stats and URL list         |
| `/api/dashboard/delete/<url>`   | DELETE | Remove a URL from dashboard          |
| `/api/download/<filename>`      | GET    | Download scan report files           |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Docker not found | Install Docker and ensure it's running: `docker --version` |
| Gemini 404 error | Check your API key at [Google AI Studio](https://aistudio.google.com) |
| reptor not found | Run `pip install reptor` in your venv, then restart |
| Scan timeout | Increase timeout in `app.py`: `timeout=1200` (20 min) |
| SysReptor template error | Use a different `REPTOR_DESIGN_ID` — this is a template issue, not a scanner issue |
| NetworkError in browser | The app uses async polling — if this still happens, check the server logs |
| systemd 203/EXEC | Verify the Python path in `scanner.service` matches your venv |

---

## Security Notes

- **Never commit `.env`** — it contains API keys and secrets
- `.gitignore` excludes `.env`, `scans/`, and `scan_history.json`
- Scan outputs contain sensitive vulnerability data — treat as confidential
- Only scan systems you own or have permission to test
- Run the app behind a firewall — it has no built-in authentication

---

## License

MIT License

---

## Credits

Built with [Flask](https://flask.palletsprojects.com/), [OWASP ZAP](https://www.zaproxy.org/), [Google Gemini](https://ai.google.dev/), and [SysReptor](https://sysreptor.com/).

Developed for **Letshego Africa Holdings Limited** — Group Information Security.
