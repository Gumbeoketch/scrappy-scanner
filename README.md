# scrappy-scanner

A security scanning toolkit that runs a ZAP baseline scan, parses findings into SysReptor-ready JSON, and exports them to a SysReptor project.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) — required to run the ZAP scanner
- Python 3
- `reptor` CLI — installed automatically in the steps below

---

## Installation

### 1. Clone the repo

```bash
git clone <repo-url>
cd scrappy-scanner
```

### 2. Set up the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

Then edit `.env`:

```
GEMINI_API_KEY=your-gemini-api-key-here
REPTOR_API_KEY=your-reptor-api-key-here
REPTOR_TEMPLATE_ID=your-template-id-here
```

- `GEMINI_API_KEY` — enables AI enrichment of findings in `parser.py`. Get one at [aistudio.google.com](https://aistudio.google.com)
- `REPTOR_API_KEY` — your SysReptor API key for the `reptor` CLI
- `REPTOR_TEMPLATE_ID` — the SysReptor report template ID to use when creating projects

---

## Usage

### Run the scanner

Prompts for a target URL and outputs `.json` and `.html` files named after the scanned URL.

```bash
./scanner.sh
```

### Parse ZAP findings

Converts a ZAP JSON report into a SysReptor-ready findings file. Enriches findings with Gemini AI if `GEMINI_API_KEY` is set.

```bash
source .venv/bin/activate
python3 parser.py <scanned-report.json> reptor-ready.json
```

### Export to SysReptor

Creates a new project in SysReptor and pushes the parsed findings.

```bash
./exporter.sh
```

---

## File Overview

| File | Purpose |
|---|---|
| `unified-scanner.sh` | Runs ZAP scan against a target URL |
| `parser.py` | Parses ZAP JSON → SysReptor-ready JSON, with optional AI enrichment |
| `exporter.sh` | Creates a SysReptor project and pushes findings |
| `requirements.txt` | Python dependencies |
| `.env` | Local environment variables (not committed) |
| `.env.example` | Template for `.env` |
