#!/usr/bin/env python3
import json
import sys
import os
import time
try:
    import google.generativeai as genai
except ImportError:
    print("[!] Missing dependency: google-generativeai")
    print("[!] Run: pip install -r requirements.txt")
    print("[!] Or:  pip install google-generativeai")
    import sys; sys.exit(1)
from typing import Dict, List

# Load .env file if present (without requiring python-dotenv)
def _load_dotenv(dotenv_path=".env"):
    if not os.path.isfile(dotenv_path):
        return
    with open(dotenv_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Only set if not already set in the environment
            if key and key not in os.environ:
                os.environ[key] = value

_load_dotenv()

def parse_zap_to_sysreptor(zap_json_output):
    zap_data = json.loads(zap_json_output)
    findings = []

    # Get alerts (ZAP structure varies)
    alerts = zap_data.get("alerts", [])
    if not alerts and "site" in zap_data:
        if isinstance(zap_data["site"], list):
            for site in zap_data["site"]:
                alerts.extend(site.get("alerts", []))
        elif isinstance(zap_data["site"], dict):
            alerts.extend(zap_data["site"].get("alerts", []))

    severity_map = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "info"
    }

    for alert in alerts:
        title = alert.get("alert", "Untitled Finding")
        riskdesc = alert.get("riskdesc", "Low (Default)")
        severity = severity_map.get(riskdesc.split(" ")[0], "low")
        description = alert.get("desc", "")
        recommendation = alert.get("solution", "")
        references = []

        # Parse HTML references into plain list
        ref_str = alert.get("reference", "")
        if ref_str:
            refs = ref_str.replace("<p>", "").replace("</p>", "\n").split("\n")
            references = [r.strip() for r in refs if r.strip()]

        affected_components = []
        for instance in alert.get("instances", []):
            uri = instance.get("uri")
            param = instance.get("param")
            if uri:
                affected = uri
                if param:
                    affected += f" [Param: {param}]"
                affected_components.append(affected)

        findings.append({
            "status": "in-progress",
            "data": {
                "title": title,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
                "affected_components": affected_components or ["General Application"],
                "references": references,
                "type": "Web-Application"
            }
        })

    # ✅ Output wrapped JSON object
    return json.dumps({"findings": findings}, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python zap_to_sysreptor.py <zap_report.json> <output.json>")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    with open(input_file, "r") as f:
        zap_json_output = f.read()

    parsed = parse_zap_to_sysreptor(zap_json_output)

    with open(output_file, "w") as f:
        f.write(parsed)

    print(f"[+] Parsed SysReptor-ready JSON saved to {output_file}")


def initialize_gemini():
    """Initialize Gemini API with API key from environment"""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[!] Warning: GEMINI_API_KEY not found. AI enrichment will be skipped.")
        print("[!] Set it with: export GEMINI_API_KEY='your-api-key'")
        return None
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash')
    return model


def enrich_with_gemini(model, finding_data: Dict) -> Dict:
    """Use Gemini to enrich and clarify security findings"""
    if not model:
        return finding_data
    
    title = finding_data.get("title", "Unknown")
    description = finding_data.get("description", "")
    recommendation = finding_data.get("recommendation", "")
    severity = finding_data.get("severity", "low")
    affected = finding_data.get("affected_components", [])
    
    prompt = f"""You are a security expert writing a clear, actionable security report for a technical security team.

**Vulnerability:** {title}
**Severity:** {severity}
**Original Description:** {description}
**Original Recommendation:** {recommendation}
**Affected Components:** {', '.join(affected[:3])}

Please provide:

1. **DESCRIPTION** (2-3 paragraphs):
   - Explain what this vulnerability is in clear, technical terms
   - Describe the security risk and potential impact on the application
   - Explain how an attacker could exploit this vulnerability
   - Keep it concise but comprehensive for security professionals

2. **RECOMMENDATION** (clear, numbered steps):
   - Provide specific, actionable remediation steps
   - Include code examples or configuration changes where applicable
   - Prioritize the most effective fixes first
   - Make it practical and easy to implement
   - Consider different fix options (immediate, short-term, long-term)

Format your response as JSON:
{{
  "description": "your enriched description here",
  "recommendation": "your clear, actionable recommendations here"
}}

Keep technical accuracy high but make it readable. Focus on actionable information."""

    try:
        response = model.generate_content(prompt)
        result_text = response.text.strip()
        
        # Extract JSON from markdown code blocks if present
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0].strip()
        elif "```" in result_text:
            result_text = result_text.split("```")[1].split("```")[0].strip()
        
        enriched = json.loads(result_text)
        
        finding_data["description"] = enriched.get("description", description)
        finding_data["recommendation"] = enriched.get("recommendation", recommendation)
        
        print(f"  ✓ Enriched: {title}")
        
        # Rate limiting to avoid API throttling
        time.sleep(1)
        
    except Exception as e:
        print(f"  ✗ Failed to enrich '{title}': {str(e)}")
        # Keep original data on failure
    
    return finding_data


def parse_zap_to_sysreptor(zap_json_output, use_ai_enrichment=True):
    zap_data = json.loads(zap_json_output)
    findings = []

    # Get alerts (ZAP structure varies)
    alerts = zap_data.get("alerts", [])
    if not alerts and "site" in zap_data:
        if isinstance(zap_data["site"], list):
            for site in zap_data["site"]:
                alerts.extend(site.get("alerts", []))
        elif isinstance(zap_data["site"], dict):
            alerts.extend(zap_data["site"].get("alerts", []))

    severity_map = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "info"
    }

    # Initialize Gemini if AI enrichment is enabled
    model = None
    if use_ai_enrichment:
        print("[*] Initializing Gemini AI for enrichment...")
        model = initialize_gemini()
        if model:
            print(f"[+] AI enrichment enabled. Processing {len(alerts)} findings...\n")
        else:
            print("[!] Proceeding without AI enrichment.\n")

    for idx, alert in enumerate(alerts, 1):
        title = alert.get("alert", "Untitled Finding")
        riskdesc = alert.get("riskdesc", "Low (Default)")
        severity = severity_map.get(riskdesc.split(" ")[0], "low")
        description = alert.get("desc", "")
        recommendation = alert.get("solution", "")
        references = []

        # Parse HTML references into plain list
        ref_str = alert.get("reference", "")
        if ref_str:
            refs = ref_str.replace("<p>", "").replace("</p>", "\n").split("\n")
            references = [r.strip() for r in refs if r.strip()]

        affected_components = []
        for instance in alert.get("instances", []):
            uri = instance.get("uri")
            param = instance.get("param")
            if uri:
                affected = uri
                if param:
                    affected += f" [Param: {param}]"
                affected_components.append(affected)

        finding_data = {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "affected_components": affected_components or ["General Application"],
            "references": references,
            "type": "Web-Application"
        }

        # Enrich with Gemini AI
        if model:
            print(f"[{idx}/{len(alerts)}] Processing: {title}")
            finding_data = enrich_with_gemini(model, finding_data)

        findings.append({
            "status": "in-progress",
            "data": finding_data
        })

    # ✅ Output wrapped JSON object
    return json.dumps({"findings": findings}, indent=2)