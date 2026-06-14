import os
import sys
import json
from google import genai
from google.genai.types import HttpOptions

# vérification clé Gemini
if not os.environ.get("GEMINI_API_KEY"):
    print("[-] GEMINI_API_KEY non définie")
    sys.exit(1)

client = genai.Client(
    http_options=HttpOptions(api_version="v1")
)

from orchestrator import run_pipeline


def build_prompt(evidence_path, findings):
    return f"""
You are a DFIR expert analyzing a forensic case.

========================
EVIDENCE PATH
========================
{evidence_path}

========================
ORCHESTRATOR FINDINGS
========================
{json.dumps(findings, indent=2)}

========================
TASK
========================
1. Analyze all artifacts
2. Correlate system, memory and yara detections
3. Identify possible intrusion or malicious behavior
4. Produce a structured DFIR report with:
   - Executive Summary
   - Technical Findings
   - Indicators of Compromise (IOCs)
   - Conclusion

IMPORTANT:
Only use the provided structured findings.
Do not assume missing memory results.
If memory.status is not success, explicitly state limitation.
"""


def run_forensic_agent():

    print("=" * 50)
    print("        SIFT-F4S DFIR AGENT (v2)        ")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python3 agent.py <evidence_path>")
        sys.exit(1)

    evidence_path = sys.argv[1]

    if not os.path.exists(evidence_path):
        print(f"[-] Evidence introuvable : {evidence_path}")
        sys.exit(1)

    print(f"[*] Evidence : {evidence_path}")
    print("[*] Lancement du pipeline orchestrateur...")

    findings = run_pipeline(evidence_path)

    print("[*] Envoi des findings à Gemini...")

    prompt = build_prompt(evidence_path, findings)

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt
        )

        report = response.text

        print("\n" + "=" * 20 + " FORENSIC REPORT " + "=" * 20)
        print(report)
        print("=" * 60)

        os.makedirs("reports", exist_ok=True)
        with open("reports/report.md", "w") as f:
            f.write(report)

        print("[+] Rapport sauvegardé dans reports/report.md")

    except Exception as e:
        print(f"[!] Erreur Gemini : {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_forensic_agent()
