import os
import sys
from google import genai
from google.genai import types
from google.genai.types import HttpOptions


if not os.environ.get("GEMINI_API_KEY"):
    print("[-] Erreur : La variable d'environnement GEMINI_API_KEY n'est pas configurée.")
    print("[*] Check-Check : Exécutez 'export GEMINI_API_KEY=\"votre_cle\"' avant de lancer.")
    sys.exit(1)

# 1. Configuration du client Gemini
client = genai.Client(
    http_options=HttpOptions(api_version="v1")
)

def run_forensic_agent():
    print("=" * 50)
    print("        SIFT-F4S : AUTOMATED DFIR AGENT        ")
    print("=" * 50)
    
    # Demande du chemin de la preuve en anglais
    evidence_path = input("\n[+] Enter the absolute path of the evidence to analyze: ").strip()
    
    # Validation de l'existence de la cible avant traitement
    if not os.path.exists(evidence_path):
        # Message d'erreur conservé en français
        print(f"[-] Erreur : Le fichier ou dossier '{evidence_path}' n'existe pas.")
        return

    # Directives système (System Instructions) passées à Gemini en anglais
    system_instruction = """
        You are an expert SOC forensic analyst and incident responder. 
        Your objective is to independently investigate the provided evidence path. 
        Leverage the available MCP tools (Triage, Prefetch, Volatility, YARA, TSK) 
        to inspect the target, correlate findings, and build a comprehensive incident report.
        

        Start the forensic investigation immediately on the following target: {evidence_path}
    """

    print("\n[*] Gemini agent is starting autonomous analysis...")

    try:
        # 3. Requête d'orchestration au modèle de génération
        generation_response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=system_instruction
        )
        
        # 4. Affichage du rapport final d'investigation en anglais
        print("\n" + "=" * 20 + " GENERATED FORENSIC REPORT " + "=" * 20)
        print(generation_response.text)
        print("=" * 68)
        
    except Exception as exception_error:
        # Gestion de l'exception et affichage de l'erreur en français
        print(f"\n[!] Échec de l'agent ! Détails de l'erreur : {exception_error}")

if __name__ == "__main__":
    run_forensic_agent()
