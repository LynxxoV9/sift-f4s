#!/bin/bash
# Script de lancement automatisé et sécurisé pour SIFT-F4S

echo "[*] Virtual environnement configuration..."
python3 -m venv ai_agent_env
source ai_agent_env/bin/activate

echo "[*] Requirements downloading..."
pip install -r requirements.txt

# --- SECTION SÉCURITÉ DE LA CLÉ D'API ---
if [ -z "$GEMINI_API_KEY" ]; then
    echo "===================================================="
    echo "  SECURITY: Missing GEMINI API key."
    echo "===================================================="
    # Le flag -s permet de masquer la saisie à l'écran (comme pour un mot de passe)
    read -sp "[?] Plaste your Gemini API Key (mask is on) : " USER_KEY
    echo ""
    if [ -z "$USER_KEY" ]; then
        echo "[-] Erreur : No key provided. Script stopped."
        exit 1
    fi
    export GEMINI_API_KEY="$USER_KEY"
fi
# ----------------------------------------

echo "[*] Starting SIFT-F4S mcp server..."
python3 build2.py &
SERVER_PID=$!

# Laisser le temps au serveur MCP de démarrer
sleep 5

echo "[*] Launch of the AI ​​Agent..."
python3 agent.py

# Nettoyage à l'arrêt : on coupe le serveur MCP proprement
kill $SERVER_PID
echo "[*] SIFT-F4S successfully shut down. Process completed.."
